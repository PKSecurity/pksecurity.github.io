### Overview

To participate in Pwn2Own 2021, I discoverd a bug in Virtualbox and successfully led it to Guest-To-Host Escape. However, I started preparing too late, and as result, I couldn't submit an application for Pwn2Own. Moreover, just after Pwn2Own, Someone received a CVE fo the vulnerabilty.
Despite this, I'd like to share how I discoverd and exploited the bug because I used only one bug for leaking and exploiting, and the technique wasn't well-known before.
The bug I found was heap-overflow, with no info-leak bug involved. That meant I had to facilitate a leak using only heap-overflow vulnerability. The process was quite interesting.

        
**This post based on VirtualBox 6.1.18**

### Vulnerability
At that time, Pwn2Own allowed to use Linux as guest on VM category, so I focused on vmsvga, which is default graphic option when the guest is Linux-based.

```c++
static VBOXSTRICTRC vmsvgaWritePort(PPDMDEVINS pDevIns, PVGASTATE pThis, PVGASTATECC pThisCC, uint32_t u32)
    ...
    switch(idxReg) {
        ...
        case SVGA_REG_HEIGHT://DevVGA-SVGA.cpp-1724~1733
            STAM_REL_COUNTER_INC(&pThis->svga.StatRegHeightWr);
            if (pThis->svga.uHeight != u32)
            {
                pThis->svga.uHeight = u32;
                if (pThis->svga.fEnabled)
                    ASMAtomicOrU32(&pThis->svga.u32ActionFlags, VMSVGA_ACTION_CHANGEMODE);
            }
            /* else: nop */
        break;
            ...
```
`vmsvga` is implemented under [PCI-Communication](https://en.wikipedia.org/wiki/Peripheral_Component_Interconnect) allowing the Guest in root to easily invoke PCI with `in` and `out` instructions.
In `vmsvgaWriteport`, without any validation code,`pThis->svga.uHeight` is set to `u32`, which is passed by the Guest. That is main key point of the vulnerability, as it allows to control the field variable as what I want.


```c++
static int vmsvgaR3ChangeMode(PVGASTATE pThis, PVGASTATECC pThisCC)
{
...
VMSVGASCREENOBJECT *pScreen = &pSVGAState->aScreens[0];
...
pScreen->cHeight   = pThis->svga.uHeight; //DevVGA-SVGA.cpp-1448~
```


`pScreen->cHeight` is assigned the value of `pThis->svga.uHeight`, which I have set.
The height of Guest OS depends on this variable.

```c++
static DECLCALLBACK(int) vmsvgaR3FifoLoop(PPDMDEVINS pDevIns, PPDMTHREAD pThread)
{
    ...
    case SVGA_CMD_DEFINE_SCREEN:
        uint32_t const uHeight = pCmd->screen.size.height;
        AssertBreak(uHeight <= pThis->svga.u32MaxHeight);
        ...
        if (!fBlank)
        {
            AssertBreak(uWidth > 0 && uHeight > 0);
            ...
            pScreen->cHeight = uHeight;
            ...
        }
```
`vmsvgaR3FifoLoop` is invoked by [MMIO](https://en.wikipedia.org/wiki/Memory-mapped_I/O_and_port-mapped_I/O). `vmsvgaR3FifoLoop` has also code snippet that Assigning value to `pScreen->cHeight`. However, Unlikely `vmsvgaR3ChangeMode`, there is validation code for the field, which checking whether the value will be assigned to the field is bigger than `pThis->svga.u32MaxHeight` or not (`pThis->svga.u32MaxHeight` is set when Guest OS starts as well as immutable value). If bigger, do not to assign.


Based on the above information, I could come up with suspicious thought for unbalanced validation code for `pScreen->cHeight`. It's time to find side effect of that.


```c++
static int vmsvgaR3ChangeMode(PVGASTATE pThis, PVGASTATECC pThisCC)
{
    ...
    pThis->last_scr_height = pSVGAState->aScreens[0].cHeight; // [1]
    ...
}
```

```C++
static int vmsvgaR3DrawGraphic(PVGASTATE pThis, PVGASTATER3 pThisCC, bool fFullUpdate,
                               bool fFailOnResize, bool reset_dirty, PDMIDISPLAYCONNECTOR *pDrv)
{
    uint32_t const cx        = pThis->last_scr_width;
    uint32_t const cxDisplay = cx;
    uint32_t const cy        = pThis->last_scr_height; // [2]
    uint32_t       cBits     = pThis->last_bpp;
    ...
    uint8_t    *pbDst          = pDrv->pbData; // [3]


    uint32_t    cbDstScanline  = pDrv->cbScanline;//0
    uint32_t    offSrcStart    = 0;  /* always start at the beginning of the framebuffer */
    uint32_t    cbScanline     = (cx * cBits + 7) / 8;   /* The visible width of a scanline. */
    uint32_t    yUpdateRectTop = UINT32_MAX;
    uint32_t    offPageMin     = UINT32_MAX;
    int32_t     offPageMax     = -1;
    uint32_t    y;
    for (y = 0; y < cy; y++) //[4]
    {
        uint32_t offSrcLine = offSrcStart + y * cbScanline;
        uint32_t offPage0   = offSrcLine & ~PAGE_OFFSET_MASK;
        uint32_t offPage1   = (offSrcLine + cbScanline - 1) & ~PAGE_OFFSET_MASK;
        ...
        fUpdate |= (pThis->invalidated_y_table[y >> 5] >> (y & 0x1f)) & 1;
        if (fUpdate)
        {
            ...
            if (pThis->fRenderVRAM)
                pfnVgaDrawLine(pThis, pThisCC, pbDst, pThisCC->pbVRam + offSrcLine, cx); //[5]
        }
        ...
        pbDst += cbDstScanline;
    }
    ...
}
```

[1]: `pThis->last_scr_height` is assigned the value of `pSVGAState->aScreens[0].cHeight`.
[2]: `cy` also has same value with `pThis->last_scr_height`
[3]: `pDrv->pbData(pbDst)` contains the address of Graphic buffer, the size of which is controllable by user and  does not depend on `pThis->last_scr_height` .
[4]: While iterating over `cy`, write data into `pbDst` with user data(`pThisCC->pbVRAm`) at [5]


As result, `cy` is fully-controllable variable as well as due to the lack of validation I mentioned above the flow can reach the loop even if the value is 0xffffffff.

*By repeatedly skipping over `cbScanline`(fully-controllable), I was able to overwrite the heap chunks next to `pbDst`*


![image](https://hackmd.io/_uploads/H1lo2xFXA.png)
![image](https://hackmd.io/_uploads/ry7ohltQA.png)

### Leak? URB?

As you know, I didn't have any single of info-leak and anything related to. Only what I had is heap-overflow. Other leak methods published was already patched or they required the installation of extension which was not possible at Pwn2Own. Due to this reason, I had to figure out a new way with only overflow vulnerability. Attempting to leak has taken more time than finding vulnerability by far. That's why I have failed to apply. 😭😭

What I focuse on is URB. URB includes a USB Interface and is easily accessible to the Guest.


```c++
DECLHIDDEN(PVUSBURB) vusbUrbPoolAlloc(PVUSBURBPOOL pUrbPool, VUSBXFERTYPE enmType,
                                      VUSBDIRECTION enmDir, size_t cbData, size_t cbHci,
                                      size_t cbHciTd, unsigned cTds)
{
    ...
    RTCritSectEnter(&pUrbPool->CritSectPool);
    PVUSBURBHDR pHdr = NULL; //[1]
    PVUSBURBHDR pIt, pItNext;
    RTListForEachSafe(&pUrbPool->aLstFreeUrbs[enmType], pIt, pItNext, VUSBURBHDR, NdFree) //[2]
    {
        if (pIt->cbAllocated >= cbMem)
        {
            RTListNodeRemove(&pIt->NdFree);
            Assert(pIt->Urb.u32Magic == VUSBURB_MAGIC);
            Assert(pIt->Urb.enmState == VUSBURBSTATE_FREE);
            /*
             * If the allocation is far too big we increase the age counter too
             * so we don't waste memory for a lot of small transfers
             */
            if (pIt->cbAllocated >= 2 * cbMem) //[3]
                pIt->cAge++;
            else
                pIt->cAge = 0;
            pHdr = pIt; //[4]
            break;
        }
        else
        {
            /* Increase age and free if it reached a threshold. */
            pIt->cAge++;
            if (pIt->cAge == VUSBURB_AGE_MAX)
            {
                RTListNodeRemove(&pIt->NdFree);
                ASMAtomicDecU32(&pUrbPool->cUrbsInPool);
                RTMemFree(pIt);
            }
        }
    }

    if (!pHdr) //[5]
    {
        /* allocate a new one. */
        size_t cbDataAllocated = cbMem <= _4K  ? RT_ALIGN_32(cbMem, _1K)
                               : cbMem <= _32K ? RT_ALIGN_32(cbMem, _4K)
                                               : RT_ALIGN_32(cbMem, 16*_1K);

        pHdr = (PVUSBURBHDR)RTMemAllocZ(RT_UOFFSETOF_DYN(VUSBURBHDR, Urb.abData[cbDataAllocated]));
        if (RT_UNLIKELY(!pHdr))
        {
            RTCritSectLeave(&pUrbPool->CritSectPool);
            AssertLogRelFailedReturn(NULL);
        }

        pHdr->cbAllocated = cbDataAllocated;
        pHdr->cAge        = 0;
        ASMAtomicIncU32(&pUrbPool->cUrbsInPool);
    }
    RTCritSectLeave(&pUrbPool->CritSectPool);

    Assert(pHdr->cbAllocated >= cbMem);
}
```

VirtualBox especially implemented the custom free system on URB.


[1]: pHdr inclues structure of Urb

[2]: We can guess from the field name of `pUrbPool->aLstFreeUrbs`, the Urbs which was freed(removed) is inserted into the array.

[3], [4]:  If [The size of the freed URB obtained by for-each lop](`cbAllocated`) > [The required size] is satisfied, unlink and obtain the URB. That means reusing URB, not calling malloc.

[5] If none of the URBs on the freed list satisfy the condition, create(malloc) a new one.

THe structure of URB(PVUSBURBHDR) is like that.
![image](/assets/virtualbox/PVUSBURBHDR.png)



- The structure of URB is included in `pHDR`
- The structure of that URB has space which User is able to read and write as much as `cbData`. Also, includes the structure of `pVUsb`. (That is secure against leak vulnerability.)
- In the `pVUsb`, there are variables related to URB information. As can be inferred above image, is like `pvUSB =  &URB[cbData]`
- `pVUsb` also includes a function pointer, similar to `_free_hook` on glibc, that is called when Free on the URB Free system is invoked against that.


Now, I'll explain how I did leak with the custom free management system of URB.



### Heap overflow to Leak

"Let's clarify the information I have with additional details.

Heap-overflow (vmsvga)
- I can allocate `pbData` as much as I want.
- I can control `cbScanline` the gap of overflow.

URB
- I can create  multiple new URBs. 
- I can control the size of URB will be created.
- The already freed URB has a variable named `cbAllocated` which represents the total size of it.

The goal is overwriting `cbAllocated` of which freed URB using Heap overflow.
For that, I needed to perform [heap spray](https://en.wikipedia.org/wiki/Heap_spraying) and ensure stable possibility.

Because the host was Windows at Pwn2Own, I was able to use [LFH](https://illmatics.com/Understanding_the_LFH.pdf). This means I also had to have capability to allocate as much as I wanted and to read and write freely. I overcame it using **VBoxGuestPropSvc** of HGCM ([[1]](https://xz.aliyun.com/t/9274?time__1311=n4%2BxuDgD9DyDRD0xxGO4BMb7epwDOInmeD), [[2]](https://raw.githubusercontent.com/phoenhex/files/master/slides/thinking_outside_the_virtualbox.pdf)).

**The Leak Scenario**

1. Using VBoxGuestPropSvc, Allocate size **N** multiple times to activate LFH.
2. Create URB of size **N** and Free it to insert it into FreeList of URB free management system(though it's not actually freed on NTMalloc).
3. Using the found Heap-overflow vulnerability, overwrite `cbAllocated` of the freed URB's to a huge value like 0x41414141.
4. To be allocated next to the free URB, spray `VBoxGuestPropSvc` of size **N**.
5. Request to create a new URB with a size more than three times larger than **N***.
6. Because the `cbAllocated` value of the freed URB was overwritten to a huge value by [3], even if `vusbUrbPoolAlloc` gets request to the size of [5] which is larger than **N**, the function obtains the freed URB from FreeList.
7. The pVUsb of the URB is written to ``&URB[cbData = N*3 ([5])]``.
8. `&URB[N*3]` overlaps with the space of `VBoxGuestPropSvc`, which the guest can read and write freely. Therefore Guest can leak PIE and Heap.


![leak](/assets/virtualbox/leak.gif)


### Exploit

The process of exploit is so easier than leaking as well as it is not main point of the post and published exploit was working that I'll skip detailed explanation 

I used the same vulnerability to exploit. This time, I controlled the sturcture of `VBoxGuestPropSvc` to [ROP](https://en.wikipedia.org/wiki/Return-oriented_programming).

```c++
/** Get a guest property */
#define GUEST_PROP_FN_GET_PROP              1
/** Set a guest property */
#define GUEST_PROP_FN_SET_PROP              2
/** Set just the value of a guest property */
#define GUEST_PROP_FN_SET_PROP_VALUE        3
/** Delete a guest property */
#define GUEST_PROP_FN_DEL_PROP              4
/** Enumerate guest properties */
#define GUEST_PROP_FN_ENUM_PROPS            5
/** Poll for guest notifications */
#define GUEST_PROP_FN_GET_NOTIFICATION      6
/** @} */
```

`VBoxGuestPropSvc` provides the 6 features like above.

```c++
int Service::getNotification(uint32_t u32ClientId, VBOXHGCMCALLHANDLE callHandle,
                             uint32_t cParms, VBOXHGCMSVCPARM paParms[])
{
    int rc = VINF_SUCCESS;
    char *pszPatterns = NULL;           /* shut up gcc */
    char *pchBuf;
    uint32_t cchPatterns = 0;
    uint32_t cbBuf = 0;
    uint64_t nsTimestamp;

    /*
     * Get the HGCM function arguments and perform basic verification.
     */
    ...
        while (it != mGuestWaiters.end())
        {
            if (u32ClientId == it->u32ClientId)
            {
                const char *pszPatternsExisting;
                uint32_t    cchPatternsExisting;
                int rc3 = HGCMSvcGetCStr(&it->mParms[0], &pszPatternsExisting, &cchPatternsExisting);
                if (   RT_SUCCESS(rc3)
                    && RTStrCmp(pszPatterns, pszPatternsExisting) == 0)
                {
                    /* Complete the old request. */
                    mpHelpers->pfnCallComplete(it->mHandle, VERR_INTERRUPTED); //[1]
                    it = mGuestWaiters.erase(it);
                }
                ...
```
```c++
int HGCMThread::MsgComplete(HGCMMsgCore *pMsg, int32_t result)
{
    LogFlow(("HGCMThread::MsgComplete: thread = %p, pMsg = %p, result = %Rrc (%d)\n", this, pMsg, result, result));

    AssertRelease(pMsg->m_pThread == this);
    AssertReleaseMsg((pMsg->m_fu32Flags & HGCM_MSG_F_IN_PROCESS) != 0, ("%p %x\n", pMsg, pMsg->m_fu32Flags));

    int rcRet = VINF_SUCCESS;
    if (pMsg->m_pfnCallback)
    {
        /** @todo call callback with error code in MsgPost in case of errors */

        rcRet = pMsg->m_pfnCallback(result, pMsg); //[2]

        LogFlow(("HGCMThread::MsgComplete: callback executed. pMsg = %p, thread = %p, rcRet = %Rrc\n", pMsg, this, rcRet));
    }
```

[1]: Through HGCM Call, call `pfnCallComplete` with `it->mHandle` as argument, which is handle address of HGCM of the Guest.

[2]: The flow reaches to `HGCMThread::MsgComplete` from [1]. The `pMsg` in the function is same as `it->mHandle` and, it calls `m_pfnCallback` which is a function pointer.

Using the heap-overflow vulnerability, I could write it->mHandle to an arbitrary value, and the second argument of m_pfnCallback is pMsg (from it->mHandle). Finally, I succeeded in leading it to a ROP attack.

### Demo

[Demo.mp4](/assets/virtualbox/demo.mp4)