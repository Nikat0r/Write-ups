# TryHackMe: Tempest

**Platform:** TryHackMe | **Path:** SOC Level 1 | **Type:** Incident response / log and network forensics

> Spoilers (domains, ports, timestamps, tool names) are hidden in collapsible blocks. Click to reveal. Flags and answer-field values are not included.

## Summary

A SOC analyst triaged a CRITICAL alert: a user downloaded a malicious `.doc` through Chrome, and it executed a chain of commands. I acted as the incident responder and reconstructed the full intrusion from Sysmon logs, Windows Security logs and a packet capture: initial access through a malicious document, a stage 2 implant with C2, internal reconnaissance, a reverse SOCKS proxy, privilege escalation, and persistence through new accounts and a Windows service.

## Tools

- **EvtxECmd** to parse EVTX logs into CSV
- **Timeline Explorer** to filter and sort the parsed logs
- **Wireshark** for the packet capture
- **PowerShell** to decode large Base64 output
- VirusTotal for hash lookups

## Setup

Sysmon logs were parsed from EVTX to CSV with EvtxECmd, then loaded into Timeline Explorer.

![EvtxECmd parsing the Sysmon log](images/tempest-01.png)
![Parsed CSV loaded in Timeline Explorer](images/tempest-02.png)

## 1. Initial access: malicious document

**Question:** which document compromised the user, and who was affected?

Since the document came through Chrome, I filtered on `chrome.exe`. The download event gave me the file name, the compromised user and the machine name (`Computer` and `User name` fields), plus a timestamp for the attack timeline.

![Chrome download event](images/tempest-03.png)

To find the Word process that opened it, I filtered on the document name and used the process creation event (Event ID 1), where the command line shows Word and its PID.

![Process creation for the document](images/tempest-04.png)
![Command line and PID](images/tempest-05.png)

For the malicious domain, the `Zone.Identifier` stream creation events (Event ID 15) for the document revealed where it was downloaded from. A live DNS lookup returned nothing, because the domain was no longer active. I pivoted to historical Sysmon DNS logs (Event ID 22), filtered on `chrome.exe`, and found the query that resolved it.

![Zone.Identifier event](images/tempest-06.png)
![DNS query event](images/tempest-07.png)

Next I filtered on `ParentProcessID` using Word's PID to find the child process it spawned. The first of three events held the Base64-encoded payload.

![Encoded payload in the command line](images/tempest-08.png)

Researching the decoded command line, the `msdt.exe` call with the `ms-msdt:` handler, led me straight to the vulnerability used (name and CVE in the spoiler block below).

<details>
<summary>Spoiler: values</summary>

- Vulnerability: Follina, CVE-2022-30190
- Malicious domain: `phishteam.xyz`
- Download: 2022-06-20 17:12:58
- DNS query: 2022-06-20 17:12:57
- Word process execution: 2022-06-20 17:13:12
- Payload execution: 2022-06-20 17:13:35

</details>

## 2. Stage 2 execution

Decoding the payload showed it writes into the user's Startup folder, downloads a `.zip` from the same domain, expands it, and deletes the archive. Filtering on Event ID 11 (file creation) with the execution timestamp gave me the full path of the dropped file.

![File creation event](images/tempest-09.png)

The payload runs when the user logs in. To prove that, I parsed the Windows Security log, filtered on Event ID 4624 (successful logon), and noted the time the attacker logged in again. Returning to Sysmon, I filtered on process creation events after that timestamp and found the command that ran at login. It downloaded a binary using a built-in Windows utility, then executed it right away. The SHA256 hash is in that same process creation event.

![4624 logons](images/tempest-10.png)
![Command executed at login](images/tempest-11.png)
![Downloaded binary and hash](images/tempest-12.png)

The binary then opened a C2 connection. Event ID 3 (network connection), filtered around that timestamp, showed the destination IP and port. The question asked for a domain, so I searched the DNS events for the IP to find the matching domain.

![Network connection events](images/tempest-13.png)
![DNS query resolving the C2 domain](images/tempest-14.png)

<details>
<summary>Spoiler: values</summary>

- Second logon: 2022-06-20 17:14:49
- Login command execution: 2022-06-20 17:15:10
- Binary download utility: `certutil`
- Binary execution: 2022-06-20 17:15:14
- First C2 connection: 2022-06-20 17:15:16
- C2 domain: `resolvecyber.xyz`

</details>

## 3. Network analysis (Wireshark)

In the packet capture I filtered HTTP traffic on the first domain and found the URL of the payload fetched by the encoded PowerShell command.

![Payload URL in Wireshark](images/tempest-15.png)

Filtering on the C2 domain showed the C2 traffic: repeated GET requests with encoded URLs, a parameter carrying the command output, and a fixed URL the binary polls for new commands. The user agent revealed which language the implant was written in.

![Encoded C2 requests](images/tempest-16.png)
![User agent](images/tempest-17.png)

<details>
<summary>Spoiler: values</summary>

- Result parameter: `q`
- Filters used: `http contains "phishteam"` and `http contains "resolvecyber"`

</details>

## 4. Discovery: internal reconnaissance

Decoding the C2 traffic showed the attacker's commands and their output. One of the decoded commands revealed a sensitive file and a password stored inside it.

![Decoded command output](images/tempest-18.png)

The attacker then listed listening ports. The output was too large to copy from the console, so I decoded it with PowerShell:

```powershell
$t = Get-Content "file with encoded output" -Raw
$b64 = [regex]::Match($t,'[A-Za-z0-9+/]{40,}={0,2}').Value
[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($b64)) | Out-File decoded.txt
notepad decoded.txt
```

![Decoded netstat output](images/tempest-19.png)

Among the listening ports, one belongs to Windows Remote Management, which can give an interactive remote session. I had to research what each port was for. This was a knowledge gap for me.

<details>
<summary>Spoiler: values</summary>

- WinRM HTTP port: `5985` (unencrypted)
- Port enumeration: 2022-06-20 17:16:51

</details>

## 5. Reverse SOCKS proxy and lateral movement tooling

After seeing that port, the attacker used PowerShell to download another binary. More process creation events showed it was used to set up a reverse SOCKS proxy, and the hash of the binary was in the same log. A hash lookup identified the tool.

![PowerShell download](images/tempest-20.png)
![Reverse SOCKS proxy command](images/tempest-21.png)
![Binary hash](images/tempest-22.png)

Right after the proxy started, I saw `wsmprovhost.exe` being created, and a child `powershell.exe whoami /priv` with it as parent. `wsmprovhost.exe` hosts remote PowerShell sessions, so the attacker was authenticating to the host's remote management service with the harvested credentials, a living-off-the-land technique (service name in the spoiler block below).

![wsmprovhost process](images/tempest-23.png)
![whoami /priv child process](images/tempest-24.png)

<details>
<summary>Spoiler: values</summary>

- Reverse SOCKS proxy activation: 2022-06-20 17:18:48
- Service used to authenticate: WinRM

</details>

## 6. Privilege escalation

After `whoami /priv`, the attacker downloaded another binary with PowerShell (`iwr`). I found its hash in a later execution event and identified the tool on VirusTotal. The tool abuses a specific privilege held by the user; I researched which one. The attacker then ran it to launch a second C2 binary, and Event ID 3 showed it connecting on a different port than the first C2.

![Privilege escalation tool download](images/tempest-25.png)
![Execution with the second binary](images/tempest-26.png)
![Second C2 connection](images/tempest-27.png)

<details>
<summary>Spoiler: values</summary>

- Tool binary: `spf.exe`
- Download: 2022-06-20 17:20:06
- Execution with new binary: 2022-06-20 17:21:34
- Second C2 connection: 2022-06-20 17:21:35

</details>

## 7. Actions on objectives: persistence

With SYSTEM access, the attacker created two accounts. Process creation events showed a run of `net`/`net1.exe` commands. A first attempt failed because an option was missing; a later attempt added it and succeeded. One account was then added to the local administrators group, and a final command created a Windows service for persistent admin access.

![Account creation commands](images/tempest-28.png)
![Failed vs. successful attempt](images/tempest-29.png)
![Service creation](images/tempest-30.png)

*Command details are censored in the screenshots.*

<details>
<summary>Spoiler: values</summary>

- Group: `administrators`
- Service name: `TEMPESTUpdate`
- Service creation: 2022-06-20 17:26:04

</details>

## Attack chain

| Stage | Behaviour | MITRE ATT&CK (suggested, verify) |
|---|---|---|
| Initial access | Malicious `.doc` downloaded via Chrome | T1566 Phishing |
| Execution | Word spawns `msdt.exe` via the `ms-msdt:` handler | T1203 Exploitation for Client Execution |
| Persistence | Payload dropped in Startup folder, runs at logon | T1547.001 Startup Folder |
| Ingress tool transfer | Binaries pulled with `iwr` and a built-in utility | T1105 |
| C2 | HTTP beaconing with Base64-encoded data | T1071.001, T1132 |
| Discovery | Port and file enumeration | T1049, T1083 |
| Lateral movement | Remote management service with harvested credentials | T1021.006 |
| Proxy | Reverse SOCKS proxy | T1090 |
| Privilege escalation | Abuse of a user privilege to elevate to SYSTEM | T1134.001 Token Impersonation/Theft |
| Persistence | New local accounts, new service | T1136.001, T1543.003 |

## Detection takeaways

- **Office spawning `msdt.exe`** via the `ms-msdt:` handler is a high-confidence alert for exploitation of the Office/msdt flaw.
- **Downloads followed by immediate execution** from user-writable paths, especially through built-in utilities.
- **Periodic HTTP GETs** with long encoded query strings to a rarely seen domain.
- **`wsmprovhost.exe`** appearing on a host that doesn't normally receive remote PowerShell.
- **Burst of `net user` / `net localgroup` commands**, and new services created by non-admin tooling.

## What I got wrong first

- Tried resolving the malicious domain live instead of using historical Sysmon DNS logs (Event ID 22).
- Decoded the Base64 string when the question asked for the encoded value.
- Didn't know which listening port corresponded to remote management. I researched the common Windows ports afterwards.

## What I'd do differently

- Build the timeline in a separate sheet as I go, not at the end.
