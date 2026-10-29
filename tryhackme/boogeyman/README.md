# TryHackMe: Boogeyman (1, 2 and 3)

**Platform:** TryHackMe | **Path:** SOC Level 1 | **Type:** Email analysis, log analysis, memory forensics, network forensics

> Spoilers (names, answers, exact commands) are hidden in collapsible blocks. Click to reveal. Flags and credentials are not included.

## Summary

A three-part scenario in which a threat group called the Boogeyman repeatedly targets Quick Logistics LLC, each time with improved tactics. Across the three rooms I worked a phishing intrusion end to end using different evidence each time: email headers, PowerShell logs and a packet capture (part 1), a malicious macro and a memory dump (part 2), and an ELK stack with Sysmon-style process telemetry (part 3). The highlight for me was part 1, where I rebuilt a file stolen over DNS directly from the packet capture.

| Room | Scenario | Evidence | Main tools |
|---|---|---|---|
| Boogeyman 1 | Phishing of a finance employee | `.eml`, PowerShell logs, PCAP | Thunderbird, lnkparse, jq, Wireshark, tshark |
| Boogeyman 2 | Phishing of an HR specialist | `.eml`, memory dump | olevba, Volatility 3, strings |
| Boogeyman 3 | CEO targeted, full domain compromise | Logs in Kibana (ELK) | Kibana / Elasticsearch |

*Scenario images below are from the room itself.*

---

## Boogeyman 1: phishing, PowerShell logs and DNS exfiltration

Julianne, a finance employee, received a follow-up email about an unpaid invoice from a business partner. The attached document was malicious.

![Room scenario](images/boogeyman-misc-1.png)

### Email analysis

I opened `dump.eml` in Thunderbird. The sender and the victim's address are visible in the headers. Using **View source** to read the raw headers, the `DKIM-Signature` and `List-Unsubscribe` headers revealed the third-party mail relay the attacker used. The attachment was an encrypted archive, and its password was in the email body. Inside was a shortcut file. Parsing it with `lnkparse` showed an encoded PowerShell payload in the Command Line Arguments field.

![Raw email headers](images/boogeyman-01.png)
![DKIM-Signature header](images/boogeyman-02.png)
![lnkparse output](images/boogeyman-03.png)

### Endpoint: PowerShell logs

PowerShell Script Block Logging records the script text as the engine executes it, which usually includes the decoded content of encoded commands. That made the logs readable. I extracted and de-duplicated the script blocks:

```bash
cat powershell.json | jq '{ScriptBlockText}' | uniq | sort -nr | uniq
```

![Script block output](images/boogeyman-04.png)

From this I found the domains used for file hosting and C2, and the enumeration tool the attacker downloaded. The tool was run against a database file belonging to a desktop application in the user's profile. The full path was not in a single command, so I derived it by following the earlier `cd` commands. Further down, a script read a password database file and sent it out through a C2 channel. The exfiltration tool and encoding were visible in the commands.

![Tool run against the database file](images/boogeyman-05.png)
![Exfiltration script](images/boogeyman-06.png)

### Network analysis

In Wireshark, the `Server` header in HTTP responses from the attacker's infrastructure revealed the software hosting the payloads.

![Server header](images/boogeyman-07.png)

The attacker returned command output to the C2 using POST requests. I found the one related to the sensitive file, followed its TCP stream and decoded the values to recover the password.

![POST request](images/boogeyman-08.png)
![Followed stream](images/boogeyman-09.png)

The last question asked for data inside the exfiltrated file. This one stumped me and I used the room's hint. The data had been sent out through DNS queries, so I rebuilt the file from the capture. Filtering DNS traffic to the attacker's IP was very noisy at first:

![Raw tshark output](images/boogeyman-10.png)
![After grepping the domain](images/boogeyman-11.png)

The final pipeline (values replaced with placeholders, real ones are in the spoiler block):

```bash
tshark -r capture.pcapng -Y "ip.dst==<C2_IP> and dns" -T fields -e dns.qry.name \
  | grep -E '[A-F0-9]+\.<exfil-domain>$' \
  | cut -d "." -f1 | tr -d '\n' | xxd -p -r > recovered_file
```

What each stage does:
- `-Y` keeps only DNS queries sent to the attacker's IP.
- `-T fields -e dns.qry.name` prints just the queried names.
- `grep` keeps the exfiltration subdomains (hex labels on the attacker's domain).
- `cut` takes the hex label from each name, and `tr` joins them into one string.
- `xxd -p -r` converts the hex back into the original binary file.

I then opened the recovered file with the password found earlier and got the answer.

![Recovered file](images/boogeyman-13.png)

<details>
<summary>Spoiler: Boogeyman 1 values</summary>

- File accessed: `plum.sqlite` (Microsoft Sticky Notes)
- Exfiltrated file: `protected_data.kdbx`
- Exfiltration tool: `nslookup`
- Encoding: hex
- Real pipeline:

```bash
tshark -r capture.pcapng -Y "ip.dst==167.71.211.113 and dns" -T fields -e dns.qry.name | grep -E '[A-F0-9]+.bpakcaging.xyz$' | cut -d "." -f1 | tr -d '\n' | xxd -p -r > file.kdbx
```

</details>

---

## Boogeyman 2: macro and memory forensics

Maxine, an HR specialist, received a job application with a malicious resume attached. This time the evidence was the email and a memory dump of her workstation.

![Room scenario](images/boogeyman-misc-2.png)

### Email and macro

The mail file showed the sender and the attachment name. I saved the attachment and hashed it with `md5sum`. To inspect the macro I used `olevba`, which extracts VBA code from Office documents. Its output gave the URL of the stage 2 payload, the process used to run it, and the payload's full path.

![Email](images/boogeyman-14.png)
![md5sum](images/boogeyman-15.png)
![olevba output](images/boogeyman-16.png)
![Payload path](images/boogeyman-17.png)

### Memory forensics

I used the process tree to establish the parent-child chain and the PIDs:

```bash
vol -f <image> windows.pstree.PsTree
```

![Process tree](images/boogeyman-18.png)

Then I searched the raw image for the script name, with context lines, to find the download URL for the next binary sitting nearby in memory:

```bash
strings <image> | grep -i -A 5 -B 5 "<script-name>"
```

![Strings output](images/boogeyman-19.png)

For the C2 process I used `netscan` to find its connections (which also gave the C2 IP and port) and `windows.cmdline --pid <PID>` to get its full path. The email attachment's path came from grepping the image for the `.doc` extension, and the persistence mechanism from a grep for `schtasks` with `/create`:

```bash
strings <image> | grep -i -E "schtasks.*/create"
```

![netscan](images/boogeyman-20.png)
![cmdline](images/boogeyman-21.png)
![Attachment path](images/boogeyman-22.png)
![Scheduled task command](images/boogeyman-23.png)

<details>
<summary>Spoiler: Boogeyman 2 values</summary>

- Process executing the payload: `wscript.exe`
- Chain: `winword.exe` → `wscript.exe` → `updater.exe`

</details>

---

## Boogeyman 3: ELK, domain compromise

After the previous attacks, the company hired a managed SOC. The Boogeyman had kept quiet inside an employee's email and used it to target the CEO. The CEO opened an attachment (an ISO) that appeared to do nothing, then reported it. The incident window was 29 to 30 August 2023, and the evidence was in Kibana.

![Room scenario](images/boogeyman-misc-3.png)

I worked through the process creation events (Event ID 1), pivoting on parent process and PID.

- **Stage 1:** searched for the payload name to find the process that executed it, then used its command line as the *parent* command line to find what it ran next: the file implant and the command that executed it.

![Stage 1 process](images/boogeyman-24.png)
![Implant command](images/boogeyman-25.png)
![Execution of the implant](images/boogeyman-26.png)

- **Persistence:** a long command created a scheduled task. The task name is in the `Register-ScheduledTask` argument.

![Scheduled task command](images/boogeyman-27.png)

- **C2:** I took the PID of the implanted file's process and correlated it with Event ID 3 (network connection) to get the IP and port.

![C2 connection](images/boogeyman-28.png)

- **Privilege escalation:** following `parent_process.pid` down the chain, I saw discovery commands (`whoami`, `net.exe`), then a legitimate Windows binary launched by the implant, which is a known way to bypass UAC.

![Discovery](images/boogeyman-29.png)

- **Credential dumping:** I added `process.args` to my columns and found a well-known credential dumping tool downloaded from GitHub. Filtering on the tool's name showed the new username and hash pair it dumped.

![Credential dumping](images/boogeyman-30.png)
![Dumped credentials](images/boogeyman-31.png)

- **Lateral movement:** the attacker used the credentials to enumerate file shares and read a remote script file. The script contained a new set of credentials, which the attacker immediately used to log in to another machine. On the second machine, the lateral movement command ended with a `whoami`, so I jumped to that log to get the parent process name.

![Share access](images/boogeyman-32.png)
![Login with new credentials](images/boogeyman-33.png)
![Parent process on machine two](images/boogeyman-34.png)

- **Domain controller:** the attacker dumped the administrator's credentials, then ran a DCSync attack. Besides the administrator, one more account's credentials were dumped.

![Administrator dump](images/boogeyman-35.png)
![DCSync](images/boogeyman-36.png)

- **Impact:** a final log showed the attacker downloading a ransomware binary from a link.

![Ransomware download](images/boogeyman-37.png)

<details>
<summary>Spoiler: Boogeyman 3 values</summary>

- UAC bypass binary: `fodhelper.exe`
- Credential dumping tool: `mimikatz`
- Remote file accessed: `IT_Automation.ps1`
- Account the attacker logged in to next: `allan.smith`
- Command at the end of the lateral movement line: `whoami`
- Second DCSync account: `backupda`
- Ransomware binary: `randomboogey.exe`

</details>

---

## Attack chains (MITRE ATT&CK)

| Room | Behaviour | Technique |
|---|---|---|
| All | Phishing email with malicious attachment | T1566.001 Spearphishing Attachment |
| 1 | Shortcut file launching encoded PowerShell | T1204.002 User Execution, T1059.001 PowerShell |
| 1 | Reading local app data | T1005 Data from Local System |
| 1 | Data exfiltration via DNS with hex encoding | T1048, T1071.004, T1132.001 |
| 2 | Macro downloads and runs a script | T1059.005 VBA, T1059.007 JavaScript |
| 2, 3 | Scheduled task for persistence | T1053.005 Scheduled Task |
| 3 | UAC bypass | T1548.002 |
| 3 | Credential dumping | T1003.001 LSASS Memory |
| 3 | Reusing a hash to authenticate | T1550.002 Pass the Hash |
| 3 | Share enumeration and credentials in a script | T1135, T1552.001 |
| 3 | DCSync | T1003.006 |
| 3 | Ransomware staging | T1105 Ingress Tool Transfer |

## Detection takeaways

- **Shortcut or macro-enabled files from email** launching PowerShell or a script host (`wscript`) are high-confidence, especially from an Office process.
- **DNS exfiltration:** many long, hex-looking subdomains to a single domain, or a large query volume from one host.
- **Script Block Logging** was the difference-maker in part 1. It is worth having enabled everywhere.
- **Scheduled task creation** (`schtasks /create`, `Register-ScheduledTask`) shortly after a C2 callback.
- **UAC bypass binaries** launched by an unusual parent, followed by credential dumping.
- **Directory replication requests** from a host that is not a domain controller (DCSync).
- **Hash-based logons** and a sudden jump from one workstation to another with a new account.

## What I got wrong first

- **Boogeyman 3:** I set my Kibana time filter from 29 August 00:00 to 30 August 00:00 and missed all of the 30th. The scenario gave the full window, and I should have re-read it before filtering. I only noticed partway through the investigation.
- **Boogeyman 1:** I couldn't work out how to get the data out of the capture and used the room's hint. After that, I understood that DNS exfiltration is just data carried in query names, which can be extracted and reassembled.

## What I'd do differently

- **Confirm the scope before filtering.** Re-read the scenario's time window and check my filters against it before I start, instead of discovering the mistake midway.
- **Keep a running timeline** in a separate sheet as I go, not at the end. Part 3 in particular, with its many hops between machines, would have been easier to follow with one.
