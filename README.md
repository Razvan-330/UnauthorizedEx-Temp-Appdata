<h1>Unauthorized Execution of Files in Temp or AppData</h1>

<h2>Description</h2>
This alert detects the execution of files from the Temp and AppData directories, which are commonly used by attackers and malware to run malicious code stealthily.
Most legitimate applications do not execute files directly from these folders, making any activity in these locations a strong indicator of potential malware infection.

<b>This alert can help with:</b>

- It helps detect suspicious executions that could be part of an attack
- Enables fast response to prevent malware from spreading
- Uncovers stealthy activity that would otherwise go unnoticed

<br />

<h2>Languages and Utilities Used</h2>

- <b>SPL-Search Processing Language</b>
- <b>BotsV2-[Dataset](https://github.com/splunk/botsv2)</b>
  
<h2>Environments Used </h2>

- <b>SIEM-Splunk</b>
- <b>OS-Kali Linux</b>

<h2>Alert Setup:</h2>

<b><p align="center">
SPL Query: <br/> 
</b>
```
index=botsv2 sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
| search Image="*\\AppData\\*" OR Image="*\\Temp\\*"
| table _time, Computer, user, Image, CommandLine, Hashes
```
<b>This SPL query uses Sysmon logs (EventCode 1) to detect any process execution from the AppData or Temp folders. The results include time, user, process path, command line, and file hashes to help with threat analysis.</b>


<br />
SPL Query Results in the Dataset:  <br/>
<img src="https://i.imgur.com/9KkOSE1.png" height="80%" width="80%" alt="Dataset Query"/>
<br />
We can observe that on August 24 and 26, 2017, users al.bungstien and amber.turing from the company “FROTHLY” executed a process named software_reporter_tool.exe in the AppData directory on their computers wrk-abungst.frothly.local and wrk-aturing.frothly.local between 4 AM and 5 AM.

<b>Suspicious indicators:</b>

-The process was executed outside of working hours.

-The file is an executable (.exe).

-Hash lookup (SHA1): Initially seems harmless, but VirusTotal shows that it's linked to malware in the Relations tab.

This suggests a likely malware infection. The systems should be quarantined, and user accounts temporarily disabled to prevent further spread. A deeper investigation is required.

<br />
<b>Initial Hash Search</b>  <br/>
<img src="https://i.imgur.com/FgnPw92.png" height="80%" width="80%" alt="Dataset Query"/>
<br />

<br />
<b>Relations Tab</b>  <br/>
<img src="https://i.imgur.com/vyoxGCA.png" height="80%" width="80%" alt="Dataset Query"/>
<br />

<br />
<b>Linked to Malware</b>  <br/>
<img src="https://i.imgur.com/71TmsLa.png" height="80%" width="80%" alt="Dataset Query"/>
<br />

<b><h3>Saving and Configuring the Alert:</h3></b>

To save and configure the alert, click on Save as > Alert.

<b>Title:</b> New Process in AppData/Temp Alert

<b>Permissions:</b> Shared in App (so the security team can act quickly)

<b>Alert Type:</b> Real-time

<b>Expires:</b> Set to 24 Hours. The alert will expire 24 hours after being triggered, which is appropriate for this type of attack, as it requires a fast response.

<b>Trigger Conditions:</b> Per result (each detection triggers the alert)

<b>Trigger Actions:</b> Add to triggered alerts (Severity: Critical)

<br />
Save as Alert: <br/>
<img src="https://i.imgur.com/LJ2yeiL.png" height="80%" width="80%" alt="Bruteforce alert"/>
<br />

<h2>Conclusion</h2>

Files like trojans, ransomware, and attack scripts are often downloaded and executed from paths such as:

C:\Users\[User]\AppData\Local\Temp

C:\Users\[User]\AppData\Roaming

This behavior is frequently seen in attacks such as:

-Ransomware (encrypting user files)

-Trojans / Keyloggers

-Living-off-the-Land (LotL) attacks (using legitimate tools like powershell.exe, cmd.exe, mshta.exe)

<!--
 ```diff
- text in red
+ text in green
! text in orange
# text in gray
@@ text in purple (and bold)@@
```
--!>
