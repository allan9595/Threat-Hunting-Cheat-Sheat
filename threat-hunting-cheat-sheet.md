## Hunting Empire
1. eif-parser
2. Get-InjectedThread
3. Nork-Nork.exe

## Hunting Responder
1. [CredDenfense (Responder Guard)](blackhillsinfosec.com/the-creddefense-toolkit/)
2. Powershell Script Block Logging (Event ID 4104)
3. Sysmon Event ID 3
4. Honey Credentials (Event ID 4648)

https://www.markdownguide.org/cheat-sheet/
https://markdownlivepreview.com/

## Event ID
1. 4624 (successful logon)
2. 4625 (failed logon)
3. 4634 (successful logoff)
4. 4647 (user-initiated logoff)
5. 4648 (logon using explicit credentials)
6. 4672 (special privileges assigned)
7. 4768 (Kerberos ticket (TGT) requested)
8. 4769 (Kerberos service ticket requested)
9. 4771 (Kerberos pre-auth failed)
10. 4776 (attempted to validate credentials)
11. 4778 (session reconnected)
12. 4779 (session disconnected)
13. 4720 (account created)
14. 4722 (account enabled)
15. 4724 (attempt to reset password)
16. 4728 (user added to global group)
17. 4732 (user added to local group)
18. 4756 (user added to universal group)

## Logon Type
1. 2 Interactive A user physically logged onto this computer.
2. 3 Network A user or computer logged on from the network.
3. 4 Batch Used by batch servers where processes may be executing on behalf of a user, like scheduled tasks.
4. 5 Service A service started by the Service Control Manager.
5. 7 Unlock The workstation was unlocked.
6. 8 NetworkClear text Network credentials sent in cleartext.
7. 9 NewCredentials A caller cloned its current token and specified new credentials (runas command).
8. 10 RemoteInteractive A user logged onto computer using Terminal Services or RDP.
9. 11 CachedInteractive A user logged onto computer using network credentials which were stored locally on the computer.

## Hunting PTH
1. Looking for Event ID 4624 and Logon Type 3, and Logon Process to be NtLmSsP as well key length to be 0

## Hunting RDP
1. Looking for Event ID 4624 and 4778, Logon Type 3

## Hunting Passwd Attack
1. Looking for Event ID 4625, Logon Type 3

## Hunting PsEXEC
1. Looking for "\\" and prefix "-accepteula"
2. 5145 (captures requests to shares, we are interested in ADMIN$ and IPC$)
3. 5140 (share successfully accessed)
4. 4697 / 7045 (service creation)
5. 4688 / Sysmon EID 1

## Hunting WMI
1. [https://www.fireeye.com/blog/threat-research/2016/08/wmi_vs_wmi_monitor.html](https://www.fireeye.com/blog/threat-research/2016/08/wmi_vs_wmi_monitor.html)

## Hunting Scheduled Tasks
1. Looking for Event ID 4698, 106, 200, 201

## Hunting Network Shares
1. Looking for Event ID 4776, 5140, 5145

## Hunting Windows Log Rotation & Clearing
1. Looking for Event ID 1102, 104

## Other resources:
1. [https://github.com/ThreatHuntingProject/ThreatHunting/blob/master/hunts/lateral-movement-windows-authentication-logs.md](https://github.com/ThreatHuntingProject/ThreatHunting/blob/master/hunts/lateral-movement-windows-authentication-logs.md)
2. [https://github.com/ThreatHuntingProject/ThreatHunting/blob/master/hunts/lateral_movement_detection_via_process_monitoring.md](https://github.com/ThreatHuntingProject/ThreatHunting/blob/master/hunts/lateral_movement_detection_via_process_monitoring.md)
3. [https://github.com/ThreatHuntingProject/ThreatHunting/blob/master/hunts/lateral-movement-via-explicit-credentials.md](https://github.com/ThreatHuntingProject/ThreatHunting/blob/master/hunts/lateral-movement-via-explicit-credentials.md)
4. [https://jpcertcc.github.io/ToolAnalysisResultSheet/](https://jpcertcc.github.io/ToolAnalysisResultSheet/)
5. [https://www.jpcert.or.jp/english/pub/sr/DetectingLateralMovementThroughTrackingEventLogs_version2.pdf](https://www.jpcert.or.jp/english/pub/sr/DetectingLateralMovementThroughTrackingEventLogs_version2.pdf)

## Tools
1. [sysmon](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon)
   [sysmon-config](https://github.com/SwiftOnSecurity/sysmon-config)

## LOLBAS
1. [https://lolbas-project.github.io/](https://lolbas-project.github.io/)
2. Looking for hashes
3. Looking for process description
4. [https://car.mitre.org/analytics/CAR-2013-04-002/](https://car.mitre.org/analytics/CAR-2013-04-002/)

## Powershell Logging (Script Block Logging)
1. Event ID (4104,4105,4106)
2. [https://github.com/Neo23x0/sigma/tree/master/rules/windows/powershell](https://github.com/Neo23x0/sigma/tree/master/rules/windows/powershell)
3. [https://github.com/danielbohannon/Invoke-Obfuscation](https://github.com/danielbohannon/Invoke-Obfuscation)
4. [https://github.com/Ben0xA/nps](https://github.com/Ben0xA/nps)
5. Looking for Event ID 400, 500
6. [https://github.com/GhostPack](https://github.com/GhostPack)

## Hunting .NET
1. ETW
2. [https://github.com/fireeye/SilkETW](https://github.com/fireeye/SilkETW)
3. [https://github.com/byt3bl33d3r/SILENTTRINITY]
4. Get-WinEvent -FilterHashtable @{logname="Microsoft-WindowsSysmon/Operational"; id=1} | Where-Object {$_.Properties[10].Value -like "*Windows_Reporting.exe*"} | fl
5. [https://github.com/fireeye/SilkETW](https://github.com/fireeye/SilkETW)
6. [https://github.com/endgameinc/ClrGuard](https://github.com/endgameinc/ClrGuard)
7. [https://zhuanlan.zhihu.com/p/38601278](https://zhuanlan.zhihu.com/p/38601278)
8. [https://pen-testing.sans.org/resources/papers/gpen/preventing-living-land-attacks-140526](https://pen-testing.sans.org/resources/papers/gpen/preventing-living-land-attacks-140526)

## AMSI
1. [https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell)
2. [https://blog.f-secure.com/hunting-for-amsi-bypasses/](https://blog.f-secure.com/hunting-for-amsi-bypasses/)
3. [https://bohops.com/2018/06/28/abusing-com-registry-structure-clsid-localserver32-inprocserver32/](https://bohops.com/2018/06/28/abusing-com-registry-structure-clsid-localserver32-inprocserver32/)

## Hunting WMI
1. [https://cyberwardog.blogspot.com/2017/03/chronicles-of-threat-hunter-hunting-for_26.html](https://cyberwardog.blogspot.com/2017/03/chronicles-of-threat-hunter-hunting-for_26.html)
2. Get-WinEvent -FilterHashtable @{logname="Microsoft-Windows-Sysmon/Operational"; id=1} | Where-Object {$_.Properties[20].Value -like "*wmi*"} | fl

## Powershell
1. [https://www.sans.org/reading-room/whitepapers/threathunting/hunting-gathering-powershell-38842](https://www.sans.org/reading-room/whitepapers/threathunting/hunting-gathering-powershell-38842)
2. [https://github.com/Infocyte/PSHunt](https://github.com/Infocyte/PSHunt)
3. [https://devblogs.microsoft.com/scripting/use-powershell-cmdlet-to-filter-event-log-for-easy-parsing/](https://devblogs.microsoft.com/scripting/use-powershell-cmdlet-to-filter-event-log-for-easy-parsing/)


[https://www.sans.org/cyber-security-summit/archives/file/summit-archive-1536354143.pdf](https://www.sans.org/cyber-security-summit/archives/file/summit-archive-1536354143.pdf)