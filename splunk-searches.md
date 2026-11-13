# Splunk searches

All searches use the Sysmon XML sourcetype collected from the Windows endpoint.

## Reusable field extractions

```spl
| rex field=_raw "<EventID[^>]*>(?<SysmonEventID>\d+)</EventID>"
| rex field=_raw "<Data Name=.Image.>(?<Image>[^<]+)"
| rex field=_raw "<Data Name=.CommandLine.>(?<CommandLine>[^<]+)"
| rex field=_raw "<Data Name=.User.>(?<User>[^<]+)"
| rex field=_raw "<Data Name=.ParentImage.>(?<ParentImage>[^<]+)"
```

The dot surrounding each XML attribute value deliberately accommodates either single or double quotation marks in the rendered raw event.

## 1. Total Sysmon events

```spl
index=* sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
| stats count AS "Total Sysmon Events"
```

## 2. Sysmon events over time

```spl
index=* sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
| timechart span=5m count AS Events
```

## 3. Sysmon Event IDs by volume

```spl
index=* sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
| rex field=_raw "<EventID[^>]*>(?<SysmonEventID>\d+)</EventID>"
| stats count AS Events BY SysmonEventID
| sort - Events
```

## 4. Top processes created

```spl
index=* sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
| rex field=_raw "<EventID[^>]*>(?<SysmonEventID>\d+)</EventID>"
| rex field=_raw "<Data Name=.Image.>(?<Image>[^<]+)"
| search SysmonEventID=1
| eval Process=replace(Image,"^.*\\","")
| stats count AS Executions BY Process
| sort - Executions
| head 10
```

## 5. Recent process creation

```spl
index=* sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
| rex field=_raw "<EventID[^>]*>(?<SysmonEventID>\d+)</EventID>"
| rex field=_raw "<Data Name=.Image.>(?<Image>[^<]+)"
| rex field=_raw "<Data Name=.CommandLine.>(?<CommandLine>[^<]+)"
| rex field=_raw "<Data Name=.User.>(?<User>[^<]+)"
| rex field=_raw "<Data Name=.ParentImage.>(?<ParentImage>[^<]+)"
| search SysmonEventID=1
| table _time host User Image CommandLine ParentImage
| sort - _time
| head 20
```

## 6. PowerShell process activity

```spl
index=* sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
| rex field=_raw "<EventID[^>]*>(?<SysmonEventID>\d+)</EventID>"
| rex field=_raw "<Data Name=.Image.>(?<Image>[^<]+)"
| rex field=_raw "<Data Name=.CommandLine.>(?<CommandLine>[^<]+)"
| rex field=_raw "<Data Name=.User.>(?<User>[^<]+)"
| rex field=_raw "<Data Name=.ParentImage.>(?<ParentImage>[^<]+)"
| search SysmonEventID=1
| where like(lower(Image), "%\\powershell.exe") OR like(lower(Image), "%\\pwsh.exe")
| table _time host User Image CommandLine ParentImage
| sort - _time
```

## 7. Suspicious PowerShell indicators

```spl
index=* sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
| rex field=_raw "<EventID[^>]*>(?<SysmonEventID>\d+)</EventID>"
| rex field=_raw "<Data Name=.Image.>(?<Image>[^<]+)"
| rex field=_raw "<Data Name=.CommandLine.>(?<CommandLine>[^<]+)"
| rex field=_raw "<Data Name=.User.>(?<User>[^<]+)"
| rex field=_raw "<Data Name=.ParentImage.>(?<ParentImage>[^<]+)"
| search SysmonEventID=1
| where like(lower(Image), "%\\powershell.exe") OR like(lower(Image), "%\\pwsh.exe")
| eval DetectionReason=case(
    like(lower(CommandLine), "%executionpolicy%bypass%"), "ExecutionPolicy Bypass",
    like(lower(CommandLine), "%encodedcommand%"), "Encoded PowerShell command",
    like(lower(CommandLine), "%frombase64string%"), "Base64 decoding",
    like(lower(CommandLine), "%downloadstring%"), "DownloadString usage",
    like(lower(CommandLine), "%invoke-webrequest%"), "Invoke-WebRequest usage",
    like(lower(CommandLine), "%invoke-expression%"), "Invoke-Expression usage",
    true(), "Other PowerShell activity"
)
| search DetectionReason!="Other PowerShell activity"
| table _time host User Image CommandLine ParentImage DetectionReason
| sort - _time
```

### Scheduled alert settings

| Setting | Value |
|---|---|
| Title | SOC Lab - Suspicious PowerShell Activity |
| Schedule | `*/5 * * * *` |
| Search window | Last 5 minutes |
| Condition | Number of results greater than 0 |
| Trigger | Once |
| Action | Add to Triggered Alerts |
| Severity | Medium |

The detection output must be investigated in context. A match is not automatically malicious.

