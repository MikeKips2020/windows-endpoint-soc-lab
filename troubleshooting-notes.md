# Sysmon and Splunk troubleshooting notes

## Problem statement

Splunk was already receiving the Windows Application, Security and System channels, but this search returned no results:

```spl
index=* sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
```

The objective was to determine whether the failure was at the endpoint service, input configuration, forwarding path, receiver or search layer.

## 1. Verify endpoint services

```powershell
Get-CimInstance Win32_Service -Filter "Name='SplunkForwarder'" |
    Select-Object Name, StartName, State

Get-Service SplunkForwarder, Sysmon64
```

Both services were running. This established service health but did not prove that the correct event channel was configured or that events were reaching Splunk.

## 2. Review the Universal Forwarder log

The first attempt failed because a PowerShell command was entered in the Ubuntu shell. The command was rerun in Windows PowerShell:

```powershell
Select-String -Path "C:\Program Files\SplunkUniversalForwarder\var\log\splunk\splunkd.log" `
    -Pattern "Sysmon|WinEventLog|ERROR|WARN" |
    Select-Object -Last 50
```

Relevant messages included connection timeouts, resets and a paused output queue. This moved the investigation from basic service status to the forwarding data path.

## 3. Verify the receiver

On the Ubuntu Splunk server:

```bash
sudo ss -lntp | grep 9997
```

The output showed `splunkd` listening on `0.0.0.0:9997`, confirming that the receiving port was active.

## 4. Create a dedicated Sysmon input

The following file was created:

```text
C:\Program Files\SplunkUniversalForwarder\etc\apps\soc_lab_sysmon\local\inputs.conf
```

```ini
[WinEventLog://Microsoft-Windows-Sysmon/Operational]
disabled = 0
```

A dedicated app keeps the configuration isolated and easier to validate or document than editing default files.

## 5. Validate Splunk's effective configuration

```powershell
& "C:\Program Files\SplunkUniversalForwarder\bin\splunk.exe" btool inputs list --debug
```

`btool` shows Splunk's merged effective configuration and the source file for every setting. It helps identify disabled, overridden or misplaced stanzas.

## 6. Restart and validate

```powershell
Restart-Service SplunkForwarder
Get-Service SplunkForwarder, Sysmon64
```

Validation searches:

```spl
index=* host="Home-PC011"
| stats count BY source sourcetype
```

```spl
index=* sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" earliest=-30m
```

Sysmon events then appeared in Splunk, confirming that the end-to-end collection path was operational.

## Root-cause statement

The evidence did not support a stopped Sysmon or Universal Forwarder service. The fault was within the data path and effective input configuration: the forwarder had reported connectivity problems, and the Sysmon Operational channel needed to be explicitly enabled and verified. Confirming the receiver, validating the input with `btool` and restarting the forwarder restored collection.

## Lessons learned

1. A running service does not prove successful data ingestion.
2. Troubleshooting should follow the complete path: event source, input, forwarder, network, receiver, index and search.
3. Forwarder logs provide stronger evidence than assumptions based on the user interface.
4. `btool` is essential when Splunk configuration may be overridden across multiple files.
5. A high event count or suspicious keyword is an investigation lead, not proof of compromise.
6. Parent process, command line, file path, signature, user and time provide the context needed for triage.

