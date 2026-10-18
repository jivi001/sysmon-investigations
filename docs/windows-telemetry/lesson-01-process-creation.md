# Windows Telemetry Lab — Process Creation and Process Identity

**Date:** 2026-10-18\
**Repository:** `sysmon-investigations`\
**Status:** In progress\
**Environment:** Windows 11 VM, VMware, Sysmon\
**Focus:** Windows Event Logs, Sysmon Event ID 1, parent-child relationships, PID reuse, and evidence validation.

## 1. Objectives

- Understand the difference between Windows Security logs and Sysmon telemetry.
- Verify that the Sysmon Operational channel is enabled and contains events.
- Interpret Sysmon Event ID 1 process-creation records.
- Understand `ProcessId`, `ProcessGuid`, `ParentProcessId`, and `ParentProcessGuid`.
- Investigate process ancestry without assuming that suspicious activity is malicious.
- Validate query logic before drawing conclusions from event data.

## 2. Initial Telemetry Verification

### Sysmon channel

The following PowerShell command was executed:

```powershell
Get-WinEvent -ListLog "Microsoft-Windows-Sysmon/Operational" |
    Select-Object LogName, IsEnabled, RecordCount
```

Observed result:

| Property    | Value                                |
| ----------- | ------------------------------------ |
| LogName     | Microsoft-Windows-Sysmon/Operational |
| IsEnabled   | True                                 |
| RecordCount | 504                                  |

### Interpretation

The Sysmon Operational channel exists, is enabled, and reports 504 records.

This establishes that the event channel is available and contains records. It does not prove that every relevant event type is configured, that telemetry is complete, or that events are being forwarded successfully to a SIEM.

## 3. Sysmon Event ID 1 — Process Creation

I queried the Sysmon Operational channel for Event ID 1 records.

The query returned process-creation events for Windows components including:

- `SoftLandingTask.exe`
- `taskhostw.exe`
- `svchost.exe`
- `WindowsPackageManagerServer.exe`
- `RuntimeBroker.exe`

A separate query for `notepad.exe` also returned a matching process-creation record according to my lab observation.

### Important fields

| Field               | Purpose                                                      |
| ------------------- | ------------------------------------------------------------ |
| `UtcTime`           | Event-associated UTC timestamp                               |
| `ProcessGuid`       | Identifier used to correlate the process in Sysmon telemetry |
| `ProcessId`         | Windows process ID                                           |
| `Image`             | Executable image path                                        |
| `CommandLine`       | Recorded command line                                        |
| `User`              | Security context associated with the process                 |
| `IntegrityLevel`    | Process integrity level                                      |
| `Hashes`            | File hash information, when recorded                         |
| `ParentProcessGuid` | Parent process identity recorded by Sysmon                   |
| `ParentProcessId`   | Parent process ID                                            |
| `ParentImage`       | Parent executable image                                      |
| `ParentCommandLine` | Recorded parent command line                                 |

### Key learning

A process is a running instance of a program. The executable file on disk is not the same thing as the running process.

A parent-child relationship helps reconstruct process execution, but it does not by itself prove what caused the process to run or whether the process is malicious.

## 4. PID Versus ProcessGuid

A PID can be reused after a process exits. Therefore, matching PIDs across different events do not necessarily identify the same process instance.

`ProcessGuid` provides a stronger correlation key for process identities within Sysmon telemetry.

When investigating process ancestry, compare:

- The child's `ParentProcessGuid`
- The corresponding parent's `ProcessGuid`
- The parent and child PIDs
- Timestamps and process paths
- Command lines and user contexts

A process tree is evidence of recorded execution relationships. Connecting that tree to a website visit, login, or document requires additional corroborating telemetry.

## 5. Investigation Case — Parent Process Correlation

### Observation

Two initial Event ID 1 records reported parent PID `952`, but different parent process GUIDs and command lines.

One record involved `SoftLandingTask.exe`; another involved `taskhostw.exe`.

The records were close in time, so the discrepancy required validation rather than an immediate conclusion of compromise.

### Investigation hypothesis

The records might refer to different parent process instances, or the discrepancy might have another explanation in the source records or the query used to retrieve them.

### Query-validation mistake

An early query searched formatted event messages using a substring pattern intended to match `ProcessGuid`.

However, `ParentProcessGuid` contains the substring `ProcessGuid`. As a result, the query could match a child event's parent field rather than the event's own process identity.

**Lesson:** A query returning results does not prove that it retrieved the intended records.

### Improved approach

Read the original event XML and extract named fields from `EventData`. Compare the value of the `ProcessGuid` field directly with the target GUIDs.

Do not search the entire formatted message when the investigation depends on distinguishing fields with similar names.

### Current status

**Unresolved.** The subsequent output contained child events that referenced target GUIDs in their `ParentProcessGuid` fields. The output did not establish that the corresponding parent process-creation records had been found.

The original parent identities still need to be verified using exact structured-field matching and the available event-retention window.

No conclusion of malicious activity has been established.

## 6. SOC Investigation Principles Learned

1. **Telemetry presence is not telemetry completeness.** An enabled event channel does not guarantee that every relevant event is collected.
2. **Evidence is not a verdict.** A suspicious process or command line requires contextual investigation.
3. **Process ancestry matters.** Parent-child relationships can reveal expected execution or suspicious chains.
4. **Validate query semantics.** Confirm that a filter matches the intended field, not merely similar text.
5. **Correlate multiple sources.** Connecting process activity to a login, website, or document requires additional evidence.
6. **Record uncertainty.** Separate observed facts, hypotheses, and conclusions.
7. **Protect evidence.** Redact usernames, host-specific identifiers, and unnecessary raw telemetry before publishing.

## 7. Next Steps

- Verify the two target parent GUIDs against the `ProcessGuid` field in original Sysmon Event ID 1 records.
- Compare parent and child identities, PIDs, timestamps, and command lines.
- Investigate the `hpatchmonTask.cmd` execution and determine whether it corresponds to expected scheduled activity.
- Record the outcome, including limitations and alternative explanations.
- Verify whether Windows Security Event ID 4688 is generated under the current process-creation audit policy.
- Later, verify that configured Windows telemetry reaches Wazuh.

## 8. References

- Microsoft Learn — [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
- Microsoft Learn — [Get-WinEvent](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.diagnostics/get-winevent)
- Microsoft Learn — [Windows Security auditing](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/basic-audit-process-creation)
