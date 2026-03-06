# LockBit 5.0 Ransomware Behavioral Activity Analysis

---

# Overview

LockBit 5.0 ransomware demonstrates advanced **cross-platform capabilities and anti-forensic techniques** designed to evade detection and hinder system recovery.

Recent behavioral analysis identified the use of a distinctive **16-character hexadecimal file extension** applied during file encryption. In addition, the ransomware drops a ransom note named:

```
ReadMeForDecrypt.txt
```

Pre-encryption activity includes:

- Event log clearing
- Microsoft Defender service termination
- Shadow copy deletion
- System recovery configuration modification

The threat actors make extensive use of **Living-off-the-Land Binaries (LOLBins)** such as:

```
cmd.exe
net.exe
wmic.exe
vssadmin.exe
bcdedit
```

These behaviors match patterns observed in **LockBit affiliate intrusions across enterprise environments**.

---

# Tools and Techniques Observed

| Tool / Technique | Description |
|------------------|-------------|
| Random Hexadecimal File Extension | LockBit encrypts files using a distinctive 16-character hexadecimal extension |
| Ransom Note Deployment | Drops `ReadMeForDecrypt.txt` across affected systems |
| Event Log Clearing | Removes forensic evidence using commands such as `EvtClearLog` |
| Security Service Termination | Uses `net.exe` to stop security services |
| LOLBins Abuse | System tools used to bypass detection |
| Shadow Copy Deletion | Removes system restore points |
| Defender Exclusion Modification | Adds directories to Defender exclusions |
| Staged Payloads | Uses disguised or renamed binaries prior to ransomware execution |

---

# Indicators of Compromise (IOCs)

## File Indicators

- File extensions matching **16-character hexadecimal patterns**
- Ransom note file:

```
ReadMeForDecrypt.txt
```

---

## Behavioral Indicators

| Behavior | Example Commands |
|--------|----------------|
| Event log clearing | `EvtClearLog`, `clear-eventlog` |
| Defender tampering | `Add-MpPreference -ExclusionPath` |
| Shadow copy removal | `vssadmin Delete Shadows /All /Quiet` |
| Shadow copy removal | `wmic SHADOWCOPY /nointeractive` |
| System recovery modification | `bcdedit recoveryenabled No` |
| Service termination | `net.exe stop defender`, `net.exe stop wdfilter`, `net.exe stop sense` |

---

# Process Lineage Examples

Example ransomware execution chain:

```
explorer.exe
 └ encryptor.exe
      └ cmd.exe
           └ vssadmin Delete Shadows /All /Quiet
```

Service-based execution chain:

```
services.exe
 └ svchost.exe
      └ encryptor.exe
```

---



# Detection Query (KQL)

## LockBit 5.0 Behavioral Detection

```kql
// LockBit 5.0 behavioural hunt (ransom note + 16-char extension + evasion)

let RansomNote = "ReadMeForDecrypt.txt";
let LockBitBinaryNames = pack_array("LockBit5.0.exe", "lockbit.exe", "encryptor.exe", "a.out");

// Stage 1 – suspicious file activity
let FileActivity =
DeviceFileEvents
| where Timestamp > ago(7d)
| where ActionType in ("FileRenamed","FileCreated")
| where InitiatingProcessFileName has_any (LockBitBinaryNames)
   or FileName == RansomNote
   or FileName matches regex @"\.[a-fA-F0-9]{16}$"
| extend
    RansomNoteDetected = iff(FileName == RansomNote, "Yes", "No"),
    RandomExtensionDetected = iff(FileName matches regex @"\.[a-fA-F0-9]{16}$", "Yes", "No")
| project
    Timestamp,
    DeviceId,
    DeviceName,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    ActionType,
    FileName,
    RansomNoteDetected,
    RandomExtensionDetected;

// Stage 2 – log clearing / security service stop
let DefenseEvasion =
DeviceProcessEvents
| where Timestamp > ago(7d)
| where ActionType == "ProcessCreated"
| where ProcessCommandLine has_any ("EvtClearLog","clear-eventlog","clear-log")
   or (FileName =~ "net.exe" and ProcessCommandLine has "stop"
       and ProcessCommandLine has_any ("security","defender","wdfilter","sense"))
| extend EvasionActivity = iff(ProcessCommandLine has "clear", "Log_Clearing_Attempt", "Service_Termination_Attempt")
| project
    DeviceId,
    EvasionTime = Timestamp,
    EvasionActivity,
    EvasionCommand = ProcessCommandLine;

// Correlation logic
FileActivity
| join kind=leftouter DefenseEvasion on DeviceId
| extend DetectionReason = strcat(
        iff(RansomNoteDetected == "Yes", "RansomNoteDrop; ", ""),
        iff(RandomExtensionDetected == "Yes", "RandomExtension; ", ""),
        tostring(EvasionActivity)
    )
| where DetectionReason != ""
| project
    Time = Timestamp,
    DeviceName,
    DetectionReason,
    RansomNoteDetected,
    RandomExtensionDetected,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    EvasionTime,
    EvasionCommand
| sort by Time desc
```

---

# Recommended Defensive Actions

Security teams should implement the following monitoring controls:

1. Detect files with **16-character hexadecimal extensions**.
2. Monitor creation of ransom note `ReadMeForDecrypt.txt`.
3. Alert on **event log clearing activity**.
4. Detect termination of security services.
5. Monitor Defender exclusion changes via PowerShell.
6. Detect **shadow copy deletion commands**.
7. Alert on LOLBins abuse including:

```
cmd.exe
wmic.exe
vssadmin.exe
bcdedit
net.exe
```

---

# Conclusion

LockBit 5.0 continues to rely on **behavior-based stealth techniques and LOLBins abuse** to evade detection.

Early detection should focus on:

- Pre-encryption activity
- Security control tampering
- Shadow copy deletion
- Ransom note creation

Behavioral detection strategies provide stronger resilience compared to static IOC matching.

---
