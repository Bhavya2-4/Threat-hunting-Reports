# Threat Hunt Report  
## Lotus Blossom – Notepad++ Update Chain → Chrysalis Backdoor Deployment

**Threat Actor:** Lotus Blossom (Clustered Activity – AV Icon Spoofing Operations)  
**Also Known For:** Software Update Path Abuse, DLL Sideloading Operations  
**Report Date:** January 2026  

**Threat Type:** Trusted Software Update Hijack → Multi-Stage Loader → In-Memory Backdoor  
**Threat Maturity:** Advanced (Low-Noise, Memory-Resident, Service-Based Persistence)

---

# 1. Executive Summary

A multi-stage intrusion chain attributed to activity clusters aligned with the **Lotus Blossom campaign** was analyzed during this threat hunt. The campaign leverages a compromised **Notepad++ update mechanism** to deliver a trojanized installer that deploys a **memory-resident backdoor known as Chrysalis**.

The attack demonstrates disciplined adversary tradecraft including:

- Trusted software update abuse
- DLL sideloading via legitimate binaries
- Encrypted shellcode execution in memory
- API hashing and dynamic resolution
- Service-based persistence with fallback registry mechanisms
- HTTPS command-and-control over port 443
- Modular post-exploitation tooling


---

# 2. Threat Context & Attribution

The campaign reflects operational characteristics consistent with previously observed **Lotus Blossom activity clusters**, particularly those involving:

- AV icon spoofing
- Trusted binary abuse
- Service-based persistence
- Encrypted memory payloads

**Attribution Confidence:** Medium to High  

Confidence based on:

- Infrastructure overlap
- TTP similarity
- Tooling structure consistency
- Delivery pattern alignment

---

# 3. Kill Chain Overview

## Initial Access

- Vector: Compromised **Notepad++ update process**
- Trusted component abused: `gup.exe` (Notepad++ updater)
- Malicious delivery: `update.exe` (trojanized installer)

---

## Execution

- `update.exe` (NSIS installer) executed
- Files dropped to:

```
%AppData%\Bluetooth\
```

- Folder set to **Hidden**

---

## Defense Evasion

- DLL sideloading via `BluetoothService.exe`
- Encrypted shellcode execution in memory
- API hashing
- Fileless execution

---

## Persistence

Primary persistence:

- Windows Service creation

Fallback persistence:

```
HKCU\Software\Microsoft\Windows\CurrentVersion\Run
```

---

## Command and Control

- HTTPS communication over port **443**
- WinInet communication
- Chrome-like user-agent spoofing
- RC4-encrypted network traffic

---

# 4. Technical Analysis

## Stage 1 – Compromised Update Path

Attack flow:

1. Victim launches `notepad++.exe`
2. `gup.exe` executes (legitimate updater)
3. `update.exe` retrieved from attacker infrastructure
4. `update.exe` is a **trojanized NSIS installer**

Purpose: covert malware delivery through trusted update infrastructure.

---

## Stage 2 – File Deployment

Files dropped to:

```
%AppData%\Bluetooth\
```

Files created:

```
BluetoothService.exe
log.dll
BluetoothService
```

Descriptions:

- `BluetoothService.exe` → renamed legitimate binary
- `log.dll` → malicious sideloaded DLL
- `BluetoothService` → encrypted shellcode blob

The directory is set to **Hidden**.

---

## Stage 3 – DLL Sideloading & Shellcode Execution

Because `log.dll` resides beside `BluetoothService.exe`, Windows loads the **attacker-controlled DLL**.

Exported functions:

### LogInit
Loads encrypted shellcode.

### LogWrite
- Decrypts shellcode (LCG + XOR stream cipher)
- Allocates executable memory
- Transfers execution to RAM

No final payload written to disk.

Techniques used:

- DLL sideloading
- Encrypted shellcode
- API hashing
- Reflective execution

---

## Stage 4 – Chrysalis Backdoor

Shellcode decrypts and loads **Chrysalis backdoor** directly in memory.

Capabilities include:

- Dynamic API resolution
- String obfuscation
- Reflective PE loading
- WinInet HTTPS communication
- Full remote operator control

---

## Stage 5 – Persistence Mechanism

Primary persistence:

```
CreateService()
StartService()
```

Service stored under:

```
HKLM\SYSTEM\CurrentControlSet\Services\
```

Execution flags:

```
none → install persistence
-i → launcher mode
-k → execution mode
```

Fallback persistence:

```
HKCU\Software\Microsoft\Windows\CurrentVersion\Run
Value: BluetoothService
Data: malware.exe -i
```

Mutex observed:

```
Global\Jdhfv_1.0.1
```

Purpose: prevent multiple execution instances.

---

## Stage 6 – Command & Control

Communication channel:

- WinInet HTTPS POST
- Port 443
- RC4 encrypted traffic

Observed infrastructure:

```
api.skycloudcenter.com
api.wiresguard.com
95.179.213.0
61.4.102.97
```

Traffic characteristics:

- Small encrypted packets
- Periodic beaconing
- Chrome-like user-agent

---

## Stage 7 – Post-Exploitation Activity

Operator capabilities include:

- Reverse shell execution (`cmd.exe`)
- Process creation
- File read/write
- Drive enumeration
- File upload and download
- Self removal

Additional tools observed:

- Tiny C Compiler
- Metasploit shellcode
- Cobalt Strike beacon

---

## Stage 8 – Cleanup

Upon uninstall:

- Dropped files removed
- Service deleted
- Registry keys removed
- Self-deletion executed via:

```
u.bat
```

---

# 5. Impact Assessment

## Security Impact

- Stealth persistence capability
- Memory-resident payload reduces forensic artifacts
- Difficult IOC-only detection
- Service-level system control

---

## Business Impact

- Long-term espionage risk
- Potential data exfiltration
- Lateral movement potential
- Operational compromise

**Risk Level:** High

---

# 6. Detection Logic – KQL

## Endpoint Detection

### Malicious Updater Execution

```
DeviceProcessEvents
| where InitiatingProcessFileName =~ "gup.exe"
| where FileName !in~ ("notepad++.exe")
```

---

### DLL Sideloading Detection

```
DeviceImageLoadEvents
| where InitiatingProcessFileName in~ ("BluetoothService.exe")
| where FileName =~ "log.dll"
```

---

### Service Creation Monitoring

```
DeviceProcessEvents
| where ProcessCommandLine has "sc.exe"
| where ProcessCommandLine has_any ("create","binPath")
```

---

### Registry Persistence Detection

```
DeviceRegistryEvents
| where RegistryKey has @"\Software\Microsoft\Windows\CurrentVersion\Run"
```

---

## Network Detection

### Outbound HTTPS from Non-Browser Process

```
event.category:network and
process.name != ("chrome.exe","msedge.exe") and
network.direction:outbound and
destination.port:443
```

---

### Infrastructure Hunt

```
event.category:network and
destination.ip:(
"95.179.213.0",
"61.4.102.97",
"159.198.68.25",
"161.35.228.250",
"159.198.66.153"
)
```

---

### Suspicious POST Traffic

```
event.category:network and
http.request.method:"POST" and
process.name != ("chrome.exe","msedge.exe")
```

---

# 7. Indicators of Compromise (IOCs)

## File Hashes (SHA-256)

```
76aad2a7fa265778520398411324522c57bfd7d2ff30a5cfe6460960491bc552
f38a56b8dc0e8a581999621eef65ef497f0ac0d35e953bd94335926f00e9464f
7523e53c979692f9eecff6ec760ac3df5b47f172114286e570b6bba3b2133f58
e61b2ed360052a256b3c8761f09d185dad15c67595599da3e587c2c553e83108
```

---

## Network Indicators

```
159.198.68.25
161.35.228.250
159.198.66.153
```

---

# 8. MITRE ATT&CK Mapping

| Tactic | Technique | ID |
|------|------|------|
| Initial Access | Supply Chain Compromise | T1195 |
| Execution | Command Interpreter | T1059 |
| Defense Evasion | DLL Sideloading | T1574.002 |
| Defense Evasion | Reflective Loading | T1620 |
| Persistence | Windows Service | T1543 |
| Persistence | Registry Run Key | T1547.001 |
| Command & Control | HTTPS | T1071.001 |

---

# 9. Hunt Results

No suspicious activity or IOC matches were identified across monitored endpoints or network telemetry during the defined hunting window.

No evidence of:

- Malicious service creation
- DLL sideloading artifacts
- Known infrastructure communication
- Registry persistence mechanisms

---

# 10. Final Assessment

This campaign demonstrates **mature adversary tradecraft** centered around:

- Trusted software update abuse
- Encrypted in-memory execution
- Stealth persistence mechanisms

Detection requires emphasis on:

- Behavioral telemetry correlation
- Memory execution monitoring
- Service creation tracking
- HTTPS process profiling

**Risk Level:** High  
**Confidence in Assessment:** High

