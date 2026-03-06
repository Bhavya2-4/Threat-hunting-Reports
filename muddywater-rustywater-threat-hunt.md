## Reborn in Rust – Muddy Water APT “RustyWater” Implant

**Threat Actor:** Muddy Water APT  
**Also Known As:** Earth Vetala, MERCURY, Static Kitten, Mango Sandstorm  
**Report Date:** January 2026  

**Threat Type:** Targeted Spear-Phishing → Multi-Stage Malware → Persistent RAT  
**Threat Maturity:** Advanced (Modular, Low-Noise, Persistent)

---

# 1. Executive Summary

A targeted spear-phishing campaign attributed with high confidence to the **Muddy Water APT group** was identified targeting diplomatic, maritime, financial, telecom, and government-aligned organizations across the Middle East.

The campaign uses **icon spoofing and malicious Microsoft Word documents** to deliver a Rust-based implant referred to here as **RustyWater**. This represents an evolution from Muddy Water’s earlier PowerShell and VBS tooling toward a more modular and stealth-focused Remote Access Trojan (RAT).

Observed attacker tradecraft includes:

- Registry-based persistence
- Layered command-and-control encryption
- Anti-analysis and AV/EDR detection checks
- Asynchronous multi-threaded execution
- Modular post-compromise capability expansion

---

# 2. Threat Context & Attribution

Muddy Water historically relied heavily on **script-based loaders** for initial access. The emergence of **Rust-compiled implants** marks a clear tooling evolution toward reduced detection and greater operational reliability.

Similar samples have previously been referenced as **Archer RAT** or **RUSTRIC**, but for clarity this report refers to the implant as **RustyWater**.

**Attribution Confidence:** High

Supporting indicators include:

- Reuse of known Muddy Water VBA macro patterns
- Similar phishing lures and delivery methods
- Infrastructure and targeting overlap
- Consistency with previously documented Muddy Water TTPs

---

# 3. Kill Chain Overview

## Initial Access

- **Vector:** Spear-phishing email
- **Lure theme:** “Cybersecurity Guidelines”
- **Sender:** Spoofed telecom or government email domains
- **Attachment:** `Cybersecurity.doc`

---

# 4. Technical Analysis

## Stage 1 – Malicious Document (Cybersecurity.doc)

Observed behavior:

- Document contains **VBA macros**
- Macro extracts a **hex-encoded PE payload** embedded inside a `UserForm`
- Payload decoded and written to disk as:

```
C:\ProgramData\CertificationKit.ini
```

The macro dynamically reconstructs `WScript.Shell` and executes the dropped file via:

```
cmd.exe
```

---

## Stage 2 – Rust Implant (CertificationKit.ini / reddit.exe)

The payload masquerades as a benign executable using a **Cloudflare icon**.

The binary is compiled in **Rust**, consistent with known RustyWater samples.

### Key Capabilities

- Anti-debugging using **Vectored Exception Handlers (VEH)**
- Detection checks for **25+ AV/EDR products**
- Encrypted strings (XOR-based, position-independent)
- System profiling including:
  - Username
  - Hostname
  - Domain membership

---

## Persistence Mechanism

Registry autostart entry:

```
HKCU\Software\Microsoft\Windows\CurrentVersion\Run
```

Executable stored in:

```
C:\ProgramData\
```

---

## Command & Control (C2)

The implant uses the **Rust reqwest HTTP library**.

Communication pipeline:

```
JSON → Base64 → XOR
```

Additional behaviors:

- Asynchronous communication via **tokio**
- Randomized sleep intervals (jitter)
- Retry logic and connection pooling for resiliency

---

## Process Injection

The malware injects into:

```
explorer.exe
```

Using the following Windows APIs:

```
VirtualAllocEx
WriteProcessMemory
Thread context manipulation
```

This enables **in-memory execution** and stealth tasking.

---

# 5. Campaign Expansion & Pivoting

Further investigation identified:

- Credential leakage enabling impersonation of **government and telecom email accounts**
- Additional phishing campaigns targeting:
  - UAE financial institutions
  - Educational organizations
  - Maritime sector entities

The lure documents and delivery techniques remained consistent across multiple regions.

---

# 6. Impact Assessment

## Security Impact

- Long-term silent persistence
- Minimal disk artifacts due to memory-centric execution
- Reduced effectiveness of static IOC detection
- Increased difficulty in incident timeline reconstruction

---

## Business Impact

- Intelligence collection against targeted sectors
- Credential theft and lateral movement
- Surveillance against diplomatic, telecom, and maritime entities
- Increased data exposure risk through long-term persistence

---

# 7. Attack Vector

**Primary Vector:** Spear-phishing email  

**Lure Theme:** Cybersecurity / government compliance guidance  

**Delivery Mechanism:** Malicious Word document containing VBA macros  

**Trust Abuse:** Icon spoofing and legitimate-looking sender domains

---

# Attack Chain Flow

1. **Spear-Phishing Email**
   - Impersonates telecom or government entities
   - Contains malicious attachment `Cybersecurity.doc`

2. **User Execution**
   - Document opened
   - Macros enabled

3. **Stage-1 Loader (VBA Macro)**

```
C:\ProgramData\CertificationKit.ini
```

Payload dropped and executed via:

```
cmd.exe
```

4. **Stage-2 Rust Implant**

Capabilities include:

- Anti-debugging
- AV/EDR enumeration
- XOR string encryption

5. **Persistence**

```
HKCU\Software\Microsoft\Windows\CurrentVersion\Run
```

6. **Defense Evasion**

- In-memory execution
- Injection into `explorer.exe`
- Randomized sleep intervals

7. **Command & Control**

HTTP communication via **reqwest**

```
JSON → Base64 → XOR
```

8. **Post-Compromise Activity**

- Modular task execution
- On-demand capability expansion
- Long-term persistence

---

# 8. Detection Logic – Elastic SIEM

## Endpoint Detection

### Macro Dropping Executable to ProgramData

```
event.category:process and
process.parent.name:("WINWORD.EXE") and
process.command_line:(*"ProgramData"* and ("*.ini" or "*.exe"))
```

---

### WScript / cmd Execution from Office

```
event.category:process and
process.parent.name:("WINWORD.EXE") and
process.name:("wscript.exe","cmd.exe")
```

---

### Registry Persistence

```
event.category:registry and
registry.path:"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run*" and
registry.data.strings:*ProgramData*
```

---

### Process Injection Indicators

```
event.category:process and
process.name:"explorer.exe" and
process.thread.capabilities:("VirtualAllocEx","WriteProcessMemory")
```

---

### Suspicious Rust HTTP User Agent

```
event.category:network and
http.request.headers.user_agent:("reqwest/*")
```

---

# Network Detection

### Low-and-Slow HTTP Beaconing

```
event.category:network and
network.protocol:http and
network.direction:outbound
```

---

### Repeated HTTP Retry Pattern

```
event.category:network and
network.protocol:http and
event.outcome:failure
```

---

### JSON POST with Encoded Payload

```
event.category:network and
http.request.method:"POST" and
http.request.headers.content_type:"application/json"
```

---

# Ready-to-Use Detection Query

```
(event.category : "process" and process.parent.name : ("WINWORD.EXE" or "EXCEL.EXE") and process.name: ("cmd.exe" or "wscript.exe" or "powershell.exe"))
AND (process.executable : ("C:\\ProgramData\\*" or "C:\\Users\\*\\AppData\\*"))
AND (process.command_line.text : "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run*")
AND (event.category : "network" and network.direction : "outbound" and network.protocol : "http")
```

---

# 9. Indicators of Compromise (IOCs)

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

# 10. MITRE ATT&CK Mapping

| Tactic | Technique | Description |
|------|------|------|
| Initial Access | T1566.001 | Spearphishing Attachment |
| Initial Access | T1204.002 | User Execution |
| Execution | T1059.005 | VBA Macros |
| Execution | T1106 | Native API |
| Execution | T1620 | Reflective Code Loading |
| Defense Evasion | T1055 | Process Injection |
| Persistence | T1547.001 | Registry Run Keys |

---




