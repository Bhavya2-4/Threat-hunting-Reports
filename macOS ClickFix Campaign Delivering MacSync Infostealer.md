Threat Hunt Report | macOS ClickFix Campaign Delivering MacSync Infostealer

1. Introduction
   
This report documents a proactive threat hunt conducted to assess potential exposure to a macOS-focused infostealer campaign leveraging ClickFix-style social engineering. The campaign delivers the MacSync infostealer, a Malware-as-a-Service (MaaS) variant designed to steal credentials, cryptocurrency assets, and sensitive files while optionally establishing long-term persistence.

2. Executive Summary (Non-Technical)
   
A phishing campaign was identified that deceives macOS users into manually executing Terminal commands disguised as legitimate software installation steps. This action bypasses native macOS security controls and results in malware execution. The malware is capable of stealing passwords, browser data, cryptocurrency wallets, and modifying trusted applications to maintain persistence.
No confirmed malicious activity was observed within the monitored customer environment during this hunt.

3. Threat Hypothesis (Including Attack Vectors)
   
Hypothesis:

A threat actor may leverage phishing domains and ClickFix-style lures to convince macOS users to execute malicious Terminal commands, leading to deployment of the MacSync infostealer and potential long-term credential theft.
Attack Vectors:
•	Phishing domains impersonating Microsoft or macOS services
•	User-assisted execution (copy - paste into Terminal)
•	Script-based execution chain (curl - zsh - osascript)
•	Abuse of trusted Electron-based cryptocurrency applications




4. Attack Chain (Step-by-Step Flow)
   
Step 1 – Initial Access (Phishing / Redirect)
Victim visits a phishing domain (e.g., Microsoft-themed login lure) or is redirected through compromised infrastructure to a fake macOS download page.

Step 2 – Social Engineering (ClickFix Lure)
The landing page mimics a legitimate macOS cloud storage installer and instructs the user to paste a Terminal command to “complete installation.”

Step 3 – User Execution (Terminal Command)
The pasted one-liner uses curl to fetch remote content and pipes it directly into zsh, bypassing Gatekeeper, notarization, and signature checks.

Step 4 – Stage-1 Loader (Zsh Stager)
The downloaded Zsh script daemonizes itself, suppresses output, and establishes communication with attacker infrastructure.

Step 5 – Stage-2 Payload (AppleScript Execution)
The stager retrieves a remote AppleScript payload and executes it in-memory using osascript, avoiding disk-based detection.

Step 6 – Credential Phishing (macOS Password)
The AppleScript repeatedly displays fake system dialogs until the user enters their macOS login password.

Step 7 – Data Collection
The malware harvests:
•	Browser credentials and cookies
•	Cryptocurrency wallet extensions and desktop wallets
•	Keychain databases
•	SSH, cloud, and messaging session data
•	Sensitive user files (size-limited)

Step 8 – Data Exfiltration
Collected data is compressed into /tmp/osalogging.zip and exfiltrated via HTTP POST to rotating C2 domains.

Step 9 – Persistence (Conditional)
If detected, trusted Electron-based crypto wallet applications are trojanized to enable delayed phishing and long-term access.

5. Methodology (Hunt Approach & Data Sources)

Hunt Approach:
•	Intelligence-led hypothesis testing
•	Behavior-based validation over IOC-only matching
•	Cross-correlation of endpoint and network telemetry
Data Sources Reviewed:
•	endpoint logs 
•	Process execution telemetry
•	Network / firewall DNS and HTTP logs

6. Indicators of Compromise (IOCs) Reviewed

Phishing / Lure Domains
macclouddrive[.]com

maccloudvault[.]com

maccloudsafe[.]com

macfiledrive[.]com

macfilevault[.]com

macfilebackup[.]com

Command-and-Control Domains

•	jmpbowl[.]xyz

•	jmpbowl[.]today

•	jmpbowl[.]space

•	jmpbowl[.]top

•	jmpbowl[.]world

•	jmpbowl[.]shop

•	jmpbowl[.]fun

•	jmpbowl[.]coupons


File Hashes (SHA-256)

app.asar:

ec6bc84be18ce4cb55fb915370c00f2a836ffefc65c6b728efb8d2d28036e376

Info.plist:

c99dea85f0ef8d3e2f3771c8ebd02d7dee0d90efc5c8392e5c266a59640a4206



7. Detections / Queries (Relayed to SecOps / Detection Engineering Team)
   
A. Endpoint Detection – 

Suspicious Terminal-Based Execution Chain

process.name:(curl or zsh or osascript) and
process.command_line:( "*curl*" and "*zsh*" or "*http*" or "*https*"  )
Suspicious Temp Artifact Creation
event.category:file and
file.path:"/tmp/osalogging.zip"
Electron App Tampering (app.asar modification)
file.path:"*/Applications/*/Contents/Resources/app.asar"





B. Firewall / Network Detection – Elastic Network Logs

Outbound Communication to Known C2 Domains

event.category:network and
dns.question.name:(
  "jmpbowl.xyz" or "jmpbowl.today" or "jmpbowl.space" or
  "jmpbowl.top" or "jmpbowl.world" or "jmpbowl.shop" or
  "jmpbowl.fun" or "jmpbowl.coupons"
)
Suspicious HTTP POST Exfiltration
http.request.method:"POST" and
url.path:"/gate"
Base64 Encoded Payload Delivery
event.category:network and
http.request.body: (should include Bsae64) 

8. Impact Assessment
    
Potential Impact if Exploited:
•	Complete credential and wallet compromise
•	Financial theft via cryptocurrency wallet recovery
•	Long-term persistence through trusted applications
•	Delayed detection due to user-driven execution
Risk Level: High (Credential & Financial Impact)






