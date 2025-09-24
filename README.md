# Cyber-Security--Elevate-Labs-

Phishing Email Analysis – Task 2
This project documents a **phishing email investigation** performed on **Kali Linux**.

Overview :
A synthetic phishing email (`phishing_sample.eml`) was analyzed to detect spoofing, suspicious links, and missing authentication records using only Kali tools.

Tools :
`grep` • `dig` • `whois` • `curl` • **Ripmime** • **ClamAV** • VirusTotal (for safe URL scans)

Key Findings :
- Spoofed domain:** `support@paypa1-security.com` (number “1” instead of “l”)  
- No SPF/DKIM/DMARC** → sender not authenticated  
- Urgent language & generic greeting** (social engineering)  
- Malicious URL:** `secure-paypa1.com` (newly registered, privacy-protected)

Report :
This exercise shows how free tools in Kali Linux can uncover phishing indicators without commercial software.
