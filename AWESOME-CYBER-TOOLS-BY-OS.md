# Awesome Cyber Security Tools by Operating System

Last updated: 2026-02-12

Selection method:
- Searched GitHub with `gh search repos` across cybersecurity, pentest, DFIR, network-security, and OS-specific queries.
- Normalized tool metadata with `gh repo view` (stars + latest update timestamps).
- Cross-checked with official tool/vendor docs and security ecosystems (multiple domains).

## Cross-Platform (Linux, Windows, macOS)

| Tool | Primary Use | GitHub Signal (2026-02-12) | Links |
|---|---|---:|---|
| Nmap | Network discovery and security auditing | 12,390 stars | [GitHub](https://github.com/nmap/nmap) • [Official](https://nmap.org/download) |
| Wireshark | Packet capture and protocol analysis | 8,999 stars | [GitHub](https://github.com/wireshark/wireshark) • [Official](https://www.wireshark.org/download.html) |
| Metasploit Framework | Exploit development and validation | 37,502 stars | [GitHub](https://github.com/rapid7/metasploit-framework) • [Docs](https://docs.rapid7.com/metasploit/) |
| OWASP ZAP | Web app DAST/proxy scanning | 14,742 stars | [GitHub](https://github.com/zaproxy/zaproxy) • [Official](https://www.zaproxy.org/) |
| Nuclei | Template-driven vulnerability scanning | 26,988 stars | [GitHub](https://github.com/projectdiscovery/nuclei) |
| SQLMap | SQL injection detection/testing | 36,583 stars | [GitHub](https://github.com/sqlmapproject/sqlmap) |
| mitmproxy | Interactive HTTP(S) interception/proxying | 42,268 stars | [GitHub](https://github.com/mitmproxy/mitmproxy) |
| Hashcat | GPU password recovery/auditing | 25,414 stars | [GitHub](https://github.com/hashcat/hashcat) |
| John the Ripper | Offline password cracking/auditing | 12,711 stars | [GitHub](https://github.com/openwall/john) |
| YARA | Malware pattern matching/rules | 9,407 stars | [GitHub](https://github.com/VirusTotal/yara) |
| osquery | Endpoint telemetry with SQL | 23,099 stars | [GitHub](https://github.com/osquery/osquery) |
| Velociraptor | Endpoint DFIR and threat hunting | 3,757 stars | [GitHub](https://github.com/Velocidex/velociraptor) |
| Autopsy | GUI digital forensics platform | 3,003 stars | [GitHub](https://github.com/sleuthkit/autopsy) |
| The Sleuth Kit | CLI forensic toolkit and library | 2,982 stars | [GitHub](https://github.com/sleuthkit/sleuthkit) |

## Linux-Focused

| Tool | Primary Use | GitHub Signal (2026-02-12) | Links |
|---|---|---:|---|
| Suricata | IDS/IPS and NSM engine | 6,000 stars | [GitHub](https://github.com/OISF/suricata) • [Official](https://suricata.io/download/) |
| Zeek | Network security monitoring/analysis | 7,470 stars | [GitHub](https://github.com/zeek/zeek) • [Official](https://zeek.org/get-zeek/) |
| Snort 3 | IDS/IPS engine | 3,263 stars | [GitHub](https://github.com/snort3/snort3) |
| Wazuh | Open source SIEM/XDR platform | 14,712 stars | [GitHub](https://github.com/wazuh/wazuh) • [Docs](https://documentation.wazuh.com/current/) |
| Aircrack-ng | Wi-Fi security auditing suite | 6,920 stars | [GitHub](https://github.com/aircrack-ng/aircrack-ng) |
| THC Hydra | Network login/password auditing | 11,653 stars | [GitHub](https://github.com/vanhauser-thc/thc-hydra) |
| Masscan | High-speed Internet-scale port scanning | 25,317 stars | [GitHub](https://github.com/robertdavidgraham/masscan) |
| Netdiscover | ARP reconnaissance on LAN | 368 stars | [GitHub](https://github.com/netdiscover-scanner/netdiscover) |
| Bettercap | MITM and network protocol auditing | 18,830 stars | [GitHub](https://github.com/bettercap/bettercap) |
| FFUF | Fast web fuzzing/content discovery | 15,576 stars | [GitHub](https://github.com/ffuf/ffuf) |
| Amass | External attack surface mapping | 14,120 stars | [GitHub](https://github.com/owasp-amass/amass) |
| httpx | HTTP service probing at scale | 9,544 stars | [GitHub](https://github.com/projectdiscovery/httpx) |
| Impacket | Network protocol tooling (AD-heavy) | 15,448 stars | [GitHub](https://github.com/fortra/impacket) |
| PEASS-ng (linPEAS/winPEAS) | Privilege escalation auditing checks | 19,286 stars | [GitHub](https://github.com/peass-ng/PEASS-ng) |
| Volatility 3 | Memory forensics framework | 3,891 stars | [GitHub](https://github.com/volatilityfoundation/volatility3) |

## Windows-Focused

| Tool | Primary Use | GitHub Signal (2026-02-12) | Links |
|---|---|---:|---|
| x64dbg | User-mode debugger for RE/malware analysis | 47,728 stars | [GitHub](https://github.com/x64dbg/x64dbg) |
| Mimikatz | Windows credential/security research | 21,258 stars | [GitHub](https://github.com/gentilkiwi/mimikatz) |
| Rubeus | Kerberos abuse/research operations | 4,874 stars | [GitHub](https://github.com/GhostPack/Rubeus) |
| BloodHound | AD relationship and attack path mapping | 2,761 stars | [GitHub](https://github.com/SpecterOps/BloodHound) |
| Sysinternals Suite | Windows internals/process and incident tooling | N/A (official suite) | [Official](https://learn.microsoft.com/en-us/sysinternals/) |
| Sysmon | Endpoint event telemetry for detection pipelines | N/A (official docs) | [Official](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon) |
| Impacket | SMB/NTLM/Kerberos protocol operations | 15,448 stars | [GitHub](https://github.com/fortra/impacket) |
| PEASS-ng (winPEAS) | Local privilege escalation checks | 19,286 stars | [GitHub](https://github.com/peass-ng/PEASS-ng) |

## macOS-Focused

| Tool | Primary Use | GitHub Signal (2026-02-12) | Links |
|---|---|---:|---|
| LuLu | Open-source macOS firewall | 11,992 stars | [GitHub](https://github.com/objective-see/LuLu) • [Official](https://objective-see.org/tools.html) |
| KnockKnock | Persistence item inspection for macOS | 658 stars | [GitHub](https://github.com/objective-see/KnockKnock) • [Official](https://objective-see.org/tools.html) |
| BlockBlock | Persistence monitoring and alerting | 740 stars | [GitHub](https://github.com/objective-see/BlockBlock) • [Official](https://objective-see.org/tools.html) |
| OverSight | Mic/webcam access monitoring | 642 stars | [GitHub](https://github.com/objective-see/OverSight) • [Official](https://objective-see.org/tools.html) |
| osquery | Endpoint telemetry on macOS fleets | 23,099 stars | [GitHub](https://github.com/osquery/osquery) |
| Wireshark | Packet analysis on macOS | 8,999 stars | [GitHub](https://github.com/wireshark/wireshark) • [Official](https://www.wireshark.org/download.html) |
| Nmap | Security scanning and host discovery | 12,390 stars | [GitHub](https://github.com/nmap/nmap) • [Official](https://nmap.org/download) |

## Distro/Platform Ecosystems (for Tool Discovery)

- Kali Linux tools catalog: https://www.kali.org/tools/
- Parrot Security tools/catalog: https://parrotsec.org/

## Notes

- This list mixes offensive, defensive, and DFIR tooling for authorized security testing, hardening, detection engineering, and incident response.
- GitHub stars are popularity signals, not quality guarantees. Prefer active maintenance, release cadence, and fit for your environment.
- Avoid archived projects unless you have a specific reason and compensating controls.
