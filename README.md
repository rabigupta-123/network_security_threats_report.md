# Network Security Threats & Defense Architectures: Technical Research Report

[![Security Research](https://img.shields.io/badge/Security_Research-Task_4-blue.svg)](#)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE_ATT%26CK-Mapped-red.svg)](https://attack.mitre.org/)
[![Standards](https://img.shields.io/badge/Standards-NIST_|_CISA_|_RFC-green.svg)](https://csrc.nist.gov/)
[![License](https://img.shields.io/badge/License-MIT-lightgrey.svg)](#)

> **Ethical Hacking Internship — Task 4 Submission**  
> **Author:** Rabi Kumar Gupta | Senior Network Security Engineer & Ethical Hacking Research Lead  
> **Primary Report Document:** [`network_security_threats_report.md`](./network_security_threats_report.md)

---

## Executive Overview

This repository hosts an engineering-level research report evaluating four foundational network security threats that continue to jeopardize modern enterprise perimeters:
1. **Denial of Service (DoS) and Distributed Denial of Service (DDoS)**
2. **Man-in-the-Middle (MITM / Adversary-in-the-Middle)**
3. **IP Address Spoofing**
4. **DNS Poisoning and DNS Spoofing**

Each threat vector is analyzed through a rigorous, defense-in-depth framework: technical attack mechanics mapped to the **MITRE ATT&CK Enterprise Matrix**, documented named real-world case studies (*Krebs on Security*, *Wired*, official forensic post-mortems), concrete business and operational impacts, and **three specific, production-ready mitigations** with exact protocol, kernel, and network configuration standards.

---

## Quick Navigation: Primary Report Sections

The complete report is available in [`network_security_threats_report.md`](./network_security_threats_report.md). Jump directly to any core section below:

| Section | Topic | Primary Reference & Mitre Mapping |
| :--- | :--- | :--- |
| [**Section 1**](./network_security_threats_report.md#1-introduction) | **Threat Landscape Introduction** | *Verizon DBIR*, CISA Advisories |
| [**Section 2**](./network_security_threats_report.md#2-threat-analysis-denial-of-service-dos-and-distributed-denial-of-service-ddos) | **Denial of Service (DoS/DDoS)** | MITRE [T1498](https://attack.mitre.org/techniques/T1498/) / [T1499](https://attack.mitre.org/techniques/T1499/) • Dyn Mirai Botnet (~1.2 Tbps) |
| [**Section 3**](./network_security_threats_report.md#3-threat-analysis-man-in-the-middle-mitm--adversary-in-the-middle) | **Man-in-the-Middle (MITM / AiTM)** | MITRE [T1557](https://attack.mitre.org/techniques/T1557/) • DigiNotar CA Breach (300k Users Intercepted) |
| [**Section 4**](./network_security_threats_report.md#4-threat-analysis-ip-address-spoofing) | **IP Address Spoofing** | MITRE [T1584](https://attack.mitre.org/techniques/T1584/) / [T1498.002](https://attack.mitre.org/techniques/T1498/002/) • GitHub 1.35 Tbps Memcached Assault |
| [**Section 5**](./network_security_threats_report.md#5-threat-analysis-dns-poisoning-and-dns-spoofing) | **DNS Poisoning & Spoofing** | MITRE [T1584.004](https://attack.mitre.org/techniques/T1584/004/) • Route 53 BGP Hijack & MyEtherWallet Theft |
| [**Section 6**](./network_security_threats_report.md#6-threat-vector-comparative-matrix) | **Threat Vector Comparative Matrix** | Qualitative Assessment Matrix (Risk, Execution, Mitigation) |
| [**Section 7**](./network_security_threats_report.md#7-strategic-conclusions-and-administrator-recommendations) | **Administrator Takeaways** | 3 Prioritized Strategic Recommendations |
| [**Section 8**](./network_security_threats_report.md#8-references) | **Verified Bibliography** | NIST, CISA, SANS, IETF, Krebs, Wired, Fox-IT |

---

## Threat Matrix Summary

| Attack Vector | Who Is At Risk | Difficulty to Execute | Ease of Mitigation | Core Technical Defenses |
| :--- | :--- | :--- | :--- | :--- |
| **DoS / DDoS** | Public APIs, e-commerce, cloud endpoints, authoritative DNS | **Low** | **Medium** | Kernel TCP SYN Cookies (`sysctl.conf`), Anycast BGP routing, BGP Flowspec (RFC 5575), WAF rate limiting |
| **MITM / AiTM** | Enterprise LANs, unpinned web applications, remote users | **Medium** | **High** | Dynamic ARP Inspection (DAI), DHCP Snooping, HSTS preloading, CAA records (RFC 8659), SMB signing |
| **IP Address Spoofing** | Stateless UDP daemons (DNS/NTP/Memcached), IP-whitelisted firewalls | **Low** | **Low** | BCP 38 / RFC 2827 ingress/egress filtering, Unicast Reverse Path Forwarding (uRPF Strict Mode), IPsec ESP |
| **DNS Poisoning / Spoofing** | Recursive resolvers, cryptocurrency platforms, corporate email | **High** | **High** | Universal DNSSEC validation (NIST SP 800-81-2), UDP source port randomization (RFC 5452), BGP RPKI ROV |

---

## Key Defense Configurations Included

The report provides exact configuration snippets for enterprise implementations:
* **Linux Kernel Hardening (`/etc/sysctl.conf`):**
  ```ini
  net.ipv4.tcp_syncookies = 1
  net.ipv4.tcp_max_syn_backlog = 4096
  net.core.somaxconn = 65535
  ```
* **Cisco IOS Switch Layer 2 Port Security:**
  ```text
  Switch(config)# ip dhcp snooping
  Switch(config)# ip dhcp snooping vlan 10,20
  Switch(config)# ip arp inspection vlan 10,20
  ```
* **Boundary Router Anti-Spoofing (uRPF Strict Mode):**
  ```text
  Router(config-if)# ip verify unicast source reachable-via rx
  ```
* **BIND 9 Cryptographic DNSSEC Enforcement:**
  ```text
  options {
      dnssec-validation auto;
  };
  ```

---

## Standards and Sourcing Compliance

The technical documentation adheres to strict sourcing rules and draws from primary authority bodies:
* **NIST (National Institute of Standards and Technology):** NIST SP 800-81-2 (Secure DNS Deployment), NIST SP 800-61 Rev. 2 (Incident Handling).
* **CISA (Cybersecurity & Infrastructure Security Agency):** Alert TA16-288A (Mirai and Botnet DDoS Threats).
* **MITRE ATT&CK®:** Techniques T1498, T1499, T1557, T1584, and associated sub-techniques.
* **IETF (Internet Engineering Task Force):** RFC 2827 / BCP 38 (Ingress Filtering), RFC 5452 (DNS Hardening), RFC 4033/4034/4035 (DNSSEC), RFC 4303 (IPsec ESP), RFC 8659 (DNS CAA).
* **Forensic Post-Mortems & Investigative Reporting:** *Krebs on Security*, *Wired*, Fox-IT (*Operation Black Tulip*), and GitHub Engineering Incident Reports.

---

## Repository Structure

```
├── .gitignore                          # Standard development hygiene exclusions
├── README.md                           # Project presentation, overview & navigation index
└── network_security_threats_report.md  # Comprehensive technical research report
```

---

## Author & Verification

* **Engineer:** Rabi Kumar Gupta
* **Role:** Senior Network Security Research Engineer
* **Internship:** Ethical Hacking Internship — Task 4
* **GitHub Repository:** [rabigupta-123/network_security_threats_report.md](https://github.com/rabigupta-123/network_security_threats_report.md)