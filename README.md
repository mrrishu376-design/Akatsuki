# AppIntel Pro - Android Malware Analysis & Digital Forensics Workstation

**AppIntel Pro** is a comprehensive, production-grade Android Application Security, Malware Analysis, and Digital Forensics platform. Built for security analysts, incident responders, and law enforcement forensics units, it enables automated decompilation, static bytecode inspection, dynamic sandbox tracing, IOC extraction, MITRE ATT&CK for Mobile mapping, explainable risk scoring, side-by-side APK comparison, and export of court-ready forensic reports.

---

## 🛡️ Core Capabilities

### 1. Real APK Ingestion & Decompilation Pipeline
- **Package Archive Validation:** Verifies APK binary ZIP structure, detects malformed headers, and enforces a 250 MB inspection limit.
- **Evidentiary Hash Generation:** Calculates cryptographic checksums (**MD5**, **SHA-1**, and **SHA-256**) in real-time.
- **Binary AXML Parser:** Decodes compiled `AndroidManifest.xml` binaries directly from byte streams without third-party CLI dependencies, extracting package name, SDK targets, permissions, exported components, and intent filters.
- **DEX Bytecode & String Analysis:** Parses `classes.dex` string pools and method tables to locate reflection, dynamic class loading (`DexClassLoader`, `InMemoryDexClassLoader`), shell execution (`Runtime.getRuntime().exec`), and anti-debugging triggers.
- **Certificate & Signer Audit:** Inspects `META-INF/*.RSA` and APK Signature Scheme v2/v3 blocks, extracting X.509 validity periods, serial numbers, and SHA-1 fingerprints.
- **SBOM & CVE Correlation:** Matches detected third-party dependencies (`okhttp`, `retrofit`, `gson`, `commons-io`, `bouncycastle`) against public CVE databases.

### 2. APK Analysis Workspace (6 Deep Forensic Tabs)
1. **Static & Manifest Analysis:** Header metadata, dangerous vs. normal permission audit, exported component analysis, and suspicious reflection signatures.
2. **Dynamic Behavioural Sandbox:** Isolated ARM64 emulator monitoring with real-time logcat streaming, file-system operation tracking (`/data/data/...`), sensitive API hook logging (`SmsManager`, `LocationManager`, `TelephonyManager`, `AccessibilityService`), and network traffic logging.
3. **Evasion & Obfuscation Inspector:** Detects anti-debugging (ptrace, TracerPid), anti-emulation sensor checks, root detection, ProGuard/DexGuard identifier stripping, and includes an interactive **Encrypted Asset & Payload Decoder** (Base64, Hex, AES unpacking).
4. **Network, Certificate & Library Analysis:** Extracted C2 domain and IP IOCs, SSL/TLS certificate viewer, and SBOM dependency vulnerability table with links to NIST NVD.
5. **Threat Intelligence & MITRE ATT&CK:** Explainable risk scoring (0–100) with weighted threat factors and tactical mapping to official **MITRE ATT&CK® for Mobile** techniques.
6. **Forensic Report Generator:** Generates downloadable **PDF Reports** with forensic headers and evidentiary integrity hashes, plus **JSON IOC exports** for SIEM/MISP ingestion.

### 3. Side-by-Side APK Comparison
- Select any two previously ingested samples.
- Visual comparative differential highlighting unique permissions in Sample A vs. Sample B, risk score gaps, component exposure, and IOC differences.
- Export comparison analysis in structured JSON.

### 4. Global Threat Intelligence & IOC Feed
- Searchable database of indicators (domains, IPs, file hashes, URLs).
- Filter by indicator type and confidence.
- One-click copy, verified status badges, and registration of newly identified IOCs.
- Export feed as CSV or JSON.

---

## 🔒 Privacy & Data Retention Protocol

- **Zero Unnecessary PII:** AppIntel Pro requires only an email address for session verification. It **never** asks for or records full names, phone numbers, birthdates, gender, organizations, or profile images.
- **Ephemeral Storage:** Uploaded APK binaries are inspected in memory/temporary containers and are **not stored permanently**.
- **No Trackers:** Zero third-party analytics pixels, tracking cookies, or behavioral advertising scripts.

---
