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

## 🗄️ Supabase PostgreSQL Setup (Step-by-Step)

AppIntel Pro works out-of-the-box in local persistence mode, and seamlessly connects to **Supabase** for cloud PostgreSQL storage, Row Level Security (RLS), and Email Authentication.

### Step 1: Create a Free Supabase Project
1. Go to [supabase.com](https://supabase.com) and create an account.
2. Click **"New Project"**, select your preferred cloud region, and set a database password.

### Step 2: Initialize the Database Schema
1. In your Supabase Dashboard, click on **SQL Editor** in the left sidebar.
2. Click **"New query"**.
3. Copy the complete contents of `/supabase_schema.sql` from this repository and paste it into the editor.
4. Click **"Run"**.
5. All 8 forensic tables (`apk_analyses`, `permissions_findings`, `component_findings`, `network_iocs`, `global_iocs`, `mitre_mappings`, `code_findings`, and `forensic_audit_events`) with strict Row Level Security (RLS) policies are now initialized!

### Step 3: Get your API Credentials
1. In Supabase, go to **Project Settings** (gear icon) → **API**.
2. Copy:
   - **Project URL** (e.g. `https://xyzcompany.supabase.co`)
   - **Project API key `anon` `public`** (e.g. `eyJhbGciOi...`)

---

## 🚀 GitHub Push & Vercel Deployment

Follow this exact guide to push to GitHub and deploy to Vercel:

### 1. Push to GitHub
In your project directory:
```bash
# 1. Initialize git (if not already initialized)
git init

# 2. Stage all files (node_modules and .env are automatically ignored by .gitignore)
git add .

# 3. Create initial commit
git commit -m "feat: complete AppIntel Pro forensic platform with Supabase support"

# 4. Set default branch to main
git branch -M main

# 5. Link your GitHub repository
git remote add origin https://github.com/YOUR_GITHUB_USERNAME/appintel-pro.git

# 6. Push code to GitHub
git push -u origin main
```

### 2. Deploy to Vercel
1. Log in to [vercel.com](https://vercel.com) with your GitHub account.
2. Click **"Add New..." → "Project"**.
3. Select your `appintel-pro` repository from the list and click **"Import"**.
4. In the **Environment Variables** section, add your Supabase credentials:
   - `VITE_SUPABASE_URL` = `https://your-project-id.supabase.co`
   - `VITE_SUPABASE_ANON_KEY` = `your-supabase-anon-public-key`
5. Click **"Deploy"**.

Vercel will build the project using `npm run build` and serve it with the SPA routing rules defined in `vercel.json`.

---

## 💻 Local Development

```bash
# Clone the repository
git clone https://github.com/YOUR_USERNAME/appintel-pro.git
cd appintel-pro

# Install dependencies
npm install

# (Optional) Copy environment template and add your Supabase credentials
cp .env.example .env

# Run local development server
npm run dev
```
Open `http://localhost:3000` in your browser.
