/**
 * AppIntel Pro - Local Storage & Data Store Persistence
 * Pre-populates forensic cases from the existing UI and supports user-uploaded APKs
 */

import { ForensicCase, GlobalIocItem } from '../types/forensic';

export const INITIAL_PRELOADED_CASES: ForensicCase[] = [
  {
    id: 0,
    filename: 'Spyware_Stealer_v2.4.apk',
    fileSize: 4518290,
    fileSizeBytesFormatted: '4.31 MB',
    pkg: 'com.system.updates.guard',
    classification: 'CRITICAL (Spyware)',
    riskScore: 94,
    md5: 'c4ca4238a0b923820dcc509a6f75849b',
    sha1: '5863a6cf5182069e09432b6a1996793e12358910',
    sha256: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    version: '2.4.0 (API 33)',
    minSdk: 'API 21',
    targetSdk: 'API 33',
    signer: 'Self-Signed (Untrusted)',
    uploadedAt: '2026-10-31T14:22:00Z',
    isDemo: true,
    components: [
      { type: 'Receiver', name: '.BootCompletedReceiver', exported: 'true', risk: 'Persistence via BOOT_COMPLETED' },
      { type: 'Service', name: '.ScreenRecordService', exported: 'true', risk: 'Background Media Projection' },
      { type: 'Activity', name: '.MainActivity', exported: 'true', risk: 'Phishing credential overlay' },
    ],
    permissions: [
      { name: 'android.permission.READ_CONTACTS', type: 'Dangerous', desc: 'Access user contacts list for harvesting' },
      { name: 'android.permission.RECEIVE_SMS', type: 'Dangerous', desc: 'Intercept 2FA authentication codes' },
      { name: 'android.permission.RECORD_AUDIO', type: 'Dangerous', desc: 'Surreptitious ambient microphone recording' },
      { name: 'android.permission.ACCESS_FINE_LOCATION', type: 'Dangerous', desc: 'Continuous GPS tracking' },
      { name: 'android.permission.CAMERA', type: 'Dangerous', desc: 'Unauthorized photo and video capture' },
      { name: 'android.permission.WRITE_EXTERNAL_STORAGE', type: 'Dangerous', desc: 'Exfiltrate encrypted local databases' },
      { name: 'android.permission.INTERNET', type: 'Normal', desc: 'C2 communication and data upload' },
      { name: 'android.permission.SYSTEM_ALERT_WINDOW', type: 'Dangerous', desc: 'Display overlay UI over banking apps' },
    ],
    codePatterns: [
      { pattern: 'Dynamic DexClassLoader', desc: 'Loads encrypted payload from assets/payload.dex at runtime', severity: 'Critical' },
      { pattern: 'Java Reflection API', desc: 'Obfuscates API calls to Class.forName() and Method.invoke()', severity: 'High' },
      { pattern: 'Anti-Debugging (ptrace)', desc: 'Terminates execution if Frida or GDB debugger is attached', severity: 'High' },
    ],
    sandboxLogs: [
      '[00:00:01] Sandbox spawned container arm64-v8a instance #09',
      '[00:00:02] Hooking ART runtime methods for API monitoring',
      '[00:00:04] Executed BroadcastReceiver: com.system.updates.guard.BootCompletedReceiver',
      '[00:00:06] WARNING: Attempted secret file access: /data/data/com.whatsapp/databases/msgstore.db',
      '[00:00:08] DNS Query generated: api.c2-secure-update.net -> 185.220.101.5',
      '[00:00:10] Established outbound TLS connection to 185.220.101.5:443',
      '[00:00:12] EXFILTRATION DETECTED: 4.2 MB compressed payload uploaded via POST',
    ],
    fileSystem: [
      'Modified: /data/data/com.system.updates.guard/shared_prefs/config.xml',
      'Created: /sdcard/Android/data/com.system.updates.guard/cache/.tmp_payload',
      'Read: /data/system/users/0/settings_secure.xml',
    ],
    apiHooks: [
      'TelephonyManager.getDeviceId() invoked',
      'SmsManager.sendTextMessage() intercepted',
      'AudioRecord.startRecording() executed',
      'LocationManager.getLastKnownLocation() queried',
    ],
    networkTraffic: [
      'DNS: api.c2-secure-update.net (Resolved to 185.220.101.5)',
      'TCP: 185.220.101.5:443 (Encrypted Payload Exchange)',
      'HTTP POST /api/v1/collect (4.2 MB sent)',
    ],
    evasionFlags: [
      { name: 'ProGuard / DexGuard Obfuscation', status: 'Detected', desc: 'Identifier renaming applied to packages' },
      { name: 'Dynamic Code Loading', status: 'Confirmed', desc: 'Uses DexClassLoader to load secondary dex' },
      { name: 'Anti-Debugging Check', status: 'Present', desc: 'Inspects /proc/self/status for TracerPid' },
      { name: 'Anti-Emulation Sensor Check', status: 'Present', desc: 'Queries accelerometer and battery voltage' },
      { name: 'Encrypted Payload', status: 'Decoded', desc: 'AES encrypted strings unpacked successfully' },
    ],
    iocs: [
      { type: 'Domain', value: 'api.c2-secure-update.net', risk: 'Critical (C2 Server)' },
      { type: 'IP Address', value: '185.220.101.5', risk: 'Critical (Tor Exit Node / C2)' },
      { type: 'File Hash', value: 'c4ca4238a0b923820dcc509a6f75849b', risk: 'Malicious (MD5)' },
    ],
    certInfo: {
      issuer: 'CN=Android Debug, OU=Android, O=Google, L=Mountain View, ST=California, C=US',
      validFrom: '2024-01-10',
      validTo: '2054-01-02',
      serial: '38928392109283',
      sha1Fingerprint: '58:63:A6:CF:51:82:06:9E:09:43:2B:6A:19:96:79:3E:12:35:89:10',
    },
    sbom: [
      { lib: 'okhttp', version: '3.10.0', vuln: 'CVE-2023-3802', severity: 'High' },
      { lib: 'gson', version: '2.8.2', vuln: 'CVE-2022-25647', severity: 'Medium' },
      { lib: 'commons-io', version: '2.4', vuln: 'CVE-2021-29425', severity: 'Critical' },
    ],
    threatFactors: [
      'Excessive SMS and Contacts permissions without valid utility',
      'Outbound connections to known malicious C2 IP (185.220.101.5)',
      'Use of DexClassLoader to execute hidden secondary payload',
      'Anti-debugging evasion techniques detected in native libraries',
    ],
    mitre: [
      { tactic: 'Collection', tech: 'T1430 - Location Tracking', observed: 'Continuous GPS data harvesting' },
      { tactic: 'Exfiltration', tech: 'T1041 - Exfiltration Over C2 Channel', observed: 'HTTPS payload upload to 185.220.101.5' },
      { tactic: 'Defense Evasion', tech: 'T1622 - Debugger Evasion', observed: 'ptrace tracer PID inspection' },
    ],
  },
  {
    id: 1,
    filename: 'Banking_Trojan_FakeBank.apk',
    fileSize: 8412891,
    fileSizeBytesFormatted: '8.02 MB',
    pkg: 'com.secure.bank.verify.app',
    classification: 'HIGH (Banking Trojan)',
    riskScore: 88,
    md5: '81dc9bdb52d04dc20036dbd8313ed055',
    sha1: 'aabbccddeeff1122334455667788990011223344',
    sha256: 'cf23df2207d99a74fbe169e3eba035e633b65d947b0f4001925d506d1c94d072',
    version: '1.1.2 (API 31)',
    minSdk: 'API 21',
    targetSdk: 'API 31',
    signer: 'Third-Party Certificate',
    uploadedAt: '2026-10-30T10:15:00Z',
    isDemo: true,
    components: [
      { type: 'Service', name: '.AccessibilityHelper', exported: 'true', risk: 'UI Automator overlay theft' },
      { type: 'Activity', name: '.LoginActivity', exported: 'true', risk: 'Credential phishing form' },
    ],
    permissions: [
      { name: 'android.permission.BIND_ACCESSIBILITY_SERVICE', type: 'Dangerous', desc: 'Read on-screen text and simulate clicks' },
      { name: 'android.permission.INTERNET', type: 'Normal', desc: 'Connect to banking C2 server' },
      { name: 'android.permission.REQUEST_INSTALL_PACKAGES', type: 'Dangerous', desc: 'Download malicious dropper updates' },
    ],
    codePatterns: [
      { pattern: 'Accessibility Abuse', desc: 'Extracts banking credentials via node traversal', severity: 'Critical' },
      { pattern: 'String Decryption Routine', desc: 'Custom AES decryption loop in JNI library', severity: 'High' },
    ],
    sandboxLogs: [
      '[00:00:01] Initializing Sandbox container...',
      '[00:00:03] Accessibility Service enabled by user prompt simulation',
      '[00:00:05] Target banking app detected in foreground: com.chase.sig.android',
      '[00:00:07] Overlay window injected over banking login UI',
      '[00:00:09] Credentials captured and sent to 45.33.22.11',
    ],
    fileSystem: ['Modified: /data/data/com.secure.bank.verify.app/databases/cache.db'],
    apiHooks: ['AccessibilityNodeInfo.getText() accessed', 'WindowManager.addView() overlay created'],
    networkTraffic: ['IP: 45.33.22.11:8443 (Banking C2 endpoint)'],
    evasionFlags: [
      { name: 'ProGuard Obfuscation', status: 'Detected', desc: 'Class names randomized' },
      { name: 'Anti-Sandbox Check', status: 'Present', desc: 'Checks uptime and battery level' },
    ],
    iocs: [{ type: 'IP Address', value: '45.33.22.11', risk: 'High (Banking C2)' }],
    certInfo: {
      issuer: 'CN=Dev Cert, O=Unknown Corp',
      validFrom: '2023-05-12',
      validTo: '2033-05-09',
      serial: '991823912',
      sha1Fingerprint: 'AA:BB:CC:DD:EE:FF:11:22:33:44:55:66:77:88:99:00:11:22:33:44',
    },
    sbom: [{ lib: 'retrofit', version: '2.3.0', vuln: 'CVE-2018-1000844', severity: 'Medium' }],
    threatFactors: [
      'Abuse of Android Accessibility Service for credential theft',
      'Overlay attacks targeting popular banking applications',
      'Communication with known financial malware C2 infrastructure',
    ],
    mitre: [
      { tactic: 'Credential Access', tech: 'T1417 - Input Capture', observed: 'Accessibility overlay keystroke logging' },
      { tactic: 'Collection', tech: 'T1533 - Data from Local System', observed: 'Banking session token extraction' },
    ],
  },
  {
    id: 2,
    filename: 'Adware_Scanner_clean.apk',
    fileSize: 3192000,
    fileSizeBytesFormatted: '3.04 MB',
    pkg: 'com.cleaner.speed.boost',
    classification: 'LOW (Adware / PUP)',
    riskScore: 24,
    md5: 'e10adc3949ba59abbe56e057f20f883e',
    sha1: '1122334455667788990011223344556677889900',
    sha256: '03ac674216f3e15c761ee1a5e255f067953623c8b388b4459e13f978d7c846f4',
    version: '3.0.1 (API 34)',
    minSdk: 'API 21',
    targetSdk: 'API 34',
    signer: 'Verified Publisher',
    uploadedAt: '2026-10-28T09:00:00Z',
    isDemo: true,
    components: [{ type: 'Activity', name: '.MainActivity', exported: 'true', risk: 'Standard launcher activity' }],
    permissions: [
      { name: 'android.permission.INTERNET', type: 'Normal', desc: 'Ad banner loading' },
      { name: 'android.permission.ACCESS_NETWORK_STATE', type: 'Normal', desc: 'Check connectivity' },
    ],
    codePatterns: [{ pattern: 'Ad SDK Integration', desc: 'Standard Google AdMob SDK present', severity: 'Low' }],
    sandboxLogs: [
      '[00:00:01] Sandbox container initialized',
      '[00:00:03] Activity started successfully',
      '[00:00:05] Ad banner requested from admob.google.com',
      '[00:00:08] Execution completed with zero anomalies',
    ],
    fileSystem: ['Modified: /data/data/com.cleaner.speed.boost/cache/ad_cache'],
    apiHooks: ['ConnectivityManager.getActiveNetworkInfo()'],
    networkTraffic: ['DNS: pagead2.googlesyndication.com'],
    evasionFlags: [{ name: 'Obfuscation', status: 'None', desc: 'Clean code structure' }],
    iocs: [{ type: 'Domain', value: 'pagead2.googlesyndication.com', risk: 'Benign (Ad Network)' }],
    certInfo: {
      issuer: 'CN=Google Inc, O=Google Inc, L=Mountain View, ST=California, C=US',
      validFrom: '2020-01-01',
      validTo: '2050-01-01',
      serial: '123456789',
      sha1Fingerprint: '11:22:33:44:55:66:77:88:99:00:11:22:33:44:55:66:77:88:99:00',
    },
    sbom: [{ lib: 'play-services-ads', version: '22.0.0', vuln: 'None', severity: 'Low' }],
    threatFactors: [
      'Low risk classification, standard advertising SDK behaviors',
      'No sensitive permission abuse or malicious C2 communication',
    ],
    mitre: [{ tactic: 'Discovery', tech: 'T1418 - System Information Discovery', observed: 'Standard network state queries' }],
  },
];

export const INITIAL_GLOBAL_IOCS: GlobalIocItem[] = [
  { id: '1', type: 'Domain', val: 'api.c2-secure-update.net', malware: 'Spyware_Stealer_v2.4', conf: '99%', source: 'Interpol Mobile Feed', firstSeen: '2026-10-15', status: 'Active C2' },
  { id: '2', type: 'IP Address', val: '185.220.101.5', malware: 'Spyware_Stealer_v2.4', conf: '100%', source: 'US-CERT Advisory', firstSeen: '2026-09-22', status: 'Active Tor Exit' },
  { id: '3', type: 'IP Address', val: '45.33.22.11', malware: 'Banking_Trojan_FakeBank', conf: '95%', source: 'Europol Cyber Division', firstSeen: '2026-10-02', status: 'Flagged Malicious' },
  { id: '4', type: 'File Hash (MD5)', val: 'c4ca4238a0b923820dcc509a6f75849b', malware: 'Spyware_Stealer_v2.4', conf: '100%', source: 'AppIntel Verified', firstSeen: '2026-10-31', status: 'Known Malware' },
  { id: '5', type: 'Domain', val: 'bank-auth-token-drop.xyz', malware: 'Anatsa / Teabot', conf: '92%', source: 'FS-ISAC Threat Hub', firstSeen: '2026-10-20', status: 'Phishing Host' },
  { id: '6', type: 'IP Address', val: '198.51.100.22', malware: 'SMS_Trojan_Dropper', conf: '90%', source: 'CERT-EU Threat Feed', firstSeen: '2026-10-25', status: 'Under Surveillance' },
  { id: '7', type: 'Domain', val: 'pagead2.googlesyndication.com', malware: 'Adware_Scanner_clean', conf: '0%', source: 'Google Safe Browsing', firstSeen: '2012-01-01', status: 'Benign (Ad Network)' },
];

const STORAGE_CASES_KEY = 'appintel_cases_v2';
const STORAGE_IOCS_KEY = 'appintel_iocs_v2';

export function getStoredCases(): ForensicCase[] {
  try {
    const raw = localStorage.getItem(STORAGE_CASES_KEY);
    if (!raw) {
      localStorage.setItem(STORAGE_CASES_KEY, JSON.stringify(INITIAL_PRELOADED_CASES));
      return INITIAL_PRELOADED_CASES;
    }
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) && parsed.length > 0 ? parsed : INITIAL_PRELOADED_CASES;
  } catch {
    return INITIAL_PRELOADED_CASES;
  }
}

export function saveCases(cases: ForensicCase[]): void {
  try {
    localStorage.setItem(STORAGE_CASES_KEY, JSON.stringify(cases));
  } catch (err) {
    console.error('Failed to save cases to localStorage:', err);
  }
}

export function addStoredCase(newCase: ForensicCase): ForensicCase[] {
  const current = getStoredCases();
  const updated = [newCase, ...current];
  saveCases(updated);
  return updated;
}

export function deleteStoredCase(id: string | number): ForensicCase[] {
  const current = getStoredCases();
  const updated = current.filter((c) => String(c.id) !== String(id));
  saveCases(updated);
  return updated;
}

export function getStoredIocs(): GlobalIocItem[] {
  try {
    const raw = localStorage.getItem(STORAGE_IOCS_KEY);
    if (!raw) {
      localStorage.setItem(STORAGE_IOCS_KEY, JSON.stringify(INITIAL_GLOBAL_IOCS));
      return INITIAL_GLOBAL_IOCS;
    }
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) && parsed.length > 0 ? parsed : INITIAL_GLOBAL_IOCS;
  } catch {
    return INITIAL_GLOBAL_IOCS;
  }
}

export function addStoredIoc(ioc: GlobalIocItem): GlobalIocItem[] {
  const current = getStoredIocs();
  // Check if indicator already exists to prevent duplicate entries
  if (current.some((existing) => existing.val.toLowerCase() === ioc.val.toLowerCase())) {
    return current;
  }
  const uniqueId = `ioc-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
  const updated = [{ ...ioc, id: uniqueId }, ...current];
  try {
    localStorage.setItem(STORAGE_IOCS_KEY, JSON.stringify(updated));
  } catch (err) {
    console.error('Failed to save IOCs:', err);
  }
  return updated;
}
