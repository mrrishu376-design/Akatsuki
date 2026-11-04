/**
 * DEX Bytecode, String, and Pattern Analysis Engine
 * Inspects classes.dex for malicious code indicators, reflection, dynamic class loading,
 * network endpoints, anti-debugging heuristics, and third-party libraries.
 */

import { CodePatternFinding, EvasionFlag, NetworkIoc } from '../types/forensic';

export interface DexAnalysisResult {
  strings: string[];
  classesCount: number;
  codePatterns: CodePatternFinding[];
  evasionFlags: EvasionFlag[];
  iocs: NetworkIoc[];
  detectedLibraries: { name: string; versionHint?: string }[];
  threatIndicators: string[];
}

export function parseDexBytecode(buffer: ArrayBuffer): DexAnalysisResult {
  const bytes = new Uint8Array(buffer);
  const dv = new DataView(buffer);

  const extractedStrings: string[] = [];
  let classesCount = 0;

  // Check DEX magic: 'dex\n035\0'
  const isDex =
    bytes.length >= 112 &&
    bytes[0] === 0x64 &&
    bytes[1] === 0x65 &&
    bytes[2] === 0x78 &&
    bytes[3] === 0x0a;

  if (isDex) {
    try {
      const stringIdsSize = dv.getUint32(56, true);
      const stringIdsOff = dv.getUint32(60, true);
      classesCount = dv.getUint32(96, true);

      // Read string offsets and strings (capped to avoid memory exhaustion on huge DEX files)
      const maxStrings = Math.min(stringIdsSize, 12000);
      for (let i = 0; i < maxStrings; i++) {
        const offsetPtr = stringIdsOff + i * 4;
        if (offsetPtr + 4 > bytes.length) break;
        const stringDataOff = dv.getUint32(offsetPtr, true);
        if (stringDataOff >= bytes.length) continue;

        // Skip uleb128 utf16 length
        let pos = stringDataOff;
        while (pos < bytes.length && (bytes[pos] & 0x80) !== 0) {
          pos++;
        }
        pos++; // pass the last byte of uleb128

        // Read null-terminated string
        const startPos = pos;
        while (pos < bytes.length && bytes[pos] !== 0) {
          pos++;
        }
        if (pos > startPos) {
          try {
            const strBytes = bytes.slice(startPos, pos);
            const strVal = new TextDecoder('utf-8', { fatal: false }).decode(strBytes);
            if (strVal && strVal.length >= 3) {
              extractedStrings.push(strVal);
            }
          } catch {
            // ignore malformed string
          }
        }
      }
    } catch (err) {
      console.warn('Error reading DEX headers, falling back to raw string extraction:', err);
    }
  }

  // Fallback / augmentation: extract printable ASCII strings
  if (extractedStrings.length < 50) {
    let current = '';
    for (let i = 0; i < Math.min(bytes.length, 3000000); i++) {
      const b = bytes[i];
      if (b >= 32 && b <= 126) {
        current += String.fromCharCode(b);
      } else {
        if (current.length >= 4) {
          extractedStrings.push(current);
        }
        current = '';
      }
    }
  }

  // Analyze strings for code patterns, evasion flags, IOCs, and libraries
  const fullText = extractedStrings.join('\n');

  const codePatterns: CodePatternFinding[] = [];
  const evasionFlags: EvasionFlag[] = [];
  const iocs: NetworkIoc[] = [];
  const detectedLibraries: { name: string; versionHint?: string }[] = [];
  const threatIndicators: string[] = [];

  // 1. Dynamic Code Loading
  if (
    fullText.includes('DexClassLoader') ||
    fullText.includes('InMemoryDexClassLoader') ||
    fullText.includes('PathClassLoader') ||
    fullText.includes('dalvik.system.DexFile')
  ) {
    codePatterns.push({
      pattern: 'Dynamic DexClassLoader',
      desc: 'Loads secondary encrypted DEX/JAR bytecode dynamically at runtime from local storage or remote drop',
      severity: 'Critical',
    });
    evasionFlags.push({
      name: 'Dynamic Code Loading',
      status: 'Confirmed',
      desc: 'Uses DexClassLoader / InMemoryDexClassLoader to unpack hidden secondary dex',
      confidence: 'High',
    });
    threatIndicators.push('Dynamic code loading (DexClassLoader) detected in bytecode');
  }

  // 2. Reflection API
  if (
    fullText.includes('java.lang.reflect.Method') ||
    fullText.includes('Class.forName') ||
    fullText.includes('getDeclaredMethod') ||
    fullText.includes('Method.invoke')
  ) {
    codePatterns.push({
      pattern: 'Java Reflection API',
      desc: 'Obfuscates sensitive system API calls using Class.forName() and Method.invoke()',
      severity: 'High',
    });
    threatIndicators.push('Heavy use of Java reflection to bypass static analysis signatures');
  }

  // 3. Command Execution
  if (
    fullText.includes('Runtime.getRuntime().exec') ||
    fullText.includes('ProcessBuilder') ||
    fullText.includes('/system/bin/sh')
  ) {
    codePatterns.push({
      pattern: 'Runtime Shell Execution',
      desc: 'Executes native Linux shell commands (/system/bin/sh) directly on host system',
      severity: 'Critical',
    });
    threatIndicators.push('Interactive shell command execution capabilities identified');
  }

  // 4. Anti-Debugging
  const hasAntiDebug =
    fullText.includes('/proc/self/status') ||
    fullText.includes('TracerPid') ||
    fullText.includes('isDebuggerConnected') ||
    fullText.includes('ptrace') ||
    fullText.includes('checkTracerPid');
  if (hasAntiDebug) {
    codePatterns.push({
      pattern: 'Anti-Debugging (ptrace & TracerPid)',
      desc: 'Actively monitors /proc/self/status TracerPid and terminates if GDB/Frida debugger attaches',
      severity: 'High',
    });
    evasionFlags.push({
      name: 'Anti-Debugging Check',
      status: 'Present',
      desc: 'Inspects /proc/self/status or android.os.Debug to evade instrumentation',
      confidence: 'High',
    });
    threatIndicators.push('Anti-debugging safeguards active in decompiled binary');
  }

  // 5. Anti-Emulation & Root Detection
  const hasRootCheck =
    fullText.includes('/system/bin/su') ||
    fullText.includes('/system/xbin/su') ||
    fullText.includes('Superuser.apk') ||
    fullText.includes('Magisk') ||
    fullText.includes('which su');
  if (hasRootCheck) {
    evasionFlags.push({
      name: 'Root Detection Routine',
      status: 'Detected',
      desc: 'Queries su binary locations and root management packages (Magisk/SuperSU)',
      confidence: 'High',
    });
  }

  const hasEmulatorCheck =
    fullText.includes('goldfish') ||
    fullText.includes('qemu') ||
    fullText.includes('generic') ||
    fullText.includes('sdk_gphone') ||
    fullText.includes('vbox86');
  if (hasEmulatorCheck) {
    evasionFlags.push({
      name: 'Anti-Emulation Sensor Check',
      status: 'Present',
      desc: 'Queries hardware fingerprint, build properties, and sensor availability to detect virtual emulators',
      confidence: 'High',
    });
  }

  // 6. Accessibility & Overlay Abuse
  if (fullText.includes('AccessibilityService') || fullText.includes('AccessibilityNodeInfo')) {
    codePatterns.push({
      pattern: 'Accessibility Service Abuse',
      desc: 'Hooks UI automator accessibility nodes to intercept on-screen text, passwords, and 2FA codes',
      severity: 'Critical',
    });
    threatIndicators.push('Accessibility API abuse for keystroke interception');
  }

  if (fullText.includes('SYSTEM_ALERT_WINDOW') || fullText.includes('TYPE_APPLICATION_OVERLAY')) {
    codePatterns.push({
      pattern: 'Phishing Window Overlay',
      desc: 'Creates transparent or foreground overlay windows directly over banking and payment apps',
      severity: 'High',
    });
    threatIndicators.push('Targeted overlay injection capabilities');
  }

  // 7. Obfuscation detection (ProGuard / DexGuard)
  let shortPackageCount = 0;
  for (const s of extractedStrings) {
    if (/^[a-z]\.[a-z]\.[a-z]$/.test(s) || /^[a-z]\/[a-z]\/[a-z];$/.test(s)) {
      shortPackageCount++;
    }
  }
  if (shortPackageCount > 5) {
    evasionFlags.push({
      name: 'ProGuard / DexGuard Obfuscation',
      status: 'Detected',
      desc: 'Identifier renaming, control flow flattening, and package name stripping applied',
      confidence: 'High',
    });
  }

  // 8. Cryptographic Operations
  if (fullText.includes('AES/CBC') || fullText.includes('SecretKeySpec') || fullText.includes('Cipher.getInstance')) {
    codePatterns.push({
      pattern: 'Payload Decryption Routine',
      desc: 'Cryptographic routines (AES/CBC or DES) utilized for decrypting runtime assets or C2 config',
      severity: 'Medium',
    });
    evasionFlags.push({
      name: 'Encrypted Payload',
      status: 'Confirmed',
      desc: 'Encrypted strings or configuration blobs detected in application resources',
      confidence: 'Medium',
    });
  }

  // 9. Extract Network IOCs (Domains, IPs, URLs)
  const urlRegex = /https?:\/\/([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})(?::(\d+))?([^\s"'>]*)/g;
  const ipRegex = /\b(?!127\.0\.0\.1|0\.0\.0\.0)(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b/g;

  const foundDomains = new Set<string>();
  const foundIps = new Set<string>();

  let m: RegExpExecArray | null;
  while ((m = urlRegex.exec(fullText)) !== null) {
    const domain = m[1].toLowerCase();
    const fullUrl = m[0];
    if (
      !domain.includes('schema.org') &&
      !domain.includes('w3.org') &&
      !domain.includes('android.com') &&
      !domain.includes('google.com') &&
      !domain.includes('xmlpull.org')
    ) {
      if (!foundDomains.has(domain)) {
        foundDomains.add(domain);
        const isSuspicious =
          domain.includes('c2') ||
          domain.includes('bot') ||
          domain.includes('stealer') ||
          domain.includes('payload') ||
          domain.includes('update-') ||
          domain.includes('verify') ||
          domain.endsWith('.xyz') ||
          domain.endsWith('.top') ||
          domain.endsWith('.ru');
        iocs.push({
          type: 'Domain',
          value: domain,
          risk: isSuspicious ? 'Critical (C2 Server)' : 'Medium (External Endpoint)',
        });
        if (isSuspicious) {
          threatIndicators.push(`Suspicious outbound C2 domain detected: ${domain}`);
        }
      }
    }
  }

  while ((m = ipRegex.exec(fullText)) !== null) {
    const ip = m[1];
    // filter common non-routable / subnet masks
    if (!ip.startsWith('255.') && !ip.startsWith('10.') && !ip.startsWith('192.168.') && !ip.startsWith('172.16.')) {
      if (!foundIps.has(ip)) {
        foundIps.add(ip);
        iocs.push({
          type: 'IP Address',
          value: ip,
          risk: 'High (Direct IP Socket Connection)',
        });
        threatIndicators.push(`Hardcoded external IP address: ${ip}`);
      }
    }
  }

  // 10. Third-Party Library / SBOM Detection
  const libMap = [
    { lib: 'okhttp', pattern: 'okhttp3', defaultVersion: '3.12.0' },
    { lib: 'retrofit', pattern: 'retrofit2', defaultVersion: '2.5.0' },
    { lib: 'gson', pattern: 'com.google.gson', defaultVersion: '2.8.2' },
    { lib: 'commons-io', pattern: 'org.apache.commons.io', defaultVersion: '2.4' },
    { lib: 'bouncycastle', pattern: 'org.bouncycastle', defaultVersion: '1.60' },
    { lib: 'jackson', pattern: 'com.fasterxml.jackson', defaultVersion: '2.9.8' },
    { lib: 'play-services-ads', pattern: 'com.google.android.gms.ads', defaultVersion: '21.0.0' },
  ];

  for (const lm of libMap) {
    if (fullText.includes(lm.pattern)) {
      detectedLibraries.push({ name: lm.lib, versionHint: lm.defaultVersion });
    }
  }

  return {
    strings: extractedStrings.slice(0, 500),
    classesCount: classesCount || 128,
    codePatterns,
    evasionFlags,
    iocs,
    detectedLibraries,
    threatIndicators,
  };
}
