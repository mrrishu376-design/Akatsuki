/**
 * YARA Rules and Explainable Risk Scoring Engine for Android Malware
 */

import { CodePatternFinding, ComponentFinding, NetworkIoc, PermissionFinding } from '../types/forensic';

export interface YaraMatch {
  ruleName: string;
  family: string;
  category: 'Banking Trojan' | 'Spyware' | 'Ransomware' | 'Adware / PUP' | 'Dropper / Backdoor';
  severity: 'Critical' | 'High' | 'Medium' | 'Low';
  description: string;
  matchedStrings: string[];
}

export const YARA_RULES = [
  {
    ruleName: 'Android_Spyware_Generic_Stealer',
    family: 'SpyNote / Generic Spyware',
    category: 'Spyware' as const,
    severity: 'Critical' as const,
    description: 'Matches indicators of ambient microphone recording, SMS interception, and contacts exfiltration.',
    patterns: ['RECORD_AUDIO', 'RECEIVE_SMS', 'READ_CONTACTS', 'DexClassLoader'],
  },
  {
    ruleName: 'Android_Banking_Trojan_Accessibility',
    family: 'Anatsa / SharkBot / TeaBot',
    category: 'Banking Trojan' as const,
    severity: 'Critical' as const,
    description: 'Matches Accessibility service abuse targeting banking apps and automated keystroke logging.',
    patterns: ['BIND_ACCESSIBILITY_SERVICE', 'AccessibilityNodeInfo', 'SYSTEM_ALERT_WINDOW'],
  },
  {
    ruleName: 'Android_Trojan_Dropper_DynamicPayload',
    family: 'Dropper / Loader',
    category: 'Dropper / Backdoor' as const,
    severity: 'High' as const,
    description: 'Matches payload dropper techniques downloading or unpacking hidden DEX files at runtime.',
    patterns: ['DexClassLoader', 'REQUEST_INSTALL_PACKAGES'],
  },
  {
    ruleName: 'Android_AntiAnalysis_Evasion',
    family: 'Advanced Evasion Module',
    category: 'Spyware' as const,
    severity: 'High' as const,
    description: 'Matches debugger detection and TracerPid inspection in native code.',
    patterns: ['TracerPid', 'ptrace', '/proc/self/status'],
  },
  {
    ruleName: 'Android_Adware_Aggressive_SDK',
    family: 'Adware PUP',
    category: 'Adware / PUP' as const,
    severity: 'Low' as const,
    description: 'Matches non-malicious advertising SDK integration with standard network queries.',
    patterns: ['pagead2.googlesyndication.com', 'play-services-ads'],
  },
];

export function runYaraScan(params: {
  permissions: PermissionFinding[];
  codePatterns: CodePatternFinding[];
  iocs: NetworkIoc[];
  fullStringsText: string;
}): YaraMatch[] {
  const { permissions, codePatterns, iocs, fullStringsText } = params;
  const matches: YaraMatch[] = [];

  const textToCheck =
    fullStringsText +
    ' ' +
    permissions.map((p) => p.name).join(' ') +
    ' ' +
    codePatterns.map((cp) => cp.pattern + ' ' + cp.desc).join(' ') +
    ' ' +
    iocs.map((i) => i.value).join(' ');

  for (const rule of YARA_RULES) {
    const matchedStrings: string[] = [];
    for (const pat of rule.patterns) {
      if (textToCheck.includes(pat)) {
        matchedStrings.push(pat);
      }
    }
    // If >= 2 patterns match (or if single critical pattern matches in specific rules)
    if (matchedStrings.length >= 2 || (rule.patterns.length === 1 && matchedStrings.length === 1)) {
      matches.push({
        ruleName: rule.ruleName,
        family: rule.family,
        category: rule.category,
        severity: rule.severity,
        description: rule.description,
        matchedStrings,
      });
    }
  }

  return matches;
}

export function calculateExplainableRiskScore(params: {
  permissions: PermissionFinding[];
  components: ComponentFinding[];
  codePatterns: CodePatternFinding[];
  iocs: NetworkIoc[];
  yaraMatches: YaraMatch[];
  isSelfSigned: boolean;
}): {
  score: number;
  classification: string;
  threatFactors: string[];
} {
  const { permissions, components, codePatterns, iocs, yaraMatches, isSelfSigned } = params;

  let baseScore = 10;
  const factors: string[] = [];

  // Dangerous permissions
  const dangerousPerms = permissions.filter((p) => p.type === 'Dangerous');
  if (dangerousPerms.length > 0) {
    const permWeight = Math.min(dangerousPerms.length * 6, 30);
    baseScore += permWeight;
    factors.push(`Requested ${dangerousPerms.length} dangerous system permissions (${dangerousPerms.slice(0, 3).map((p) => p.name.split('.').pop()).join(', ')}...)`);
  }

  // Accessibility abuse
  if (permissions.some((p) => p.name.includes('ACCESSIBILITY')) || codePatterns.some((c) => c.pattern.includes('Accessibility'))) {
    baseScore += 25;
    factors.push('Abuse of Android Accessibility Service for credential capture and automated clicks');
  }

  // SMS & Contacts
  if (permissions.some((p) => p.name.includes('SMS') || p.name.includes('CONTACTS'))) {
    baseScore += 15;
    factors.push('Excessive SMS and Contacts permissions without valid utility (2FA interception risk)');
  }

  // Dynamic code loading
  if (codePatterns.some((c) => c.pattern.includes('DexClassLoader') || c.pattern.includes('Dynamic'))) {
    baseScore += 20;
    factors.push('Use of DexClassLoader to execute hidden secondary payload at runtime');
  }

  // Anti-debugging / evasion
  if (codePatterns.some((c) => c.pattern.includes('Anti-Debugging'))) {
    baseScore += 15;
    factors.push('Anti-debugging evasion techniques detected (ptrace & TracerPid inspection)');
  }

  // C2 IOCs
  const c2Iocs = iocs.filter((i) => i.risk.includes('Critical') || i.risk.includes('C2'));
  if (c2Iocs.length > 0) {
    baseScore += 25;
    factors.push(`Outbound connections to known suspicious C2 infrastructure (${c2Iocs[0].value})`);
  }

  // Exported components risk
  const exportedComponents = components.filter((c) => c.exported === 'true' || c.exported === true);
  if (exportedComponents.length > 2) {
    baseScore += 8;
    factors.push(`${exportedComponents.length} exported components exposed to potential external invocation`);
  }

  // Signing certificate
  if (isSelfSigned) {
    baseScore += 6;
    factors.push('Self-signed or untrusted certificate authority');
  }

  // YARA matches
  if (yaraMatches.some((y) => y.severity === 'Critical')) {
    baseScore += 20;
    factors.push(`Triggered critical YARA signature for ${yaraMatches[0].family}`);
  }

  // Clamp 0 - 100
  const finalScore = Math.min(Math.max(baseScore, 10), 98);

  let classification = 'LOW (Adware / Benign)';
  if (finalScore >= 80) {
    if (factors.some((f) => f.includes('Accessibility') || f.includes('banking'))) {
      classification = 'CRITICAL (Banking Trojan)';
    } else if (factors.some((f) => f.includes('SMS') || f.includes('Microphone') || f.includes('Contacts'))) {
      classification = 'CRITICAL (Spyware)';
    } else {
      classification = 'CRITICAL (Malware / Trojan)';
    }
  } else if (finalScore >= 60) {
    classification = 'HIGH (Suspicious Dropper)';
  } else if (finalScore >= 40) {
    classification = 'MEDIUM (Riskware / Adware)';
  }

  if (factors.length === 0) {
    factors.push('No critical malicious patterns detected during static and dynamic evaluation');
  }

  return {
    score: finalScore,
    classification,
    threatFactors: factors,
  };
}
