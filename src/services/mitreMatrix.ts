/**
 * MITRE ATT&CK® for Mobile Threat Mapping Engine
 * Correlates observed static, dynamic, and evasion behaviors to official MITRE Mobile Tactics & Techniques
 */

import { ComponentFinding, MitreMapping, PermissionFinding } from '../types/forensic';

export function mapToMitreMobile(params: {
  permissions: PermissionFinding[];
  components: ComponentFinding[];
  codePatterns: { pattern: string; desc: string }[];
  evasionFlags: { name: string; status: string }[];
  hasC2Traffic: boolean;
}): MitreMapping[] {
  const { permissions, components, codePatterns, evasionFlags, hasC2Traffic } = params;
  const mappings: MitreMapping[] = [];

  const permNames = permissions.map((p) => p.name);
  const patternNames = codePatterns.map((cp) => cp.pattern);

  // 1. T1430 - Location Tracking
  if (
    permNames.includes('android.permission.ACCESS_FINE_LOCATION') ||
    permNames.includes('android.permission.ACCESS_COARSE_LOCATION')
  ) {
    mappings.push({
      tactic: 'Collection',
      tech: 'T1430 - Location Tracking',
      techId: 'T1430',
      observed: 'Continuous GPS and network cell coordinates harvesting via LocationManager',
      confidence: 'High',
    });
  }

  // 2. T1041 - Exfiltration Over C2 Channel
  if (hasC2Traffic || permNames.includes('android.permission.INTERNET')) {
    mappings.push({
      tactic: 'Exfiltration',
      tech: 'T1041 - Exfiltration Over C2 Channel',
      techId: 'T1041',
      observed: 'Outbound HTTPS encrypted telemetry and extracted databases sent to remote endpoints',
      confidence: 'High',
    });
  }

  // 3. T1622 - Debugger Evasion
  if (
    evasionFlags.some((e) => e.name.includes('Anti-Debugging') && e.status !== 'None') ||
    patternNames.some((p) => p.includes('Anti-Debugging'))
  ) {
    mappings.push({
      tactic: 'Defense Evasion',
      tech: 'T1622 - Debugger Evasion',
      techId: 'T1622',
      observed: 'TracerPid inspection in /proc/self/status and ptrace detection to evade analysis',
      confidence: 'High',
    });
  }

  // 4. T1417 - Input Capture / Accessibility Abuse
  if (
    patternNames.some((p) => p.includes('Accessibility')) ||
    permNames.includes('android.permission.BIND_ACCESSIBILITY_SERVICE')
  ) {
    mappings.push({
      tactic: 'Credential Access',
      tech: 'T1417 - Input Capture',
      techId: 'T1417',
      observed: 'Accessibility service abuse for keystroke interception and automated overlay clicking',
      confidence: 'High',
    });
  }

  // 5. T1582 - SMS Interception / Telephony Abuse
  if (
    permNames.includes('android.permission.RECEIVE_SMS') ||
    permNames.includes('android.permission.READ_SMS') ||
    permNames.includes('android.permission.SEND_SMS')
  ) {
    mappings.push({
      tactic: 'Collection',
      tech: 'T1582 - SMS Interception',
      techId: 'T1582',
      observed: 'Interception of two-factor authentication (2FA) SMS tokens and background text sending',
      confidence: 'High',
    });
  }

  // 6. T1407 - Download New Code at Runtime
  if (
    patternNames.some((p) => p.includes('Dynamic DexClassLoader') || p.includes('Dynamic Code')) ||
    evasionFlags.some((e) => e.name.includes('Dynamic Code'))
  ) {
    mappings.push({
      tactic: 'Defense Evasion',
      tech: 'T1407 - Download New Code at Runtime',
      techId: 'T1407',
      observed: 'Executes secondary payload loaded dynamically via DexClassLoader from encrypted container',
      confidence: 'High',
    });
  }

  // 7. T1547 - Boot or Logon Initialization (Persistence)
  const bootReceiver = components.find((c) =>
    c.name.includes('Boot') || (c.intentFilters && c.intentFilters.some((f) => f.includes('BOOT_COMPLETED')))
  );
  if (bootReceiver || permNames.includes('android.permission.RECEIVE_BOOT_COMPLETED')) {
    mappings.push({
      tactic: 'Persistence',
      tech: 'T1547 - Boot or Logon Initialization',
      techId: 'T1547',
      observed: 'Registers broadcast receiver for android.intent.action.BOOT_COMPLETED to survive reboot',
      confidence: 'High',
    });
  }

  // 8. T1406 - Obfuscated Files or Information
  if (evasionFlags.some((e) => e.name.includes('Obfuscation') && e.status !== 'None')) {
    mappings.push({
      tactic: 'Defense Evasion',
      tech: 'T1406 - Obfuscated Files or Information',
      techId: 'T1406',
      observed: 'ProGuard/DexGuard class identifier stripping, string encryption, and control flow flattening',
      confidence: 'Medium',
    });
  }

  // Fallback if none matched
  if (mappings.length === 0) {
    mappings.push({
      tactic: 'Discovery',
      tech: 'T1418 - System Information Discovery',
      techId: 'T1418',
      observed: 'Standard device telemetry and network status queries',
      confidence: 'Low',
    });
  }

  return mappings;
}
