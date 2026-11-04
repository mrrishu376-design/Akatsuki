/**
 * AppIntel Pro - Android Malware Analysis & Forensic Types
 */

export interface ComponentFinding {
  type: 'Activity' | 'Service' | 'Receiver' | 'Provider';
  name: string;
  exported: boolean | string;
  risk: string;
  permission?: string;
  intentFilters?: string[];
}

export interface PermissionFinding {
  name: string;
  type: 'Dangerous' | 'Normal' | 'Signature' | 'Special' | 'Unknown';
  desc: string;
  protectionLevel?: string;
}

export interface CodePatternFinding {
  pattern: string;
  desc: string;
  severity: 'Critical' | 'High' | 'Medium' | 'Low' | 'Info';
  snippet?: string;
  occurrences?: number;
}

export interface EvasionFlag {
  name: string;
  status: 'Detected' | 'Confirmed' | 'Present' | 'None' | 'Decoded';
  desc: string;
  confidence?: string;
}

export interface NetworkIoc {
  type: 'Domain' | 'IP Address' | 'URL' | 'File Hash' | 'DNS';
  value: string;
  risk: string;
  country?: string;
  port?: number | string;
  reputation?: string;
}

export interface CertInfo {
  issuer: string;
  subject?: string;
  validFrom: string;
  validTo: string;
  serial: string;
  sha1Fingerprint: string;
  sha256Fingerprint?: string;
  signingScheme?: string;
  isSelfSigned?: boolean;
}

export interface SbomItem {
  lib: string;
  version: string;
  vuln: string;
  severity: 'Critical' | 'High' | 'Medium' | 'Low';
  cveId?: string;
  cwe?: string;
  reference?: string;
  fixedIn?: string;
}

export interface MitreMapping {
  tactic: string;
  tech: string;
  techId?: string;
  observed: string;
  confidence?: 'High' | 'Medium' | 'Low';
}

export interface SandboxExecution {
  containerId: string;
  androidVersion: string;
  apiLevel: number;
  status: 'READY' | 'RUNNING' | 'COMPLETED' | 'STOPPED' | 'ERROR';
  terminalLogs: string[];
  fileSystem: string[];
  apiHooks: string[];
  networkTraffic: string[];
  durationSeconds?: number;
}

export interface ForensicCase {
  id: string | number;
  filename: string;
  fileSize?: number;
  fileSizeBytesFormatted?: string;
  pkg: string;
  classification: string;
  riskScore: number;
  md5: string;
  sha1?: string;
  sha256: string;
  version: string;
  minSdk?: string | number;
  targetSdk?: string | number;
  signer: string;
  uploadedAt: string;
  isDemo?: boolean;
  components: ComponentFinding[];
  permissions: PermissionFinding[];
  codePatterns: CodePatternFinding[];
  sandboxLogs: string[];
  fileSystem: string[];
  apiHooks: string[];
  networkTraffic: string[];
  evasionFlags: EvasionFlag[];
  iocs: NetworkIoc[];
  certInfo: CertInfo;
  sbom: SbomItem[];
  threatFactors: string[];
  mitre: MitreMapping[];
  yaraMatches?: string[];
  dexClassesCount?: number;
  dexStringsCount?: number;
}

export interface GlobalIocItem {
  id?: string;
  type: 'Domain' | 'IP Address' | 'File Hash (MD5)' | 'File Hash (SHA256)' | 'URL';
  val: string;
  malware: string;
  conf: string;
  source?: string;
  firstSeen?: string;
  status?: string;
}

export interface UserSession {
  email: string;
  isAuthenticated: boolean;
  role: string;
  division: string;
  sessionExpiry: number;
}
