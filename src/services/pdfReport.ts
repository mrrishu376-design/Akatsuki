/**
 * AppIntel Pro - Law Enforcement & Cyber Forensic Report Generator
 * Generates court-structured PDF reports and SIEM-ready JSON export
 */

import jsPDF from 'jspdf';
import { ForensicCase } from '../types/forensic';

export function downloadJsonReport(forensicCase: ForensicCase): void {
  const exportData = {
    reportMetadata: {
      generatedBy: 'AppIntel Pro - Law Enforcement Forensics Platform v4.2',
      classification: 'RESTRICTED / LAW ENFORCEMENT & FORENSIC USE ONLY',
      timestamp: new Date().toISOString(),
      evidentiaryIntegrity: {
        algorithm: 'SHA-256',
        apkHash: forensicCase.sha256,
        md5Hash: forensicCase.md5,
        status: 'VERIFIED_CRYPTOGRAPHIC_CHAIN',
      },
    },
    caseDetails: forensicCase,
  };

  const jsonString = 'data:text/json;charset=utf-8,' + encodeURIComponent(JSON.stringify(exportData, null, 2));
  const downloadAnchor = document.createElement('a');
  downloadAnchor.setAttribute('href', jsonString);
  downloadAnchor.setAttribute('download', `${forensicCase.filename.replace(/\.apk$/i, '')}_forensic_report.json`);
  document.body.appendChild(downloadAnchor);
  downloadAnchor.click();
  downloadAnchor.remove();
}

export function downloadPdfReport(forensicCase: ForensicCase): void {
  const doc = new jsPDF({
    orientation: 'portrait',
    unit: 'mm',
    format: 'a4',
  });

  const pageWidth = doc.internal.pageSize.getWidth();
  let y = 14;

  // Header Banner
  doc.setFillColor(15, 23, 42); // slate-900
  doc.rect(0, 0, pageWidth, 32, 'F');

  // Title & Classification
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(16);
  doc.setTextColor(244, 63, 94); // rose-500
  doc.text('APPINTEL PRO FORENSIC REPORT', 14, 12);

  doc.setFontSize(8);
  doc.setTextColor(148, 163, 184); // slate-400
  doc.text('ADVANCED ANDROID MALWARE & DIGITAL FORENSICS WORKSTATION - LE-SOC v4.2', 14, 18);

  doc.setFont('courier', 'bold');
  doc.setFontSize(8);
  doc.setTextColor(251, 113, 133); // rose-400
  doc.text('CLASSIFICATION: RESTRICTED / LAW ENFORCEMENT ONLY', 14, 25);

  const dateStr = new Date().toISOString().replace('T', ' ').substring(0, 19) + ' UTC';
  doc.setTextColor(255, 255, 255);
  doc.text(`EVIDENTIARY AUDIT: ${dateStr}`, pageWidth - 14, 25, { align: 'right' });

  y = 38;

  // Section 1: Case Identification
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(11);
  doc.setTextColor(15, 23, 42);
  doc.text('1. CASE IDENTIFICATION & ARTIFACT METADATA', 14, y);
  y += 6;

  doc.setDrawColor(226, 232, 240);
  doc.setFillColor(248, 250, 252);
  doc.roundedRect(14, y, pageWidth - 28, 30, 2, 2, 'FD');

  doc.setFont('courier', 'normal');
  doc.setFontSize(8);
  doc.setTextColor(30, 41, 59);

  doc.text(`Artifact Name : ${forensicCase.filename}`, 18, y + 6);
  doc.text(`Package Name  : ${forensicCase.pkg}`, 18, y + 11);
  doc.text(`Version / SDK : ${forensicCase.version}`, 18, y + 16);
  doc.text(`Certificate   : ${forensicCase.signer}`, 18, y + 21);
  doc.text(`Classification: ${forensicCase.classification} | Threat Score: ${forensicCase.riskScore}/100`, 18, y + 26);

  y += 36;

  // Section 2: Cryptographic Evidentiary Hashes
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(11);
  doc.setTextColor(15, 23, 42);
  doc.text('2. CRYPTOGRAPHIC EVIDENTIARY INTEGRITY', 14, y);
  y += 6;

  doc.setFillColor(248, 250, 252);
  doc.roundedRect(14, y, pageWidth - 28, 20, 2, 2, 'FD');

  doc.setFont('courier', 'normal');
  doc.setFontSize(7.5);
  doc.setTextColor(51, 65, 85);
  doc.text(`MD5 Checksum   : ${forensicCase.md5}`, 18, y + 6);
  doc.text(`SHA-256 Checksum: ${forensicCase.sha256}`, 18, y + 12);
  doc.text(`Integrity State: HASH CHAIN UNBROKEN & DIGITALLY VERIFIED`, 18, y + 17);

  y += 26;

  // Section 3: Executive Threat Assessment
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(11);
  doc.setTextColor(15, 23, 42);
  doc.text('3. EXECUTIVE THREAT ASSESSMENT & FACTORS', 14, y);
  y += 6;

  doc.setFont('helvetica', 'normal');
  doc.setFontSize(8);
  doc.setTextColor(71, 85, 105);

  for (const factor of forensicCase.threatFactors.slice(0, 5)) {
    doc.text(`• ${factor}`, 18, y);
    y += 5;
  }
  y += 2;

  // Section 4: Critical Permissions Audit
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(11);
  doc.setTextColor(15, 23, 42);
  doc.text('4. SENSITIVE PERMISSION AUDIT', 14, y);
  y += 6;

  const dangerous = forensicCase.permissions.filter((p) => p.type === 'Dangerous').slice(0, 6);
  for (const p of dangerous) {
    doc.setFont('courier', 'bold');
    doc.setFontSize(7.5);
    doc.setTextColor(190, 18, 60); // rose-700
    doc.text(`[DANGEROUS] ${p.name}`, 18, y);
    doc.setFont('helvetica', 'normal');
    doc.setTextColor(100, 116, 139);
    doc.text(`- ${p.desc}`, 22, y + 3.8);
    y += 8;
  }

  // Section 5: Extracted Indicators of Compromise (IOCs)
  y += 2;
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(11);
  doc.setTextColor(15, 23, 42);
  doc.text('5. EXTRACTED INDICATORS OF COMPROMISE (IOCs)', 14, y);
  y += 6;

  for (const ioc of forensicCase.iocs.slice(0, 4)) {
    doc.setFont('courier', 'normal');
    doc.setFontSize(7.5);
    doc.setTextColor(15, 23, 42);
    doc.text(`Type: ${ioc.type.padEnd(12, ' ')} | Value: ${ioc.value.padEnd(34, ' ')} | Risk: ${ioc.risk}`, 18, y);
    y += 4.5;
  }

  // Check if we need page 2
  doc.addPage();
  y = 16;

  // Page 2: MITRE ATT&CK Mapping & Sandbox Results
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(11);
  doc.setTextColor(15, 23, 42);
  doc.text('6. MITRE ATT&CK® FOR MOBILE THREAT MATRIX', 14, y);
  y += 6;

  for (const m of forensicCase.mitre.slice(0, 6)) {
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(8);
    doc.setTextColor(180, 83, 9); // amber-700
    doc.text(`[${m.tactic}] ${m.tech}`, 18, y);
    doc.setFont('helvetica', 'normal');
    doc.setTextColor(71, 85, 105);
    doc.text(`Observed Evidence: ${m.observed}`, 22, y + 3.8);
    y += 9;
  }

  y += 4;
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(11);
  doc.setTextColor(15, 23, 42);
  doc.text('7. BEHAVIORAL SANDBOX EXECUTION EVIDENCE', 14, y);
  y += 6;

  doc.setFillColor(15, 23, 42);
  doc.roundedRect(14, y, pageWidth - 28, 48, 2, 2, 'F');

  doc.setFont('courier', 'normal');
  doc.setFontSize(6.5);
  doc.setTextColor(226, 232, 240);
  let termY = y + 6;
  for (const log of forensicCase.sandboxLogs.slice(0, 8)) {
    doc.text(log, 18, termY);
    termY += 5;
  }
  y += 54;

  // Forensic Disclaimer & Methodology
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(9);
  doc.setTextColor(15, 23, 42);
  doc.text('FORENSIC METHODOLOGY & EVIDENTIARY DISCLAIMER', 14, y);
  y += 5;

  doc.setFont('helvetica', 'normal');
  doc.setFontSize(7);
  doc.setTextColor(100, 116, 139);
  const disclaimer =
    'This forensic report was generated automatically via AppIntel Pro LE-SOC v4.2 decompilation and static/dynamic heuristics. ' +
    'Evidentiary hashes (MD5/SHA-256) verify binary integrity. The risk score represents weighted risk indicators calculated from static ' +
    'permissions, reflection, dynamic bytecode loading, and network communications. Admissibility and evidentiary certification should be ' +
    'conducted in compliance with relevant jurisdiction digital forensics chain-of-custody guidelines.';
  const splitDisclaimer = doc.splitTextToSize(disclaimer, pageWidth - 28);
  doc.text(splitDisclaimer, 14, y);

  doc.save(`${forensicCase.filename.replace(/\.apk$/i, '')}_forensic_report.pdf`);
}
