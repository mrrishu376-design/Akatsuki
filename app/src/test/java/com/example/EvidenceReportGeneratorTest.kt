package com.example

import android.content.Context
import androidx.room.Room
import androidx.test.core.app.ApplicationProvider
import com.example.data.analyzer.EvidenceReportGenerator
import com.example.data.local.AppDatabase
import com.example.data.model.ForensicReport
import com.example.data.model.RiskLabel
import com.example.data.model.ScanFinding
import com.example.data.model.ScanRecord
import com.example.data.model.Severity
import kotlinx.coroutines.test.runTest
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import java.io.File
import java.util.UUID

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class EvidenceReportGeneratorTest {

  private lateinit var context: Context
  private lateinit var database: AppDatabase
  private lateinit var reportGenerator: EvidenceReportGenerator

  @Before
  fun setUp() {
    context = ApplicationProvider.getApplicationContext<Context>()
    database = Room.inMemoryDatabaseBuilder(context, AppDatabase::class.java)
      .allowMainThreadQueries()
      .build()
    reportGenerator = EvidenceReportGenerator(context, database)
  }

  @After
  fun tearDown() {
    database.close()
  }

  @Test
  fun `compilePdf generates valid structured PDF file from security models`() {
    val scanId = UUID.randomUUID().toString()
    val scan = ScanRecord(
      id = scanId,
      ownerId = "auditor_secops_01",
      appName = "Target Test App",
      packageName = "com.forensic.testapp",
      versionName = "2.1.0",
      versionCode = 21,
      originalFilename = "target-test-app.apk",
      fileSizeBytes = 12450000L,
      sha256Hash = "8f434346648f6b96df89dda901c5176b10a6d83961dd3c1ac88b59b2dc327aa4",
      riskScore = 82,
      riskLabel = RiskLabel.CRITICAL,
      criticalCount = 2,
      highCount = 1,
      mediumCount = 1,
      isDebuggable = true,
      usesCleartextTraffic = true,
      allowsBackup = true,
      targetSdk = 31
    )

    val findings = listOf(
      ScanFinding(
        scanId = scanId,
        ruleId = "SEC-CONF-DEBUG",
        category = "MANIFEST_CONFIG",
        title = "Application is Debuggable in Production",
        severity = Severity.CRITICAL,
        description = "android:debuggable flag is enabled, exposing application memory to ADB debugging.",
        evidence = "android:debuggable=\"true\"",
        recommendation = "Disable debuggable flag in release builds.",
        cweId = "CWE-215"
      ),
      ScanFinding(
        scanId = scanId,
        ruleId = "SEC-NET-CLEARTEXT",
        category = "NETWORK_SECURITY",
        title = "Cleartext HTTP Traffic Permitted",
        severity = Severity.HIGH,
        description = "Permits unencrypted communications over HTTP, vulnerable to MITM interception.",
        evidence = "android:usesCleartextTraffic=\"true\"",
        recommendation = "Enforce HTTPS communication and certificate pinning.",
        cweId = "CWE-319"
      )
    )

    val report = ForensicReport(
      id = "rep_" + UUID.randomUUID().toString().take(12),
      scanId = scanId,
      ownerId = "auditor_secops_01",
      reportTitle = "PS-02 Security Audit: Target Test App (com.forensic.testapp)",
      analystName = "Senior Forensic Auditor",
      toolVersion = "PS-02 Forensic Engine v3.0",
      riskScore = 82,
      riskLabel = RiskLabel.CRITICAL,
      executiveSummary = "Static security evaluation of 'Target Test App' identified 2 Critical and 1 High findings.",
      methodology = "Automated static bytecode and manifest inspection.",
      limitationsDisclaimer = "DISCLAIMER: Static analysis only. Does not guarantee dynamic execution safety."
    )

    val pdfFile = reportGenerator.compilePdf(scan, findings, report)

    assertNotNull(pdfFile)
    assertTrue("PDF file should exist on filesystem", pdfFile.exists())
    assertTrue("PDF file should have non-zero byte size", pdfFile.length() > 0)
    assertTrue("PDF filename should match convention", pdfFile.name.endsWith(".pdf"))
    assertTrue("PDF filename should contain sanitized app label", pdfFile.name.contains("Target_Test_App"))
  }

  @Test
  fun `generatePdf compiles analysis results directly from Room database`() = runTest {
    val scanId = UUID.randomUUID().toString()
    val scan = ScanRecord(
      id = scanId,
      ownerId = "usr_analyst_99",
      appName = "Room Persisted Insecure Bank",
      packageName = "com.insecure.bank.db",
      versionName = "1.0.4",
      versionCode = 4,
      originalFilename = "insecure-bank.apk",
      fileSizeBytes = 8400000L,
      sha256Hash = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
      riskScore = 90,
      riskLabel = RiskLabel.CRITICAL,
      criticalCount = 3,
      highCount = 1,
      isDebuggable = true,
      usesCleartextTraffic = true,
      allowsBackup = true,
      targetSdk = 30
    )

    val findings = listOf(
      ScanFinding(
        scanId = scanId,
        ruleId = "SEC-STR-AWS-KEY",
        category = "SECRETS_STRINGS",
        title = "Hardcoded AWS Access Key in DEX",
        severity = Severity.CRITICAL,
        description = "Unencrypted AWS credential detected in bytecode.",
        evidence = "AKIAIOSFODNN7EXAMPLE",
        recommendation = "Revoke key immediately via AWS IAM.",
        cweId = "CWE-798"
      )
    )

    val report = ForensicReport(
      id = "rep_room_" + UUID.randomUUID().toString().take(8),
      scanId = scanId,
      ownerId = "usr_analyst_99",
      reportTitle = "PS-02 Security Audit: Room Persisted Insecure Bank",
      analystName = "Lead Forensic Specialist",
      toolVersion = "PS-02 Static Forensic Analyzer v2.4.0",
      riskScore = 90,
      riskLabel = RiskLabel.CRITICAL,
      executiveSummary = "Severe credentials leakage and debug capabilities detected.",
      methodology = "Automated static forensic evaluation.",
      limitationsDisclaimer = "DISCLAIMER: Static analysis only."
    )

    // Insert directly into Room database
    database.scanDao().insertScan(scan)
    database.findingDao().insertFindings(findings)
    database.reportDao().insertReport(report)

    // Call generatePdf using scanId from Room
    val generatedPdf = reportGenerator.generatePdf(scanId)

    assertNotNull(generatedPdf)
    assertTrue("Generated PDF should exist", generatedPdf.exists())
    assertTrue("Generated PDF length should be substantial", generatedPdf.length() > 500)
  }
}
