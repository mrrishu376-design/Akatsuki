package com.example

import android.content.Context
import androidx.room.Room
import androidx.test.core.app.ApplicationProvider
import com.example.data.analyzer.ComponentSummary
import com.example.data.analyzer.ManifestAnalysisInput
import com.example.data.analyzer.SecurityRiskCalculator
import com.example.data.local.AppDatabase
import com.example.data.model.RiskLabel
import com.example.data.model.Severity
import kotlinx.coroutines.test.runTest
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class SecurityRiskCalculatorTest {

  private lateinit var database: AppDatabase
  private lateinit var calculator: SecurityRiskCalculator

  @Before
  fun setUp() {
    val context = ApplicationProvider.getApplicationContext<Context>()
    database = Room.inMemoryDatabaseBuilder(context, AppDatabase::class.java)
      .allowMainThreadQueries()
      .build()
    calculator = SecurityRiskCalculator(database)
  }

  @After
  fun tearDown() {
    database.close()
  }

  @Test
  fun `evaluateRisk calculates elevated score and generates findings for vulnerable manifest`() {
    val vulnerableInput = ManifestAnalysisInput(
      appName = "Insecure Banking",
      packageName = "com.vulnerable.bank",
      isDebuggable = true,
      usesCleartextTraffic = true,
      allowsBackup = true,
      targetSdk = 29,
      requestedPermissions = listOf(
        "android.permission.ACCESS_BACKGROUND_LOCATION",
        "android.permission.SEND_SMS",
        "android.permission.RECORD_AUDIO",
        "android.permission.INTERNET"
      ),
      activities = listOf(
        ComponentSummary(name = "com.vulnerable.bank.TransferActivity", isExported = true)
      ),
      services = listOf(
        ComponentSummary(name = "com.vulnerable.bank.SyncService", isExported = true)
      )
    )

    val result = calculator.evaluateRisk(vulnerableInput)

    // Score checks
    assertTrue("Risk score should be critical", result.scanRecord.riskScore >= 75)
    assertEquals(RiskLabel.CRITICAL, result.scanRecord.riskLabel)

    // Verify specific rule findings
    val ruleIds = result.findings.map { it.ruleId }
    assertTrue("Should flag debuggable", ruleIds.contains("SEC-CONF-DEBUG"))
    assertTrue("Should flag cleartext traffic", ruleIds.contains("SEC-NET-CLEARTEXT"))
    assertTrue("Should flag allowBackup", ruleIds.contains("SEC-CONF-BACKUP"))
    assertTrue("Should flag outdated SDK", ruleIds.contains("SEC-CONF-OUTDATED-SDK"))
    assertTrue("Should flag exported activity", ruleIds.contains("SEC-COMP-ACT-EXP"))
    assertTrue("Should flag exported service", ruleIds.contains("SEC-COMP-SRV-EXP"))
    assertTrue("Should flag SMS exfiltration compound vector", ruleIds.contains("SEC-COMPOUND-SMS-EXFIL"))

    // Verify executive report
    assertNotNull(result.report)
    assertTrue(result.report.executiveSummary.contains("Insecure Banking"))
  }

  @Test
  fun `evaluateRisk produces safe baseline for hardened application`() {
    val hardenedInput = ManifestAnalysisInput(
      appName = "Hardened Enterprise App",
      packageName = "com.hardened.vault",
      isDebuggable = false,
      usesCleartextTraffic = false,
      allowsBackup = false,
      targetSdk = 34,
      requestedPermissions = listOf("android.permission.INTERNET"),
      activities = listOf(
        ComponentSummary(name = "com.hardened.vault.MainActivity", isExported = true)
      )
    )

    val result = calculator.evaluateRisk(hardenedInput)

    assertEquals(0, result.scanRecord.riskScore)
    assertEquals(RiskLabel.SAFE, result.scanRecord.riskLabel)
    assertTrue("No critical findings in hardened build", result.findings.none { it.severity == Severity.CRITICAL })
  }

  @Test
  fun `calculateAndPersist saves and retrieves complete analysis in Room database`() = runTest {
    val input = ManifestAnalysisInput(
      appName = "Test Auditor APK",
      packageName = "com.audit.testapp",
      isDebuggable = true,
      usesCleartextTraffic = true,
      requestedPermissions = listOf("android.permission.RECORD_AUDIO", "android.permission.INTERNET"),
      sha256Hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
      ownerId = "auditor_123"
    )

    // Calculate and persist
    val assessment = calculator.calculateAndPersist(input)
    val scanId = assessment.scanRecord.id

    // Verify scan retrieval from Room
    val retrievedScan = calculator.getPersistedScan(scanId)
    assertNotNull("Scan should be persisted in Room", retrievedScan)
    assertEquals("Test Auditor APK", retrievedScan?.appName)
    assertEquals("auditor_123", retrievedScan?.ownerId)
    assertEquals(assessment.scanRecord.riskScore, retrievedScan?.riskScore)

    // Verify findings retrieval from Room
    val retrievedFindings = calculator.getScanFindings(scanId)
    assertTrue("Findings should be stored in Room", retrievedFindings.isNotEmpty())
    assertTrue(retrievedFindings.any { it.ruleId == "SEC-CONF-DEBUG" })

    // Verify report retrieval from Room
    val retrievedReport = calculator.getScanReport(scanId)
    assertNotNull("Forensic report should be stored in Room", retrievedReport)
    assertEquals(assessment.scanRecord.riskScore, retrievedReport?.riskScore)

    // Verify delete operation
    calculator.deleteScan(scanId)
    assertNull("Scan should be deleted from Room", calculator.getPersistedScan(scanId))
    assertTrue("Findings should be deleted from Room", calculator.getScanFindings(scanId).isEmpty())
  }
}
