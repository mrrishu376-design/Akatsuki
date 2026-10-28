package com.example

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import com.example.data.local.AppDatabase
import com.example.data.model.ForensicReport
import com.example.data.model.RiskLabel
import com.example.data.model.ScanFinding
import com.example.data.model.ScanRecord
import com.example.data.model.Severity
import com.example.data.repository.AuthRepository
import com.example.data.repository.CloudSyncState
import com.example.data.repository.SupabaseForensicsRepository
import kotlinx.coroutines.runBlocking
import org.json.JSONObject
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import java.util.UUID

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class SupabaseForensicsRepositoryTest {

  private lateinit var context: Context
  private lateinit var db: AppDatabase
  private lateinit var authRepository: AuthRepository
  private lateinit var repository: SupabaseForensicsRepository

  @Before
  fun setup() {
    context = ApplicationProvider.getApplicationContext()
    db = AppDatabase.getDatabase(context)
    authRepository = AuthRepository(context)
    repository = SupabaseForensicsRepository(context, authRepository)
  }

  @After
  fun tearDown() {
    db.close()
  }

  @Test
  fun testIsConfiguredLogic() {
    // Default values are placeholders
    authRepository.supabaseUrl = "https://your-project.supabase.co"
    authRepository.supabaseAnonKey = "sb_publishable_anon_key_placeholder"
    assertFalse("Placeholders should not be marked as configured", repository.isConfigured())

    // Valid enterprise config
    authRepository.supabaseUrl = "https://cyberdefense-prod.supabase.co"
    authRepository.supabaseAnonKey = "eyJhGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.livekey"
    assertTrue("Live credentials should be marked as configured", repository.isConfigured())
  }

  @Test
  fun testBuildDossierJsonStructure() {
    val scanId = UUID.randomUUID().toString()
    val scan = ScanRecord(
      id = scanId,
      ownerId = "usr_01",
      appName = "BankingTrojanTarget",
      packageName = "com.suspicious.payload",
      versionName = "2.1.0",
      versionCode = 42,
      originalFilename = "payload_sample.apk",
      fileSizeBytes = 5120000L,
      sha256Hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
      md5Hash = "d41d8cd98f00b204e9800998ecf8427e",
      riskScore = 88,
      riskLabel = RiskLabel.CRITICAL
    )

    val findings = listOf(
      ScanFinding(
        scanId = scanId,
        ruleId = "HEUR_DCL_DEX_01",
        category = "DYNAMIC_CODE_LOADING",
        title = "DexClassLoader Dynamic Loading",
        severity = Severity.CRITICAL,
        description = "Dynamic code loading detected from writable directory",
        evidence = "dalvik.system.DexClassLoader",
        recommendation = "Enforce read-only dex execution",
        cweId = "CWE-912"
      )
    )

    val report = ForensicReport(
      scanId = scanId,
      ownerId = "usr_01",
      reportTitle = "Formal Static Forensic Audit: BankingTrojanTarget",
      analystName = "Lead Auditor",
      riskScore = 88,
      riskLabel = RiskLabel.CRITICAL,
      executiveSummary = "Severe indicators of weaponized dropper identified.",
      methodology = "Static Bytecode & Dalvik Decompilation"
    )

    val jsonString = repository.buildDossierJson(scan, findings, report)
    assertNotNull(jsonString)

    val json = JSONObject(jsonString)
    assertEquals("2.4.0", json.getString("schemaVersion"))
    assertEquals("PS-02 Android Forensic Security Platform", json.getString("platform"))

    val targetArtifact = json.getJSONObject("targetArtifact")
    assertEquals(scanId, targetArtifact.getString("scanId"))
    assertEquals("com.suspicious.payload", targetArtifact.getString("packageName"))
    assertEquals(88, targetArtifact.getInt("riskScore"))
    assertEquals("CRITICAL", targetArtifact.getString("riskLabel"))

    val findingsArray = json.getJSONArray("findings")
    assertEquals(1, findingsArray.length())
    val finding0 = findingsArray.getJSONObject(0)
    assertEquals("HEUR_DCL_DEX_01", finding0.getString("ruleId"))
    assertEquals("CWE-912", finding0.getString("cweId"))
    assertEquals("CRITICAL", finding0.getString("severity"))
  }

  @Test
  fun testUploadForensicDossierOfflineSandbox() = runBlocking {
    val scanId = UUID.randomUUID().toString()
    val scan = ScanRecord(
      id = scanId,
      ownerId = "usr_analyst",
      appName = "TargetApp",
      packageName = "org.sample.audit",
      originalFilename = "audit.apk",
      fileSizeBytes = 204800L,
      sha256Hash = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
      riskScore = 45,
      riskLabel = RiskLabel.MEDIUM
    )

    db.scanDao().insertScan(scan)
    db.findingDao().insertFindings(
      listOf(
        ScanFinding(
          scanId = scanId,
          ruleId = "PERM_SMS",
          category = "PERMISSIONS",
          title = "Send SMS Permission",
          severity = Severity.HIGH,
          description = "App can trigger premium SMS",
          evidence = "android.permission.SEND_SMS",
          recommendation = "Remove unless core function"
        )
      )
    )

    val result = repository.uploadForensicDossier(scanId)
    assertTrue("Upload should succeed", result.isSuccess)

    val upload = result.getOrNull()
    assertNotNull(upload)
    assertEquals("forensic-artifacts", upload?.bucketName)
    assertTrue("Path should contain scan ID", upload?.storagePath?.contains(scanId) == true)
    assertTrue("Should be marked simulated in sandbox mode", upload?.isSimulated == true)
    assertNotNull(upload?.sha256Checksum)

    // Check reactive sync state
    val state = repository.syncState.value
    assertTrue("Sync state should be Success", state is CloudSyncState.Success)
  }

  @Test
  fun testUploadForensicPdfSandbox() = runBlocking {
    val scanId = UUID.randomUUID().toString()
    val dummyPdfBytes = "%PDF-1.4\n%PS-02 Forensic Test\n%%EOF".toByteArray()

    val result = repository.uploadForensicPdf(scanId, "evidence_dossier.pdf", dummyPdfBytes)
    assertTrue(result.isSuccess)

    val upload = result.getOrNull()
    assertNotNull(upload)
    assertEquals("scans/$scanId/pdf/evidence_dossier.pdf", upload?.storagePath)
    assertTrue(upload?.fileSizeBytes == dummyPdfBytes.size.toLong())
  }

  @Test
  fun testListStoredArtifacts() = runBlocking {
    val result = repository.listStoredArtifacts()
    assertTrue(result.isSuccess)

    val items = result.getOrNull()
    assertNotNull(items)
    assertTrue("Should contain sample artifacts", items?.isNotEmpty() == true)
  }

  @Test
  fun testResetSyncState() {
    repository.resetSyncState()
    assertEquals(CloudSyncState.Idle, repository.syncState.value)
  }
}
