package com.example.data.analyzer

import android.content.Context
import androidx.room.withTransaction
import com.example.data.local.AppDatabase
import com.example.data.local.FindingDao
import com.example.data.local.ReportDao
import com.example.data.local.ScanDao
import com.example.data.model.ForensicReport
import com.example.data.model.RiskLabel
import com.example.data.model.ScanFinding
import com.example.data.model.ScanRecord
import com.example.data.model.ScanStatus
import com.example.data.model.Severity
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.util.UUID

/**
 * Summary descriptor for an Android application component (Activity, Service, Receiver, Provider).
 */
data class ComponentSummary(
  val name: String,
  val isExported: Boolean,
  val permissionRequired: String? = null
)

/**
 * Encapsulates static input extracted from an Android APK manifest and package headers.
 */
data class ManifestAnalysisInput(
  val appName: String,
  val packageName: String,
  val versionName: String = "1.0.0",
  val versionCode: Long = 1L,
  val targetSdk: Int = 34,
  val minSdk: Int = 24,
  val isDebuggable: Boolean = false,
  val allowsBackup: Boolean = true,
  val usesCleartextTraffic: Boolean = false,
  val isTestOnly: Boolean = false,
  val requestedPermissions: List<String> = emptyList(),
  val activities: List<ComponentSummary> = emptyList(),
  val services: List<ComponentSummary> = emptyList(),
  val receivers: List<ComponentSummary> = emptyList(),
  val providers: List<ComponentSummary> = emptyList(),
  val sha256Hash: String = "",
  val md5Hash: String = "",
  val fileSizeBytes: Long = 0L,
  val originalFilename: String = "app-release.apk",
  val ownerId: String = "usr_secops",
  val isDemoData: Boolean = false
)

/**
 * Transparent scoring breakdown for security audits.
 */
data class ScoreBreakdownDetails(
  val permissionsScore: Int,
  val manifestConfigScore: Int,
  val componentsScore: Int,
  val compoundThreatScore: Int,
  val rawTotalScore: Int,
  val finalCappedScore: Int,
  val riskLabel: RiskLabel,
  val formulaExplanation: String
)

/**
 * Complete evaluation result containing the computed risk score, findings, and dossier.
 */
data class RiskAssessmentResult(
  val scanRecord: ScanRecord,
  val findings: List<ScanFinding>,
  val report: ForensicReport,
  val scoreBreakdown: ScoreBreakdownDetails
)

/**
 * Security Risk Calculator for Android applications.
 *
 * Evaluates declared Android permissions, insecure manifest configuration flags,
 * and unprotected exported components to generate a normalized 0-100 risk score.
 * Integrates directly with Room Database for persistence.
 */
class SecurityRiskCalculator(
  private val scanDao: ScanDao,
  private val findingDao: FindingDao,
  private val reportDao: ReportDao,
  private val database: AppDatabase? = null
) {

  constructor(database: AppDatabase) : this(
    scanDao = database.scanDao(),
    findingDao = database.findingDao(),
    reportDao = database.reportDao(),
    database = database
  )

  constructor(context: Context) : this(AppDatabase.getDatabase(context))

  // Threat weights definition
  companion object {
    const val WEIGHT_CRITICAL = 25
    const val WEIGHT_HIGH = 15
    const val WEIGHT_MEDIUM = 8
    const val WEIGHT_LOW = 3

    // Known dangerous permissions catalog mapped to Threat Profile
    private val DANGEROUS_PERMS = mapOf(
      "android.permission.ACCESS_BACKGROUND_LOCATION" to Triple(
        Severity.CRITICAL,
        "Continuous Background Geolocation",
        "Tracks physical coordinates persistently even when the application is backgrounded."
      ),
      "android.permission.SEND_SMS" to Triple(
        Severity.CRITICAL,
        "Unauthorized Premium Messaging",
        "Can dispatch SMS messages in the background, risking financial fraud."
      ),
      "android.permission.RECEIVE_SMS" to Triple(
        Severity.CRITICAL,
        "SMS Interception Vector",
        "Capable of intercepting 2FA OTP security verification tokens before user review."
      ),
      "android.permission.SYSTEM_ALERT_WINDOW" to Triple(
        Severity.HIGH,
        "Tapjacking & Overlay Attack",
        "Allows rendering arbitrary windows over other applications to trick user taps."
      ),
      "android.permission.REQUEST_INSTALL_PACKAGES" to Triple(
        Severity.HIGH,
        "Arbitrary Package Dropper",
        "Can trigger installation of secondary executable APKs without store oversight."
      ),
      "android.permission.RECORD_AUDIO" to Triple(
        Severity.HIGH,
        "Covert Microphone Capture",
        "Enables background audio recording without ongoing call indicator."
      ),
      "android.permission.CAMERA" to Triple(
        Severity.HIGH,
        "Camera Surveillance",
        "Captures photos and video streams from front/rear device sensors."
      ),
      "android.permission.READ_CONTACTS" to Triple(
        Severity.HIGH,
        "Address Book Harvesting",
        "Extracts social graph, emails, and personal contacts from device storage."
      ),
      "android.permission.READ_CALL_LOG" to Triple(
        Severity.HIGH,
        "Call Metadata Surveillance",
        "Extracts incoming and outgoing telephone numbers and call durations."
      ),
      "android.permission.READ_SMS" to Triple(
        Severity.HIGH,
        "Private Message Reading",
        "Reads stored and inbound SMS messages containing private communications."
      ),
      "android.permission.ACCESS_FINE_LOCATION" to Triple(
        Severity.MEDIUM,
        "Precise GPS Tracking",
        "Accesses high-accuracy satellite and network geolocation data."
      ),
      "android.permission.WRITE_EXTERNAL_STORAGE" to Triple(
        Severity.MEDIUM,
        "Shared Storage Modification",
        "Legacy broad storage permission allowing cross-application file manipulation."
      ),
      "android.permission.READ_EXTERNAL_STORAGE" to Triple(
        Severity.LOW,
        "Shared Storage Read",
        "Legacy read permission for shared photos, documents, and downloads."
      ),
      "android.permission.RECEIVE_BOOT_COMPLETED" to Triple(
        Severity.MEDIUM,
        "Boot-Time Persistence",
        "Registers auto-launch capability upon device restart."
      )
    )
  }

  /**
   * Pure calculation function: evaluates permissions, configuration flags, and components,
   * returning an in-memory [RiskAssessmentResult].
   */
  fun evaluateRisk(
    input: ManifestAnalysisInput,
    scanId: String = UUID.randomUUID().toString()
  ): RiskAssessmentResult {
    val findings = mutableListOf<ScanFinding>()
    var permPoints = 0
    var manifestPoints = 0
    var componentPoints = 0
    var compoundPoints = 0

    // 1. Evaluate Declared Permissions
    val declaredSet = input.requestedPermissions.toSet()
    for (perm in input.requestedPermissions) {
      val catalogEntry = DANGEROUS_PERMS[perm]
      if (catalogEntry != null) {
        val (severity, threatTitle, description) = catalogEntry
        val points = when (severity) {
          Severity.CRITICAL -> WEIGHT_CRITICAL
          Severity.HIGH -> WEIGHT_HIGH
          Severity.MEDIUM -> WEIGHT_MEDIUM
          Severity.LOW -> WEIGHT_LOW
          Severity.INFO -> 0
        }
        permPoints += points

        if (severity == Severity.CRITICAL || severity == Severity.HIGH || severity == Severity.MEDIUM) {
          val shortName = perm.substringAfterLast(".")
          findings.add(
            ScanFinding(
              scanId = scanId,
              ruleId = "SEC-PERM-${shortName.take(8).uppercase()}",
              category = "PERMISSIONS",
              title = "Elevated Capability: $threatTitle",
              severity = severity,
              description = "Application declared permission '$perm'. $description",
              evidence = "<uses-permission android:name=\"$perm\" />",
              recommendation = "Adhere to the principle of least privilege. Use runtime prompts or scoped APIs.",
              cweId = "CWE-250"
            )
          )
        }
      }
    }

    val hasInternet = declaredSet.contains("android.permission.INTERNET")
    val hasSms = declaredSet.contains("android.permission.READ_SMS") ||
        declaredSet.contains("android.permission.RECEIVE_SMS") ||
        declaredSet.contains("android.permission.SEND_SMS")
    val hasAudio = declaredSet.contains("android.permission.RECORD_AUDIO")
    val hasCamera = declaredSet.contains("android.permission.CAMERA")
    val hasLocation = declaredSet.contains("android.permission.ACCESS_FINE_LOCATION") || declaredSet.contains("android.permission.ACCESS_BACKGROUND_LOCATION")
    val hasBoot = declaredSet.contains("android.permission.RECEIVE_BOOT_COMPLETED")

    if (hasSms && hasInternet) {
      compoundPoints += 15
      findings.add(
        ScanFinding(
          scanId = scanId,
          ruleId = "SEC-COMPOUND-SMS-EXFIL",
          category = "PERMISSIONS",
          title = "Compound Threat: SMS Interception & Network Exfiltration",
          severity = Severity.HIGH,
          description = "Combined access to SMS permissions and INTERNET creates an exfiltration vector for OTPs and authentication tokens.",
          evidence = "Permissions: SMS + INTERNET",
          recommendation = "Utilize Google Play SMS Retriever API to eliminate READ_SMS requirements.",
          cweId = "CWE-250"
        )
      )
    }

    if (hasLocation && hasBoot && hasInternet) {
      compoundPoints += 10
      findings.add(
        ScanFinding(
          scanId = scanId,
          ruleId = "SEC-COMPOUND-PERSIST-TRACK",
          category = "PERMISSIONS",
          title = "Compound Threat: Persistent Surveillance Vector",
          severity = Severity.HIGH,
          description = "Combination of Boot-time auto-start, Geolocation tracking, and Network access enables covert persistent background telemetry.",
          evidence = "Permissions: BOOT_COMPLETED + LOCATION + INTERNET",
          recommendation = "Eliminate boot persistence and require foreground notification for location tracking.",
          cweId = "CWE-359"
        )
      )
    }

    if (hasCamera && hasAudio && hasInternet) {
      compoundPoints += 10
      findings.add(
        ScanFinding(
          scanId = scanId,
          ruleId = "SEC-COMPOUND-AV-CAPTURE",
          category = "PERMISSIONS",
          title = "Compound Threat: Multimedia Audio/Visual Capture & Network Streaming",
          severity = Severity.HIGH,
          description = "Simultaneous declaration of CAMERA, RECORD_AUDIO, and INTERNET creates an active eavesdropping profile.",
          evidence = "Permissions: CAMERA + RECORD_AUDIO + INTERNET",
          recommendation = "Provide prominent in-app disclosure and restrict capture strictly to active user sessions.",
          cweId = "CWE-250"
        )
      )
    }

    // 3. Evaluate Manifest Configuration Vulnerabilities
    if (input.isDebuggable) {
      manifestPoints += WEIGHT_CRITICAL
      findings.add(
        ScanFinding(
          scanId = scanId,
          ruleId = "SEC-CONF-DEBUG",
          category = "MANIFEST_CONFIG",
          title = "Production Application is Debuggable",
          severity = Severity.CRITICAL,
          description = "android:debuggable is set to true. Attackers can attach a debugger via ADB to dump memory, bypass auth, or run code.",
          evidence = "android:debuggable=\"true\"",
          recommendation = "Set isDebuggable = false in the release build configuration within build.gradle.kts.",
          cweId = "CWE-215"
        )
      )
    }

    if (input.usesCleartextTraffic) {
      manifestPoints += WEIGHT_HIGH
      findings.add(
        ScanFinding(
          scanId = scanId,
          ruleId = "SEC-NET-CLEARTEXT",
          category = "NETWORK_SECURITY",
          title = "Cleartext HTTP Traffic Permitted",
          severity = Severity.HIGH,
          description = "android:usesCleartextTraffic=\"true\" allows unencrypted HTTP transmissions vulnerable to adversary interception and MITM attacks.",
          evidence = "android:usesCleartextTraffic=\"true\"",
          recommendation = "Enforce HTTPS communication across all network calls and configure certificate pinning in network_security_config.xml.",
          cweId = "CWE-319"
        )
      )
    }

    if (input.allowsBackup) {
      manifestPoints += WEIGHT_MEDIUM
      findings.add(
        ScanFinding(
          scanId = scanId,
          ruleId = "SEC-CONF-BACKUP",
          category = "MANIFEST_CONFIG",
          title = "Insecure Application Backup Enabled",
          severity = Severity.MEDIUM,
          description = "android:allowBackup=\"true\" allows sandbox data extraction via adb backup, including shared preferences and local SQLite databases.",
          evidence = "android:allowBackup=\"true\"",
          recommendation = "Set android:allowBackup=\"false\" or enforce strict exclude rules in data_extraction_rules.xml.",
          cweId = "CWE-312"
        )
      )
    }

    if (input.isTestOnly) {
      manifestPoints += WEIGHT_LOW
      findings.add(
        ScanFinding(
          scanId = scanId,
          ruleId = "SEC-CONF-TESTONLY",
          category = "MANIFEST_CONFIG",
          title = "Test-Only Flag Set in Application Tag",
          severity = Severity.LOW,
          description = "android:testOnly is enabled, which may expose internal testing harnesses or non-production backdoors.",
          evidence = "android:testOnly=\"true\"",
          recommendation = "Remove android:testOnly flag prior to distribution.",
          cweId = "CWE-215"
        )
      )
    }

    if (input.targetSdk < 33) {
      manifestPoints += WEIGHT_MEDIUM
      findings.add(
        ScanFinding(
          scanId = scanId,
          ruleId = "SEC-CONF-OUTDATED-SDK",
          category = "MANIFEST_CONFIG",
          title = "Outdated Target SDK Version (API ${input.targetSdk})",
          severity = Severity.MEDIUM,
          description = "Targeting an SDK below 33 bypasses modern Android platform security constraints such as scoped media storage and notification runtime permissions.",
          evidence = "targetSdkVersion = ${input.targetSdk}",
          recommendation = "Upgrade targetSdkVersion to 34 or higher to enforce current platform security baselines.",
          cweId = "CWE-693"
        )
      )
    }

    // 4. Evaluate Unprotected Exported Components
    input.activities.filter { it.isExported && it.permissionRequired == null && !it.name.contains("MainActivity") }
      .forEach { act ->
        componentPoints += WEIGHT_HIGH
        findings.add(
          ScanFinding(
            scanId = scanId,
            ruleId = "SEC-COMP-ACT-EXP",
            category = "EXPORTED_COMPONENTS",
            title = "Unprotected Exported Activity: ${act.name.substringAfterLast(".")}",
            severity = Severity.HIGH,
            description = "Activity is exported without an android:permission restriction, allowing third-party apps to invoke internal application workflows.",
            evidence = "<activity android:name=\"${act.name}\" android:exported=\"true\" />",
            recommendation = "Set android:exported=\"false\" or enforce signature permissions.",
            cweId = "CWE-926"
          )
        )
      }

    input.services.filter { it.isExported && it.permissionRequired == null }.forEach { srv ->
      componentPoints += WEIGHT_HIGH
      findings.add(
        ScanFinding(
          scanId = scanId,
          ruleId = "SEC-COMP-SRV-EXP",
          category = "EXPORTED_COMPONENTS",
          title = "Unprotected Exported Service: ${srv.name.substringAfterLast(".")}",
          severity = Severity.HIGH,
          description = "Exported background service without permission guard allows arbitrary apps to bind or initiate unauthorized processing.",
          evidence = "<service android:name=\"${srv.name}\" android:exported=\"true\" />",
          recommendation = "Require an explicit android:permission or set exported=\"false\".",
          cweId = "CWE-926"
        )
      )
    }

    input.receivers.filter { it.isExported && it.permissionRequired == null }.forEach { rcv ->
      componentPoints += WEIGHT_MEDIUM
      findings.add(
        ScanFinding(
          scanId = scanId,
          ruleId = "SEC-COMP-RCV-EXP",
          category = "EXPORTED_COMPONENTS",
          title = "Unprotected BroadcastReceiver: ${rcv.name.substringAfterLast(".")}",
          severity = Severity.MEDIUM,
          description = "Receiver accepts broadcasts from any app on the system, susceptible to intent spoofing.",
          evidence = "<receiver android:name=\"${rcv.name}\" android:exported=\"true\" />",
          recommendation = "Use LocalBroadcastManager or protect with signature permissions.",
          cweId = "CWE-925"
        )
      )
    }

    input.providers.filter { it.isExported && it.permissionRequired == null }.forEach { prv ->
      componentPoints += WEIGHT_CRITICAL
      findings.add(
        ScanFinding(
          scanId = scanId,
          ruleId = "SEC-COMP-PRV-EXP",
          category = "EXPORTED_COMPONENTS",
          title = "Unprotected Exported ContentProvider: ${prv.name.substringAfterLast(".")}",
          severity = Severity.CRITICAL,
          description = "ContentProvider exposed without read/write permissions allows direct leakage or alteration of local SQLite data.",
          evidence = "<provider android:name=\"${prv.name}\" android:exported=\"true\" />",
          recommendation = "Enforce android:readPermission and android:writePermission.",
          cweId = "CWE-926"
        )
      )
    }

    // 5. Compute Final Risk Score (Capped between 0 and 100)
    val rawTotal = permPoints + manifestPoints + componentPoints + compoundPoints
    val finalScore = rawTotal.coerceIn(0, 100)

    val riskLabel = when {
      finalScore >= 75 -> RiskLabel.CRITICAL
      finalScore >= 50 -> RiskLabel.HIGH
      finalScore >= 25 -> RiskLabel.MEDIUM
      finalScore >= 10 -> RiskLabel.LOW
      else -> RiskLabel.SAFE
    }

    val criticalCount = findings.count { it.severity == Severity.CRITICAL }
    val highCount = findings.count { it.severity == Severity.HIGH }
    val mediumCount = findings.count { it.severity == Severity.MEDIUM }
    val lowCount = findings.count { it.severity == Severity.LOW }
    val infoCount = findings.count { it.severity == Severity.INFO }

    val formulaExplanation = StringBuilder().apply {
      append("Risk Score Calculation Breakdown:\n")
      append("• Permissions Threat Score: $permPoints pts\n")
      append("• Manifest Configuration Score: $manifestPoints pts\n")
      append("• Exported Components Exposure: $componentPoints pts\n")
      append("• Compound Vector Correlation: $compoundPoints pts\n")
      append("Raw Total: $rawTotal pts -> Final Capped Score: $finalScore / 100 ($riskLabel)")
    }.toString()

    val breakdown = ScoreBreakdownDetails(
      permissionsScore = permPoints,
      manifestConfigScore = manifestPoints,
      componentsScore = componentPoints,
      compoundThreatScore = compoundPoints,
      rawTotalScore = rawTotal,
      finalCappedScore = finalScore,
      riskLabel = riskLabel,
      formulaExplanation = formulaExplanation
    )

    val scanRecord = ScanRecord(
      id = scanId,
      ownerId = input.ownerId,
      appName = input.appName,
      packageName = input.packageName,
      versionName = input.versionName,
      versionCode = input.versionCode,
      originalFilename = input.originalFilename,
      fileSizeBytes = input.fileSizeBytes,
      sha256Hash = input.sha256Hash,
      md5Hash = input.md5Hash,
      status = ScanStatus.COMPLETED,
      riskScore = finalScore,
      riskLabel = riskLabel,
      criticalCount = criticalCount,
      highCount = highCount,
      mediumCount = mediumCount,
      lowCount = lowCount,
      infoCount = infoCount,
      permissionsCount = input.requestedPermissions.size,
      exportedComponentsCount = input.activities.count { it.isExported } +
          input.services.count { it.isExported } +
          input.receivers.count { it.isExported } +
          input.providers.count { it.isExported },
      targetSdk = input.targetSdk,
      minSdk = input.minSdk,
      isDebuggable = input.isDebuggable,
      allowsBackup = input.allowsBackup,
      usesCleartextTraffic = input.usesCleartextTraffic,
      createdAt = System.currentTimeMillis(),
      completedAt = System.currentTimeMillis(),
      isDemoData = input.isDemoData
    )

    val report = ForensicReport(
      id = UUID.randomUUID().toString(),
      scanId = scanId,
      ownerId = input.ownerId,
      reportTitle = "PS-02 Security Audit: ${input.appName} (${input.packageName})",
      generatedAt = System.currentTimeMillis(),
      analystName = "Lead Static Security Auditor",
      toolVersion = "PS-02 Risk Engine v3.0",
      riskScore = finalScore,
      riskLabel = riskLabel,
      executiveSummary = "Static security evaluation of '${input.appName}' yielded a composite risk score of $finalScore/100 ($riskLabel). " +
          "Identified $criticalCount Critical, $highCount High, and $mediumCount Medium findings across permissions, build configurations, and exported attack surfaces.",
      methodology = "Automated static binary and manifest inspection using PS-02 Security Risk Calculator. Assessed permissions, component attack surfaces, and CWE-correlated vulnerabilities."
    )

    return RiskAssessmentResult(
      scanRecord = scanRecord,
      findings = findings,
      report = report,
      scoreBreakdown = breakdown
    )
  }

  /**
   * Persists the evaluation results (ScanRecord, ScanFindings, and ForensicReport)
   * into the Room database.
   */
  suspend fun persistAssessment(result: RiskAssessmentResult): ScanRecord = withContext(Dispatchers.IO) {
    if (database != null) {
      database.withTransaction {
        scanDao.insertScan(result.scanRecord)
        findingDao.insertFindings(result.findings)
        reportDao.insertReport(result.report)
      }
    } else {
      scanDao.insertScan(result.scanRecord)
      findingDao.insertFindings(result.findings)
      reportDao.insertReport(result.report)
    }
    result.scanRecord
  }

  /**
   * Evaluates the risk score from the provided manifest input and immediately persists
   * the full audit record to the Room database.
   */
  suspend fun calculateAndPersist(input: ManifestAnalysisInput): RiskAssessmentResult {
    val assessment = evaluateRisk(input)
    persistAssessment(assessment)
    return assessment
  }

  /**
   * Retrieves a persisted scan record by ID.
   */
  suspend fun getPersistedScan(scanId: String): ScanRecord? = withContext(Dispatchers.IO) {
    scanDao.getScanById(scanId)
  }

  /**
   * Retrieves all findings persisted for a given scan.
   */
  suspend fun getScanFindings(scanId: String): List<ScanFinding> = withContext(Dispatchers.IO) {
    findingDao.getFindingsListForScan(scanId)
  }

  /**
   * Retrieves the persisted forensic report for a given scan.
   */
  suspend fun getScanReport(scanId: String): ForensicReport? = withContext(Dispatchers.IO) {
    reportDao.getReportByScanId(scanId)
  }

  /**
   * Deletes a scan record and its associated findings from the Room database.
   */
  suspend fun deleteScan(scanId: String): Unit = withContext(Dispatchers.IO) {
    scanDao.deleteScanById(scanId)
    findingDao.deleteFindingsForScan(scanId)
  }
}
