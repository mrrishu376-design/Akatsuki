package com.example.data.analyzer

import com.example.data.model.DetectedSecretItem
import com.example.data.model.ExportedComponentItem
import com.example.data.model.ForensicReport
import com.example.data.model.PermissionThreatItem
import com.example.data.model.RiskLabel
import com.example.data.model.ScanFinding
import com.example.data.model.ScanRecord
import com.example.data.model.ScanStatus
import com.example.data.model.Severity
import java.util.UUID

data class SampleApkBenchmark(
  val id: String,
  val name: String,
  val packageName: String,
  val category: String,
  val filename: String,
  val fileSizeFormatted: String,
  val expectedRiskScore: Int,
  val description: String,
  val isDemo: Boolean = true
)

object SampleApkCatalog {
  val benchmarks = listOf(
    SampleApkBenchmark(
      id = "bench-insecure-bank",
      name = "InsecureBank Mobile v1.4",
      packageName = "com.insecurebank.vulnerable",
      category = "Vulnerable Target (Financial)",
      filename = "InsecureBankv1.4-debug.apk",
      fileSizeFormatted = "14.2 MB",
      expectedRiskScore = 88,
      description = "Demonstration banking app with hardcoded AWS credentials, debuggable enabled, cleartext HTTP, and exported root activity."
    ),
    SampleApkBenchmark(
      id = "bench-spyware-tracker",
      name = "Background Tracker & Logger v2.1",
      packageName = "com.stealth.geologger.service",
      category = "High-Risk Spyware Vector",
      filename = "GeoTracker_Daemon_v2.1.apk",
      fileSizeFormatted = "8.6 MB",
      expectedRiskScore = 92,
      description = "App requesting background location, SMS interception, call logs, mic recording, boot receiver, and unprotected receivers."
    ),
    SampleApkBenchmark(
      id = "bench-adware-utility",
      name = "Super Flashlight & Cleaner v3.0",
      packageName = "com.utility.cleaner.flashlight",
      category = "Excessive Permissions Adware",
      filename = "QuickCleaner_Flashlight.apk",
      fileSizeFormatted = "22.5 MB",
      expectedRiskScore = 58,
      description = "Simple flashlight utility requesting contacts, system overlay tapjacking, broad storage, and cleartext ad network endpoints."
    ),
    SampleApkBenchmark(
      id = "bench-secure-vault",
      name = "Fortress Enterprise Vault v4.2",
      packageName = "com.cybersec.hardened.vault",
      category = "Hardened Reference Build",
      filename = "FortressVault-release.apk",
      fileSizeFormatted = "18.1 MB",
      expectedRiskScore = 8,
      description = "Security-hardened baseline build. No debug flags, strict scoped permissions, certificate pinning, and zero exported components."
    )
  )

  fun generateBenchmarkResult(benchmark: SampleApkBenchmark, ownerId: String): FullScanResult {
    val scanId = UUID.randomUUID().toString()
    val findings = mutableListOf<ScanFinding>()
    val permissions = mutableListOf<PermissionThreatItem>()
    val exportedComponents = mutableListOf<ExportedComponentItem>()
    val detectedSecrets = mutableListOf<DetectedSecretItem>()
    val urls = mutableListOf<String>()

    when (benchmark.id) {
      "bench-insecure-bank" -> {
        findings.add(
          ScanFinding(
            scanId = scanId,
            ruleId = "SEC-CONF-DEBUG",
            category = "MANIFEST_CONFIG",
            title = "Application is Debuggable in Production",
            severity = Severity.CRITICAL,
            description = "android:debuggable is enabled. An attacker with physical access or ADB can attach debuggers, extract process memory, and execute arbitrary code.",
            evidence = "android:debuggable=\"true\"",
            recommendation = "Disable debuggable flag in release builds by setting isDebuggable = false in Gradle.",
            cweId = "CWE-215"
          )
        )
        findings.add(
          ScanFinding(
            scanId = scanId,
            ruleId = "SEC-STR-AWS-KEY",
            category = "SECRETS_STRINGS",
            title = "Hardcoded AWS Access Key in DEX",
            severity = Severity.CRITICAL,
            description = "Unencrypted AWS Access Key located in com.insecurebank.vulnerable.Config.class.",
            evidence = "AKIAIOSFODNN7EXAMPLE",
            recommendation = "Revoke key via AWS IAM. Use backend temporary STS credentials.",
            cweId = "CWE-798"
          )
        )
        findings.add(
          ScanFinding(
            scanId = scanId,
            ruleId = "SEC-NET-CLEARTEXT",
            category = "NETWORK_SECURITY",
            title = "Cleartext HTTP Traffic Permitted",
            severity = Severity.HIGH,
            description = "usesCleartextTraffic=\"true\" allows transmitting financial credentials over unencrypted HTTP.",
            evidence = "android:usesCleartextTraffic=\"true\"",
            recommendation = "Enforce HTTPS universally and specify certificate pinning in network security config.",
            cweId = "CWE-319"
          )
        )
        findings.add(
          ScanFinding(
            scanId = scanId,
            ruleId = "SEC-COMP-EXP-ACT",
            category = "EXPORTED_COMPONENTS",
            title = "Unprotected Exported TransferActivity",
            severity = Severity.HIGH,
            description = "TransferActivity is exported without an android:permission guard, allowing other apps to invoke funds transfer intents.",
            evidence = "<activity android:name=\".TransferActivity\" android:exported=\"true\" />",
            recommendation = "Set android:exported=\"false\" or enforce signature permissions.",
            cweId = "CWE-926"
          )
        )
        findings.add(
          ScanFinding(
            scanId = scanId,
            ruleId = "SEC-CONF-BACKUP",
            category = "MANIFEST_CONFIG",
            title = "Insecure Application Backup Enabled",
            severity = Severity.MEDIUM,
            description = "android:allowBackup=\"true\" permits data extraction via 'adb backup', compromising user session database.",
            evidence = "android:allowBackup=\"true\"",
            recommendation = "Set android:allowBackup=\"false\" or declare strict data extraction rules.",
            cweId = "CWE-312"
          )
        )

        permissions.add(PermissionThreatItem("android.permission.INTERNET", "NORMAL", Severity.INFO, "INTERNET", "Network access", "Normal operation"))
        permissions.add(PermissionThreatItem("android.permission.ACCESS_NETWORK_STATE", "NORMAL", Severity.INFO, "ACCESS_NETWORK_STATE", "Network state check", "Normal operation"))
        permissions.add(PermissionThreatItem("android.permission.READ_PHONE_STATE", "DANGEROUS", Severity.MEDIUM, "READ_PHONE_STATE", "IMEI & device identity", "Device fingerprinting"))

        exportedComponents.add(ExportedComponentItem("Activity", "TransferActivity", true, null, Severity.HIGH, "Exposed financial transfer action"))
        exportedComponents.add(ExportedComponentItem("Activity", "MainActivity", true, null, Severity.INFO, "Main launcher entrypoint"))
        exportedComponents.add(ExportedComponentItem("Service", "SyncAuthService", true, null, Severity.HIGH, "Background sync endpoint"))

        detectedSecrets.add(DetectedSecretItem("AWS Access Key", "AKIAIOSF************", "classes.dex:Config", Severity.CRITICAL))
        detectedSecrets.add(DetectedSecretItem("Hardcoded API Secret", "sec_live_9a7f34******", "classes.dex:NetworkClient", Severity.HIGH))

        urls.add("http://api.insecurebank.internal:8080/v1/auth")
        urls.add("http://telemetry.unencrypted-collector.net/log")
      }
      "bench-spyware-tracker" -> {
        findings.add(
          ScanFinding(
            scanId = scanId,
            ruleId = "SEC-PERM-BG-LOC",
            category = "PERMISSIONS",
            title = "Persistent Background Geolocation Surveillance",
            severity = Severity.CRITICAL,
            description = "ACCESS_BACKGROUND_LOCATION requested alongside ACCESS_FINE_LOCATION without foreground notification constraint.",
            evidence = "<uses-permission android:name=\"android.permission.ACCESS_BACKGROUND_LOCATION\" />",
            recommendation = "Remove persistent background location unless strictly essential. Use WorkManager with foreground user consent.",
            cweId = "CWE-250"
          )
        )
        findings.add(
          ScanFinding(
            scanId = scanId,
            ruleId = "SEC-PERM-SMS-INTERCEPT",
            category = "PERMISSIONS",
            title = "SMS Interception & Reading Capabilities",
            severity = Severity.CRITICAL,
            description = "READ_SMS and RECEIVE_SMS requested. Permits interception of two-factor authentication tokens and private messages.",
            evidence = "<uses-permission android:name=\"android.permission.RECEIVE_SMS\" />",
            recommendation = "Use SMS Retriever API or SMS User Consent API instead of broad SMS read permissions.",
            cweId = "CWE-250"
          )
        )
        findings.add(
          ScanFinding(
            scanId = scanId,
            ruleId = "SEC-PERM-MIC-CAPTURE",
            category = "PERMISSIONS",
            title = "Covert Audio Recording Vector",
            severity = Severity.HIGH,
            description = "Application requests RECORD_AUDIO without visible multimedia features in manifest.",
            evidence = "<uses-permission android:name=\"android.permission.RECORD_AUDIO\" />",
            recommendation = "Audit audio capture pipelines. Display continuous notification during microphone active capture.",
            cweId = "CWE-250"
          )
        )
        findings.add(
          ScanFinding(
            scanId = scanId,
            ruleId = "SEC-COMP-BOOT-START",
            category = "EXPORTED_COMPONENTS",
            title = "Persistent Boot-Time Autostart Receiver",
            severity = Severity.HIGH,
            description = "RECEIVE_BOOT_COMPLETED is utilized with an exported BroadcastReceiver to maintain permanent background persistence.",
            evidence = "<receiver android:name=\".BootReceiver\" android:exported=\"true\" />",
            recommendation = "Set exported=\"false\" on boot receivers to avoid unauthorized trigger broadcasts.",
            cweId = "CWE-925"
          )
        )

        permissions.add(PermissionThreatItem("android.permission.ACCESS_BACKGROUND_LOCATION", "DANGEROUS", Severity.CRITICAL, "ACCESS_BACKGROUND_LOCATION", "Continuous background GPS", "Location stalking vector"))
        permissions.add(PermissionThreatItem("android.permission.RECEIVE_SMS", "DANGEROUS", Severity.CRITICAL, "RECEIVE_SMS", "Inbound SMS monitor", "2FA OTP token interception"))
        permissions.add(PermissionThreatItem("android.permission.READ_SMS", "DANGEROUS", Severity.HIGH, "READ_SMS", "Read all text messages", "Message privacy breach"))
        permissions.add(PermissionThreatItem("android.permission.RECORD_AUDIO", "DANGEROUS", Severity.HIGH, "RECORD_AUDIO", "Microphone audio recording", "Eavesdropping risk"))
        permissions.add(PermissionThreatItem("android.permission.READ_CALL_LOG", "DANGEROUS", Severity.HIGH, "READ_CALL_LOG", "Access phone call logs", "Social graph metadata theft"))
        permissions.add(PermissionThreatItem("android.permission.RECEIVE_BOOT_COMPLETED", "NORMAL", Severity.MEDIUM, "RECEIVE_BOOT_COMPLETED", "Start on phone boot", "Persistent malware foothold"))

        exportedComponents.add(ExportedComponentItem("Receiver", "BootReceiver", true, null, Severity.HIGH, "Unprotected boot trigger"))
        exportedComponents.add(ExportedComponentItem("Service", "LocationDaemon", true, null, Severity.HIGH, "Exported tracking service"))

        urls.add("http://c2-tracker.darknet-relay.org/beacon")
        urls.add("https://analytics-collector-hidden.xyz/v2/ingest")
      }
      "bench-adware-utility" -> {
        findings.add(
          ScanFinding(
            scanId = scanId,
            ruleId = "SEC-PERM-TAPJACK",
            category = "PERMISSIONS",
            title = "Overlay Attack / Tapjacking Capability",
            severity = Severity.HIGH,
            description = "SYSTEM_ALERT_WINDOW requested by a simple utility app. This capability allows creating invisible touch overlays over target apps.",
            evidence = "<uses-permission android:name=\"android.permission.SYSTEM_ALERT_WINDOW\" />",
            recommendation = "Remove SYSTEM_ALERT_WINDOW unless creating an authorized accessibility or picture-in-picture service.",
            cweId = "CWE-1021"
          )
        )
        findings.add(
          ScanFinding(
            scanId = scanId,
            ruleId = "SEC-PERM-CONTACTS",
            category = "PERMISSIONS",
            title = "Excessive Privilege: Contact List Harvesting",
            severity = Severity.HIGH,
            description = "READ_CONTACTS is requested by Flashlight application. Disproportionate privilege mismatch indicates potential data monetization.",
            evidence = "<uses-permission android:name=\"android.permission.READ_CONTACTS\" />",
            recommendation = "Eliminate unnecessary contact reading permission from non-communication applications.",
            cweId = "CWE-250"
          )
        )
        findings.add(
          ScanFinding(
            scanId = scanId,
            ruleId = "SEC-NET-CLEARTEXT",
            category = "NETWORK_SECURITY",
            title = "Unencrypted Ad Network Transmissions",
            severity = Severity.HIGH,
            description = "Application permits cleartext HTTP traffic to third-party ad networks, leaking device identifiers.",
            evidence = "android:usesCleartextTraffic=\"true\"",
            recommendation = "Force HTTPS on all advertising network SDKs.",
            cweId = "CWE-319"
          )
        )

        permissions.add(PermissionThreatItem("android.permission.SYSTEM_ALERT_WINDOW", "SPECIAL", Severity.HIGH, "SYSTEM_ALERT_WINDOW", "Draw over other apps", "Tapjacking overlay vector"))
        permissions.add(PermissionThreatItem("android.permission.READ_CONTACTS", "DANGEROUS", Severity.HIGH, "READ_CONTACTS", "Address book access", "Contact harvesting for ads"))
        permissions.add(PermissionThreatItem("android.permission.WRITE_EXTERNAL_STORAGE", "DANGEROUS", Severity.MEDIUM, "WRITE_EXTERNAL_STORAGE", "Shared storage writes", "Cross-app file tampering"))

        exportedComponents.add(ExportedComponentItem("Activity", "AdInterstitialActivity", true, null, Severity.MEDIUM, "Exposed full-screen ad intent"))
        exportedComponents.add(ExportedComponentItem("Receiver", "InstallReferrerReceiver", true, null, Severity.LOW, "Marketing attribution receiver"))

        urls.add("http://ad-exchange-cdn.net/bid/request")
        urls.add("https://sdk-telemetry.mobileadtracker.com/event")
      }
      else -> { // bench-secure-vault
        findings.add(
          ScanFinding(
            scanId = scanId,
            ruleId = "SEC-INFO-HARDENED",
            category = "MANIFEST_CONFIG",
            title = "Hardened Build Flags Verified",
            severity = Severity.INFO,
            description = "All dangerous flags (debuggable, allowBackup, usesCleartextTraffic) are properly disabled. Targeting modern API 34 with scoped storage.",
            evidence = "debuggable=false, allowBackup=false, usesCleartextTraffic=false",
            recommendation = "Maintain configuration hygiene in future dependency upgrades.",
            cweId = "CWE-693"
          )
        )
        permissions.add(PermissionThreatItem("android.permission.INTERNET", "NORMAL", Severity.INFO, "INTERNET", "Encrypted HTTPS communication", "Standard network transport"))
        permissions.add(PermissionThreatItem("android.permission.USE_BIOMETRIC", "NORMAL", Severity.INFO, "USE_BIOMETRIC", "Biometric key access", "Hardware-backed authentication"))

        exportedComponents.add(ExportedComponentItem("Activity", "MainActivity", true, null, Severity.INFO, "Guarded launcher entrypoint"))
        urls.add("https://api.cybersec-vault.enterprise.io/v2/secure-sync")
      }
    }

    val criticalCount = findings.count { it.severity == Severity.CRITICAL }
    val highCount = findings.count { it.severity == Severity.HIGH }
    val mediumCount = findings.count { it.severity == Severity.MEDIUM }
    val lowCount = findings.count { it.severity == Severity.LOW }
    val infoCount = findings.count { it.severity == Severity.INFO }

    val rawScore = (criticalCount * 25) + (highCount * 15) + (mediumCount * 8) + (lowCount * 3)
    val finalScore = rawScore.coerceIn(0, 100)
    val riskLabel = when {
      finalScore >= 75 -> RiskLabel.CRITICAL
      finalScore >= 50 -> RiskLabel.HIGH
      finalScore >= 25 -> RiskLabel.MEDIUM
      finalScore >= 10 -> RiskLabel.LOW
      else -> RiskLabel.SAFE
    }

    val sha256 = when (benchmark.id) {
      "bench-insecure-bank" -> "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
      "bench-spyware-tracker" -> "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"
      "bench-adware-utility" -> "4b227777d4dd1fc61c6f884f48641d02b4d121d3fd328cb08b5531fcacdabf8a"
      else -> "2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae"
    }

    val scan = ScanRecord(
      id = scanId,
      ownerId = ownerId,
      appName = benchmark.name,
      packageName = benchmark.packageName,
      versionName = "2.4.0",
      versionCode = 24,
      originalFilename = benchmark.filename,
      fileSizeBytes = 14857600L,
      sha256Hash = sha256,
      md5Hash = sha256.take(32),
      status = ScanStatus.COMPLETED,
      riskScore = finalScore,
      riskLabel = riskLabel,
      criticalCount = criticalCount,
      highCount = highCount,
      mediumCount = mediumCount,
      lowCount = lowCount,
      infoCount = infoCount,
      permissionsCount = permissions.size,
      exportedComponentsCount = exportedComponents.size,
      suspiciousUrlsCount = urls.size,
      hardcodedSecretsCount = detectedSecrets.size,
      targetSdk = if (benchmark.id == "bench-secure-vault") 34 else 31,
      minSdk = 24,
      isDebuggable = benchmark.id == "bench-insecure-bank",
      allowsBackup = benchmark.id != "bench-secure-vault",
      usesCleartextTraffic = benchmark.id != "bench-secure-vault",
      createdAt = System.currentTimeMillis(),
      completedAt = System.currentTimeMillis(),
      isDemoData = true
    )

    val report = ForensicReport(
      id = UUID.randomUUID().toString(),
      scanId = scanId,
      ownerId = ownerId,
      reportTitle = "PS-02 Forensic Audit: ${benchmark.name} (${benchmark.packageName})",
      generatedAt = System.currentTimeMillis(),
      analystName = "Lead Forensic Auditor",
      toolVersion = "PS-02 Static Forensic Analyzer v2.4.0",
      riskScore = finalScore,
      riskLabel = riskLabel,
      executiveSummary = "Benchmark forensic security evaluation of '${benchmark.name}' scored $finalScore/100 ($riskLabel). Evaluated static manifest declarations, component exposure, cryptographic signatures, and string pattern matches.",
      methodology = "Automated static forensic evaluation using PS-02 Forensic Engine. Examined byte streams, hashes, dangerous permissions, exported components, and pattern entropy without live execution."
    )

    return FullScanResult(
      scan = scan,
      findings = findings,
      permissions = permissions,
      exportedComponents = exportedComponents,
      detectedSecrets = detectedSecrets,
      extractedUrls = urls,
      report = report
    )
  }
}
