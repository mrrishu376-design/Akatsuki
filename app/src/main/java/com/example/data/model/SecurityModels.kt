package com.example.data.model

import androidx.room.Entity
import androidx.room.PrimaryKey
import java.util.UUID

enum class Severity(val label: String, val weight: Int) {
  CRITICAL("CRITICAL", 25),
  HIGH("HIGH", 15),
  MEDIUM("MEDIUM", 8),
  LOW("LOW", 3),
  INFO("INFORMATIONAL", 0)
}

enum class ScanStatus {
  QUEUED,
  PROCESSING,
  COMPLETED,
  FAILED,
  INCONCLUSIVE
}

enum class RiskLabel {
  CRITICAL,
  HIGH,
  MEDIUM,
  LOW,
  SAFE
}

@Entity(tableName = "users")
data class AuthUser(
  @PrimaryKey val id: String = UUID.randomUUID().toString(),
  val email: String,
  val fullName: String,
  val role: String = "Forensic Analyst",
  val organization: String = "Cyber Defense Lab",
  val createdAt: Long = System.currentTimeMillis()
)

@Entity(tableName = "scans")
data class ScanRecord(
  @PrimaryKey val id: String = UUID.randomUUID().toString(),
  val ownerId: String,
  val appName: String,
  val packageName: String,
  val versionName: String = "1.0",
  val versionCode: Long = 1,
  val originalFilename: String,
  val fileSizeBytes: Long,
  val sha256Hash: String,
  val md5Hash: String = "",
  val status: ScanStatus = ScanStatus.COMPLETED,
  val riskScore: Int = 0, // 0 to 100
  val riskLabel: RiskLabel = RiskLabel.SAFE,
  val criticalCount: Int = 0,
  val highCount: Int = 0,
  val mediumCount: Int = 0,
  val lowCount: Int = 0,
  val infoCount: Int = 0,
  val permissionsCount: Int = 0,
  val exportedComponentsCount: Int = 0,
  val suspiciousUrlsCount: Int = 0,
  val hardcodedSecretsCount: Int = 0,
  val targetSdk: Int = 34,
  val minSdk: Int = 24,
  val isDebuggable: Boolean = false,
  val allowsBackup: Boolean = true,
  val usesCleartextTraffic: Boolean = false,
  val createdAt: Long = System.currentTimeMillis(),
  val completedAt: Long = System.currentTimeMillis(),
  val isDemoData: Boolean = false
)

@Entity(tableName = "scan_findings")
data class ScanFinding(
  @PrimaryKey val id: String = UUID.randomUUID().toString(),
  val scanId: String,
  val ruleId: String,
  val category: String, // PERMISSIONS, MANIFEST_CONFIG, EXPORTED_COMPONENTS, SECRETS_STRINGS, NETWORK_SECURITY
  val title: String,
  val severity: Severity,
  val description: String,
  val evidence: String,
  val recommendation: String,
  val cweId: String = "CWE-200"
)

@Entity(tableName = "forensic_reports")
data class ForensicReport(
  @PrimaryKey val id: String = UUID.randomUUID().toString(),
  val scanId: String,
  val ownerId: String,
  val reportTitle: String,
  val generatedAt: Long = System.currentTimeMillis(),
  val analystName: String = "SecOps Lead",
  val toolVersion: String = "PS-02 Static Forensic Analyzer v2.4.0",
  val riskScore: Int,
  val riskLabel: RiskLabel,
  val executiveSummary: String,
  val methodology: String,
  val limitationsDisclaimer: String = "DISCLAIMER: This report is generated through static security analysis. It inspects byte patterns, manifests, and signatures without runtime execution. Absence of findings does not guarantee immunity from zero-day threats or dynamic payloads.",
  val fullReportJson: String = ""
)

data class PermissionThreatItem(
  val permission: String,
  val protectionLevel: String, // DANGEROUS, NORMAL, SIGNATURE, SPECIAL
  val threatLevel: Severity,
  val humanName: String,
  val description: String,
  val threatImpact: String
)

data class ExportedComponentItem(
  val type: String, // Activity, Service, Receiver, Provider
  val name: String,
  val isExported: Boolean,
  val permissionRequired: String?,
  val severity: Severity,
  val rationale: String
)

data class DetectedSecretItem(
  val type: String,
  val maskedValue: String,
  val location: String,
  val severity: Severity
)
