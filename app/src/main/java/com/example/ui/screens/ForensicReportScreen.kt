package com.example.ui.screens

import android.content.Intent
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.Description
import androidx.compose.material.icons.filled.Download
import androidx.compose.material.icons.filled.Security
import androidx.compose.material.icons.filled.Share
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.example.data.model.ScanFinding
import com.example.ui.MainViewModel
import com.example.ui.components.CyberTopAppBar
import com.example.ui.components.SeverityBadge
import com.example.ui.navigation.Screen
import com.example.ui.theme.CyberAccentCyan
import com.example.ui.theme.CyberBlueDark
import com.example.ui.theme.CyberBluePrimary
import com.example.ui.theme.RiskSafeGreen
import com.example.ui.theme.SeverityCritical
import com.example.ui.theme.SeverityHigh
import com.example.ui.theme.SeverityMedium
import com.example.ui.theme.Slate200
import com.example.ui.theme.Slate600
import com.example.ui.theme.Slate800
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

@Composable
fun ForensicReportScreen(viewModel: MainViewModel) {
  val context = LocalContext.current
  val clipboardManager = LocalClipboardManager.current
  val activeResult by viewModel.activeScanResult.collectAsState()

  val scan = activeResult?.scan
  val report = activeResult?.report
  val findings = activeResult?.findings ?: emptyList()

  val dateFormat = SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'", Locale.US)
  val formattedDate = if (report != null) dateFormat.format(Date(report.generatedAt)) else ""

  fun buildReportText(): String {
    if (scan == null || report == null) return ""
    val sb = StringBuilder()
    sb.appendLine("================================================================================")
    sb.appendLine("PS-02 ANDROID APPLICATION FORENSIC & SECURITY AUDIT REPORT")
    sb.appendLine("================================================================================")
    sb.appendLine("REPORT ID     : ${report.id}")
    sb.appendLine("SCAN ID       : ${scan.id}")
    sb.appendLine("AUDITOR       : ${report.analystName}")
    sb.appendLine("TOOL VERSION  : ${report.toolVersion}")
    sb.appendLine("TIMESTAMP     : $formattedDate")
    sb.appendLine("--------------------------------------------------------------------------------")
    sb.appendLine("TARGET PACKAGE METADATA:")
    sb.appendLine("Application   : ${scan.appName}")
    sb.appendLine("Package Name  : ${scan.packageName}")
    sb.appendLine("Version       : ${scan.versionName} (Build ${scan.versionCode})")
    sb.appendLine("Target SDK    : API ${scan.targetSdk}")
    sb.appendLine("Original File : ${scan.originalFilename}")
    sb.appendLine("File Size     : ${scan.fileSizeBytes} bytes")
    sb.appendLine("SHA-256 HASH  : ${scan.sha256Hash}")
    sb.appendLine("MD5 HASH      : ${scan.md5Hash}")
    sb.appendLine("--------------------------------------------------------------------------------")
    sb.appendLine("RISK EVALUATION:")
    sb.appendLine("OVERALL SCORE : ${scan.riskScore} / 100 [${scan.riskLabel.name}]")
    sb.appendLine("FINDINGS      : Critical: ${scan.criticalCount} | High: ${scan.highCount} | Medium: ${scan.mediumCount} | Low: ${scan.lowCount}")
    sb.appendLine("--------------------------------------------------------------------------------")
    sb.appendLine("EXECUTIVE SUMMARY:")
    sb.appendLine(report.executiveSummary)
    sb.appendLine("--------------------------------------------------------------------------------")
    sb.appendLine("FINDINGS & EVIDENCE:")
    findings.forEachIndexed { i, f ->
      sb.appendLine("[#${i + 1}] [${f.severity.label}] ${f.ruleId} - ${f.title} (${f.cweId})")
      sb.appendLine("    Description    : ${f.description}")
      sb.appendLine("    Evidence       : ${f.evidence}")
      sb.appendLine("    Recommendation : ${f.recommendation}")
      sb.appendLine()
    }
    sb.appendLine("--------------------------------------------------------------------------------")
    sb.appendLine("ANALYSIS LIMITATIONS & LEGAL DISCLAIMER:")
    sb.appendLine(report.limitationsDisclaimer)
    sb.appendLine("================================================================================")
    return sb.toString()
  }

  Scaffold(
    topBar = {
      CyberTopAppBar(
        title = "Forensic Evidence Dossier",
        subtitle = scan?.appName ?: "Forensic Audit",
        showBack = true,
        onBackClick = { viewModel.navigateTo(Screen.RESULTS) },
        onProfileClick = { viewModel.navigateTo(Screen.PROFILE) }
      )
    }
  ) { innerPadding ->
    if (scan == null || report == null) {
      Box(modifier = Modifier.fillMaxSize().padding(innerPadding), contentAlignment = Alignment.Center) {
        Text("No report data available.")
      }
      return@Scaffold
    }

    LazyColumn(
      modifier = Modifier
        .fillMaxSize()
        .padding(innerPadding)
        .padding(horizontal = 16.dp),
      verticalArrangement = Arrangement.spacedBy(14.dp)
    ) {
      item {
        Spacer(modifier = Modifier.height(4.dp))
        // REPORT HEADER CARD
        Card(
          modifier = Modifier.fillMaxWidth(),
          colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
          shape = RoundedCornerShape(14.dp),
          elevation = CardDefaults.cardElevation(defaultElevation = 2.dp)
        ) {
          Column(modifier = Modifier.padding(18.dp)) {
            Row(
              modifier = Modifier.fillMaxWidth(),
              horizontalArrangement = Arrangement.SpaceBetween,
              verticalAlignment = Alignment.CenterVertically
            ) {
              Column {
                Text(
                  text = "OFFICIAL FORENSIC DOSSIER",
                  style = MaterialTheme.typography.labelSmall.copy(fontWeight = FontWeight.Bold, letterSpacing = 1.sp),
                  color = CyberBluePrimary
                )
                Text(
                  text = report.reportTitle,
                  style = MaterialTheme.typography.titleMedium.copy(fontWeight = FontWeight.Bold),
                  color = MaterialTheme.colorScheme.onSurface
                )
              }

              Surface(
                color = when (scan.riskLabel) {
                  com.example.data.model.RiskLabel.CRITICAL -> SeverityCritical
                  com.example.data.model.RiskLabel.HIGH -> SeverityHigh
                  com.example.data.model.RiskLabel.MEDIUM -> SeverityMedium
                  else -> RiskSafeGreen
                }.copy(alpha = 0.15f),
                shape = RoundedCornerShape(6.dp)
              ) {
                Text(
                  text = "${scan.riskScore}/100",
                  style = MaterialTheme.typography.labelLarge.copy(
                    fontWeight = FontWeight.Black,
                    fontFamily = FontFamily.Monospace
                  ),
                  color = when (scan.riskLabel) {
                    com.example.data.model.RiskLabel.CRITICAL -> SeverityCritical
                    com.example.data.model.RiskLabel.HIGH -> SeverityHigh
                    com.example.data.model.RiskLabel.MEDIUM -> SeverityMedium
                    else -> RiskSafeGreen
                  },
                  modifier = Modifier.padding(horizontal = 8.dp, vertical = 4.dp)
                )
              }
            }

            Spacer(modifier = Modifier.height(14.dp))
            HorizontalDivider(color = Color(0xFFE2E8F0))
            Spacer(modifier = Modifier.height(14.dp))

            // Metadata Grid
            DossierField(label = "REPORT ID", value = report.id)
            DossierField(label = "SCAN ID", value = scan.id)
            DossierField(label = "ANALYSIS TIMESTAMP", value = formattedDate)
            DossierField(label = "TOOL VERSION", value = report.toolVersion)
            DossierField(label = "TARGET FILENAME", value = scan.originalFilename)
            DossierField(label = "SHA-256 HASH", value = scan.sha256Hash)
            DossierField(label = "MD5 HASH", value = scan.md5Hash.ifEmpty { "N/A" })

            Spacer(modifier = Modifier.height(16.dp))

            // Export Actions
            Row(
              modifier = Modifier.fillMaxWidth(),
              horizontalArrangement = Arrangement.spacedBy(10.dp)
            ) {
              Button(
                onClick = {
                  val text = buildReportText()
                  clipboardManager.setText(AnnotatedString(text))
                },
                modifier = Modifier
                  .weight(1f)
                  .testTag("btn_copy_report"),
                colors = ButtonDefaults.buttonColors(containerColor = CyberBluePrimary),
                shape = RoundedCornerShape(8.dp)
              ) {
                Icon(Icons.Default.ContentCopy, contentDescription = null, modifier = Modifier.size(16.dp))
                Spacer(modifier = Modifier.width(6.dp))
                Text("Copy Report", fontSize = 12.sp, fontWeight = FontWeight.Bold)
              }

              OutlinedButton(
                onClick = {
                  val text = buildReportText()
                  val sendIntent = Intent().apply {
                    action = Intent.ACTION_SEND
                    putExtra(Intent.EXTRA_TEXT, text)
                    type = "text/plain"
                  }
                  context.startActivity(Intent.createChooser(sendIntent, "Export Forensic Report"))
                },
                modifier = Modifier
                  .weight(1f)
                  .testTag("btn_share_report"),
                shape = RoundedCornerShape(8.dp)
              ) {
                Icon(Icons.Default.Share, contentDescription = null, modifier = Modifier.size(16.dp))
                Spacer(modifier = Modifier.width(6.dp))
                Text("Share Dossier", fontSize = 12.sp, fontWeight = FontWeight.Bold)
              }
            }
          }
        }
      }

      // EXECUTIVE SUMMARY
      item {
        Card(
          modifier = Modifier.fillMaxWidth(),
          colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
          shape = RoundedCornerShape(12.dp)
        ) {
          Column(modifier = Modifier.padding(16.dp)) {
            Text(
              text = "Executive Summary",
              style = MaterialTheme.typography.titleSmall.copy(fontWeight = FontWeight.Bold),
              color = CyberBlueDark
            )
            Spacer(modifier = Modifier.height(6.dp))
            Text(
              text = report.executiveSummary,
              style = MaterialTheme.typography.bodySmall,
              color = Slate800,
              lineHeight = 20.sp
            )
          }
        }
      }

      // FINDINGS TABLE
      item {
        Text(
          text = "Detailed Forensic Evidence Findings",
          style = MaterialTheme.typography.titleSmall.copy(fontWeight = FontWeight.Bold),
          color = MaterialTheme.colorScheme.onBackground
        )
      }

      items(findings) { finding ->
        Card(
          modifier = Modifier.fillMaxWidth(),
          colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
          shape = RoundedCornerShape(10.dp)
        ) {
          Column(modifier = Modifier.padding(14.dp)) {
            Row(
              modifier = Modifier.fillMaxWidth(),
              horizontalArrangement = Arrangement.SpaceBetween,
              verticalAlignment = Alignment.CenterVertically
            ) {
              Text(
                text = "${finding.ruleId} • ${finding.cweId}",
                style = MaterialTheme.typography.labelSmall.copy(
                  fontWeight = FontWeight.Bold,
                  fontFamily = FontFamily.Monospace
                ),
                color = CyberBlueDark
              )
              SeverityBadge(severity = finding.severity)
            }

            Spacer(modifier = Modifier.height(6.dp))
            Text(
              text = finding.title,
              style = MaterialTheme.typography.bodyMedium.copy(fontWeight = FontWeight.Bold),
              color = MaterialTheme.colorScheme.onSurface
            )

            Spacer(modifier = Modifier.height(4.dp))
            Text(
              text = finding.description,
              style = MaterialTheme.typography.bodySmall,
              color = Slate600
            )

            if (finding.evidence.isNotBlank()) {
              Spacer(modifier = Modifier.height(6.dp))
              Surface(
                modifier = Modifier.fillMaxWidth(),
                color = Color(0xFF0F172A),
                shape = RoundedCornerShape(4.dp)
              ) {
                Text(
                  text = "Evidence: ${finding.evidence}",
                  style = MaterialTheme.typography.labelSmall.copy(fontFamily = FontFamily.Monospace),
                  color = Color(0xFF38BDF8),
                  modifier = Modifier.padding(8.dp)
                )
              }
            }

            Spacer(modifier = Modifier.height(6.dp))
            Text(
              text = "Remediation: ${finding.recommendation}",
              style = MaterialTheme.typography.labelSmall,
              color = Slate800
            )
          }
        }
      }

      // ANALYSIS LIMITATIONS DISCLAIMER
      item {
        Card(
          modifier = Modifier.fillMaxWidth(),
          colors = CardDefaults.cardColors(containerColor = Color(0xFFFEF2F2)),
          shape = RoundedCornerShape(12.dp)
        ) {
          Row(modifier = Modifier.padding(14.dp), verticalAlignment = Alignment.Top) {
            Icon(Icons.Default.Warning, contentDescription = null, tint = SeverityCritical, modifier = Modifier.size(20.dp))
            Spacer(modifier = Modifier.width(10.dp))
            Column {
              Text(
                text = "Analysis Limitations & Non-Warranty Statement",
                style = MaterialTheme.typography.titleSmall.copy(fontWeight = FontWeight.Bold),
                color = SeverityCritical
              )
              Spacer(modifier = Modifier.height(4.dp))
              Text(
                text = report.limitationsDisclaimer,
                style = MaterialTheme.typography.bodySmall,
                color = Color(0xFF991B1B),
                lineHeight = 18.sp
              )
            }
          }
        }
      }

      item {
        Spacer(modifier = Modifier.height(20.dp))
      }
    }
  }
}

@Composable
fun DossierField(label: String, value: String) {
  Row(
    modifier = Modifier
      .fillMaxWidth()
      .padding(vertical = 3.dp),
    horizontalArrangement = Arrangement.SpaceBetween,
    verticalAlignment = Alignment.CenterVertically
  ) {
    Text(
      text = label,
      style = MaterialTheme.typography.labelSmall.copy(fontWeight = FontWeight.Bold),
      color = Slate600,
      modifier = Modifier.width(130.dp)
    )
    Text(
      text = value,
      style = MaterialTheme.typography.labelSmall.copy(
        fontFamily = FontFamily.Monospace,
        fontWeight = FontWeight.Medium
      ),
      color = MaterialTheme.colorScheme.onSurface,
      maxLines = 1,
      modifier = Modifier.weight(1f)
    )
  }
}
