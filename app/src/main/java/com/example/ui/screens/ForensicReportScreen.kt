package com.example.ui.screens

import android.content.Intent
import androidx.compose.foundation.background
import androidx.compose.foundation.border
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
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.Cloud
import androidx.compose.material.icons.filled.CloudDone
import androidx.compose.material.icons.filled.CloudUpload
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.Description
import androidx.compose.material.icons.filled.Download
import androidx.compose.material.icons.filled.PictureAsPdf
import androidx.compose.material.icons.filled.Security
import androidx.compose.material.icons.filled.Share
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material.icons.filled.Warning
import com.example.data.repository.CloudSyncState
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
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
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
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
import com.example.data.analyzer.EvidenceReportGenerator
import com.example.data.model.ScanFinding
import kotlinx.coroutines.launch
import com.example.ui.MainViewModel
import com.example.ui.components.CyberTopAppBar
import com.example.ui.components.SeverityBadge
import com.example.ui.navigation.Screen
import com.example.ui.theme.ConsoleBlueBg
import com.example.ui.theme.ConsoleBluePrimary
import com.example.ui.theme.ConsoleBorder
import com.example.ui.theme.ConsoleNavy
import com.example.ui.theme.ConsoleWhite
import com.example.ui.theme.RiskSafeGreen
import com.example.ui.theme.SeverityCritical
import com.example.ui.theme.SeverityCriticalBg
import com.example.ui.theme.SeverityHigh
import com.example.ui.theme.SeverityHighBg
import com.example.ui.theme.SeverityMedium
import com.example.ui.theme.SeverityMediumBg
import com.example.ui.theme.Slate200
import com.example.ui.theme.Slate600
import com.example.ui.theme.Slate800
import com.example.ui.theme.Slate900
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

  var isExportingPdf by remember { mutableStateOf(false) }
  var pdfMessage by remember { mutableStateOf<String?>(null) }
  val cloudSyncState by viewModel.cloudSyncState.collectAsState()
  val coroutineScope = rememberCoroutineScope()

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
    },
    containerColor = ConsoleWhite
  ) { innerPadding ->
    if (scan == null || report == null) {
      Box(modifier = Modifier.fillMaxSize().padding(innerPadding), contentAlignment = Alignment.Center) {
        Text("No report data available.", color = Slate600)
      }
      return@Scaffold
    }

    LazyColumn(
      modifier = Modifier
        .fillMaxSize()
        .padding(innerPadding)
        .padding(horizontal = 16.dp, vertical = 12.dp),
      verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
      item {
        // REPORT HEADER CARD
        Card(
          modifier = Modifier
            .fillMaxWidth()
            .border(1.dp, ConsoleBorder, RoundedCornerShape(8.dp)),
          colors = CardDefaults.cardColors(containerColor = ConsoleWhite),
          shape = RoundedCornerShape(8.dp),
          elevation = CardDefaults.cardElevation(defaultElevation = 0.dp)
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
                  color = ConsoleBluePrimary
                )
                Text(
                  text = report.reportTitle,
                  style = MaterialTheme.typography.titleMedium.copy(fontWeight = FontWeight.Bold),
                  color = Slate900
                )
              }

              val (scoreColor, scoreBg) = when (scan.riskLabel) {
                com.example.data.model.RiskLabel.CRITICAL -> SeverityCritical to SeverityCriticalBg
                com.example.data.model.RiskLabel.HIGH -> SeverityHigh to SeverityHighBg
                com.example.data.model.RiskLabel.MEDIUM -> SeverityMedium to SeverityMediumBg
                else -> RiskSafeGreen to Color(0xFFDCFCE7)
              }

              Surface(
                color = scoreBg,
                shape = RoundedCornerShape(6.dp),
                border = androidx.compose.foundation.BorderStroke(1.dp, scoreColor.copy(alpha = 0.4f))
              ) {
                Text(
                  text = "${scan.riskScore}/100",
                  style = MaterialTheme.typography.labelLarge.copy(
                    fontWeight = FontWeight.Black,
                    fontFamily = FontFamily.Monospace
                  ),
                  color = scoreColor,
                  modifier = Modifier.padding(horizontal = 8.dp, vertical = 4.dp)
                )
              }
            }

            Spacer(modifier = Modifier.height(14.dp))
            HorizontalDivider(color = ConsoleBorder)
            Spacer(modifier = Modifier.height(14.dp))

            // Metadata Grid
            DossierField(label = "REPORT ID", value = report.id)
            DossierField(label = "SCAN ID", value = scan.id)
            DossierField(label = "TIMESTAMP", value = formattedDate)
            DossierField(label = "TOOL VERSION", value = report.toolVersion)
            DossierField(label = "TARGET FILE", value = scan.originalFilename)
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
                colors = ButtonDefaults.buttonColors(containerColor = ConsoleNavy),
                shape = RoundedCornerShape(6.dp)
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
                shape = RoundedCornerShape(6.dp),
                border = androidx.compose.foundation.BorderStroke(1.dp, ConsoleBorder)
              ) {
                Icon(Icons.Default.Share, contentDescription = null, tint = ConsoleNavy, modifier = Modifier.size(16.dp))
                Spacer(modifier = Modifier.width(6.dp))
                Text("Share Dossier", fontSize = 12.sp, fontWeight = FontWeight.Bold, color = ConsoleNavy)
              }
            }

            Spacer(modifier = Modifier.height(10.dp))

            // Compile & Export Structured PDF CTA
            Button(
              onClick = {
                isExportingPdf = true
                pdfMessage = null
                coroutineScope.launch {
                  try {
                    val generator = EvidenceReportGenerator(context)
                    val pdfFile = generator.compilePdf(scan, findings, report)
                    isExportingPdf = false
                    pdfMessage = "Generated: ${pdfFile.name}"
                    val uri = generator.getShareableUri(pdfFile)
                    val shareIntent = Intent(Intent.ACTION_SEND).apply {
                      type = "application/pdf"
                      putExtra(Intent.EXTRA_STREAM, uri)
                      putExtra(Intent.EXTRA_SUBJECT, "PS-02 Forensic Audit: ${scan.appName}")
                      addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
                    }
                    context.startActivity(Intent.createChooser(shareIntent, "Export Forensic PDF"))
                  } catch (e: Exception) {
                    isExportingPdf = false
                    pdfMessage = "Export failed: ${e.message}"
                  }
                }
              },
              modifier = Modifier
                .fillMaxWidth()
                .height(48.dp)
                .testTag("btn_export_pdf_dossier"),
              colors = ButtonDefaults.buttonColors(containerColor = ConsoleBluePrimary),
              shape = RoundedCornerShape(6.dp)
            ) {
              if (isExportingPdf) {
                CircularProgressIndicator(modifier = Modifier.size(18.dp), color = Color.White, strokeWidth = 2.dp)
                Spacer(modifier = Modifier.width(8.dp))
                Text("Compiling Forensic PDF...", fontWeight = FontWeight.Bold)
              } else {
                Icon(Icons.Default.PictureAsPdf, contentDescription = null, modifier = Modifier.size(18.dp))
                Spacer(modifier = Modifier.width(8.dp))
                Text("Compile & Export PDF Document", fontWeight = FontWeight.Bold)
              }
            }

            if (pdfMessage != null) {
              Spacer(modifier = Modifier.height(8.dp))
              Text(
                text = pdfMessage ?: "",
                style = MaterialTheme.typography.labelSmall.copy(fontWeight = FontWeight.Bold),
                color = if (pdfMessage?.startsWith("Generated") == true) RiskSafeGreen else SeverityCritical
              )
            }
          }
        }
      }

      // SUPABASE CLOUD STORAGE DOSSIER INGEST
      item {
        Card(
          modifier = Modifier
            .fillMaxWidth()
            .border(1.dp, ConsoleBorder, RoundedCornerShape(8.dp)),
          colors = CardDefaults.cardColors(containerColor = ConsoleWhite),
          shape = RoundedCornerShape(8.dp),
          elevation = CardDefaults.cardElevation(defaultElevation = 0.dp)
        ) {
          Column(modifier = Modifier.padding(16.dp)) {
            Row(
              modifier = Modifier.fillMaxWidth(),
              horizontalArrangement = Arrangement.SpaceBetween,
              verticalAlignment = Alignment.CenterVertically
            ) {
              Row(verticalAlignment = Alignment.CenterVertically) {
                Icon(Icons.Default.CloudUpload, contentDescription = null, tint = ConsoleBluePrimary, modifier = Modifier.size(20.dp))
                Spacer(modifier = Modifier.width(8.dp))
                Text(
                  text = "SUPABASE CLOUD STORAGE SYNC",
                  style = MaterialTheme.typography.labelSmall.copy(fontWeight = FontWeight.Bold, letterSpacing = 1.sp),
                  color = ConsoleBluePrimary
                )
              }

              Surface(
                color = ConsoleBlueBg,
                shape = RoundedCornerShape(4.dp),
                border = androidx.compose.foundation.BorderStroke(1.dp, ConsoleBorder)
              ) {
                Text(
                  text = "Bucket: ${viewModel.supabaseRepo.defaultBucket}",
                  style = MaterialTheme.typography.labelSmall.copy(fontFamily = FontFamily.Monospace),
                  color = ConsoleNavy,
                  modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp)
                )
              }
            }

            Spacer(modifier = Modifier.height(8.dp))
            Text(
              text = "Persist complete cryptographic evidence dossier (JSON artifact and findings metadata) to Supabase Storage for multi-analyst forensics.",
              style = MaterialTheme.typography.bodySmall,
              color = Slate600
            )

            Spacer(modifier = Modifier.height(14.dp))

            when (val state = cloudSyncState) {
              is CloudSyncState.Syncing -> {
                Surface(
                  modifier = Modifier.fillMaxWidth(),
                  color = ConsoleBlueBg,
                  shape = RoundedCornerShape(6.dp),
                  border = androidx.compose.foundation.BorderStroke(1.dp, ConsoleBluePrimary.copy(alpha = 0.4f))
                ) {
                  Row(
                    modifier = Modifier.padding(12.dp),
                    verticalAlignment = Alignment.CenterVertically
                  ) {
                    CircularProgressIndicator(
                      progress = { state.progress },
                      modifier = Modifier.size(20.dp),
                      color = ConsoleBluePrimary,
                      strokeWidth = 2.dp
                    )
                    Spacer(modifier = Modifier.width(10.dp))
                    Text(
                      text = state.stage,
                      style = MaterialTheme.typography.bodySmall.copy(fontWeight = FontWeight.SemiBold),
                      color = ConsoleNavy
                    )
                  }
                }
              }
              is CloudSyncState.Success -> {
                Surface(
                  modifier = Modifier.fillMaxWidth(),
                  color = Color(0xFFF0FDF4),
                  shape = RoundedCornerShape(6.dp),
                  border = androidx.compose.foundation.BorderStroke(1.dp, RiskSafeGreen.copy(alpha = 0.4f))
                ) {
                  Column(modifier = Modifier.padding(12.dp)) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                      Icon(Icons.Default.CloudDone, contentDescription = null, tint = RiskSafeGreen, modifier = Modifier.size(18.dp))
                      Spacer(modifier = Modifier.width(6.dp))
                      Text(
                        text = if (state.uploadResult.isSimulated) "Ingested into Cloud Storage (Sandbox)" else "Cloud Dossier Live on Supabase",
                        style = MaterialTheme.typography.labelMedium.copy(fontWeight = FontWeight.Bold),
                        color = RiskSafeGreen
                      )
                    }
                    Spacer(modifier = Modifier.height(4.dp))
                    Text(
                      text = "Remote Path: ${state.uploadResult.storagePath}",
                      style = MaterialTheme.typography.labelSmall.copy(fontFamily = FontFamily.Monospace),
                      color = Slate800
                    )
                    Text(
                      text = "Payload Size: ${state.uploadResult.fileSizeBytes} B • SHA-256: ${state.uploadResult.sha256Checksum.take(16)}...",
                      style = MaterialTheme.typography.labelSmall.copy(fontFamily = FontFamily.Monospace),
                      color = Slate600
                    )
                  }
                }
              }
              is CloudSyncState.Error -> {
                Surface(
                  modifier = Modifier.fillMaxWidth(),
                  color = SeverityCriticalBg,
                  shape = RoundedCornerShape(6.dp),
                  border = androidx.compose.foundation.BorderStroke(1.dp, SeverityCritical.copy(alpha = 0.4f))
                ) {
                  Row(
                    modifier = Modifier.padding(12.dp),
                    verticalAlignment = Alignment.CenterVertically
                  ) {
                    Icon(Icons.Default.Warning, contentDescription = null, tint = SeverityCritical, modifier = Modifier.size(18.dp))
                    Spacer(modifier = Modifier.width(8.dp))
                    Text(
                      text = "Cloud Sync Error: ${state.message}",
                      style = MaterialTheme.typography.bodySmall,
                      color = SeverityCritical
                    )
                  }
                }
              }
              CloudSyncState.Idle -> { /* Idle */ }
            }

            Spacer(modifier = Modifier.height(10.dp))

            Button(
              onClick = {
                viewModel.uploadActiveScanToCloud()
              },
              modifier = Modifier
                .fillMaxWidth()
                .height(46.dp)
                .testTag("btn_sync_supabase_storage"),
              colors = ButtonDefaults.buttonColors(containerColor = ConsoleNavy),
              shape = RoundedCornerShape(6.dp)
            ) {
              Icon(Icons.Default.CloudUpload, contentDescription = null, modifier = Modifier.size(18.dp))
              Spacer(modifier = Modifier.width(8.dp))
              Text("Upload Forensic Dossier to Supabase", fontWeight = FontWeight.Bold)
            }
          }
        }
      }

      // EXECUTIVE SUMMARY
      item {
        Card(
          modifier = Modifier
            .fillMaxWidth()
            .border(1.dp, ConsoleBorder, RoundedCornerShape(8.dp)),
          colors = CardDefaults.cardColors(containerColor = ConsoleWhite),
          shape = RoundedCornerShape(8.dp),
          elevation = CardDefaults.cardElevation(defaultElevation = 0.dp)
        ) {
          Column(modifier = Modifier.padding(16.dp)) {
            Text(
              text = "Executive Summary",
              style = MaterialTheme.typography.titleSmall.copy(fontWeight = FontWeight.Bold),
              color = ConsoleNavy
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

      // FINDINGS HEADER
      item {
        Text(
          text = "Detailed Forensic Evidence Findings",
          style = MaterialTheme.typography.titleSmall.copy(fontWeight = FontWeight.Bold),
          color = Slate900
        )
      }

      items(findings) { finding ->
        Card(
          modifier = Modifier
            .fillMaxWidth()
            .border(1.dp, ConsoleBorder, RoundedCornerShape(8.dp)),
          colors = CardDefaults.cardColors(containerColor = ConsoleWhite),
          shape = RoundedCornerShape(8.dp),
          elevation = CardDefaults.cardElevation(defaultElevation = 0.dp)
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
                color = ConsoleBluePrimary
              )
              SeverityBadge(severity = finding.severity)
            }

            Spacer(modifier = Modifier.height(6.dp))
            Text(
              text = finding.title,
              style = MaterialTheme.typography.bodyMedium.copy(fontWeight = FontWeight.Bold),
              color = Slate900
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
                color = ConsoleNavy,
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
          modifier = Modifier
            .fillMaxWidth()
            .border(1.dp, SeverityCritical.copy(alpha = 0.3f), RoundedCornerShape(8.dp)),
          colors = CardDefaults.cardColors(containerColor = SeverityCriticalBg),
          shape = RoundedCornerShape(8.dp),
          elevation = CardDefaults.cardElevation(defaultElevation = 0.dp)
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
      modifier = Modifier.width(120.dp)
    )
    Text(
      text = value,
      style = MaterialTheme.typography.labelSmall.copy(
        fontFamily = FontFamily.Monospace,
        fontWeight = FontWeight.Medium
      ),
      color = Slate900,
      maxLines = 1,
      modifier = Modifier.weight(1f)
    )
  }
}
