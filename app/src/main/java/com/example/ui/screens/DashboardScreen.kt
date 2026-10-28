package com.example.ui.screens

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
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
import androidx.compose.material.icons.filled.BugReport
import androidx.compose.material.icons.filled.CloudUpload
import androidx.compose.material.icons.filled.Description
import androidx.compose.material.icons.filled.History
import androidx.compose.material.icons.filled.PlayArrow
import androidx.compose.material.icons.filled.Policy
import androidx.compose.material.icons.filled.Public
import androidx.compose.material.icons.filled.Security
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material.icons.filled.UploadFile
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
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.example.LocalNavigationDrawerToggle
import com.example.data.analyzer.SampleApkCatalog
import com.example.data.model.RiskLabel
import com.example.data.model.ScanRecord
import com.example.data.model.Severity
import com.example.ui.MainViewModel
import com.example.ui.components.CyberTopAppBar
import com.example.ui.components.SeverityBadge
import com.example.ui.navigation.Screen
import com.example.ui.theme.ConsoleBlueBg
import com.example.ui.theme.ConsoleBluePrimary
import com.example.ui.theme.ConsoleBorder
import com.example.ui.theme.ConsoleNavy
import com.example.ui.theme.ConsoleNavyBorder
import com.example.ui.theme.RiskSafeGreen
import com.example.ui.theme.SeverityCritical
import com.example.ui.theme.SeverityCriticalBg
import com.example.ui.theme.SeverityCriticalBorder
import com.example.ui.theme.SeverityHigh
import com.example.ui.theme.SeverityHighBg
import com.example.ui.theme.SeverityHighBorder
import com.example.ui.theme.SeverityLow
import com.example.ui.theme.SeverityMedium
import com.example.ui.theme.SeverityMediumBg
import com.example.ui.theme.SeverityMediumBorder
import com.example.ui.theme.Slate200
import com.example.ui.theme.Slate600
import com.example.ui.theme.Slate700
import com.example.ui.theme.Slate800
import com.example.ui.theme.Slate900
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

@Composable
fun DashboardScreen(viewModel: MainViewModel) {
  val user by viewModel.currentUser.collectAsState()
  val scans by viewModel.allScans.collectAsState()
  val toggleDrawer = LocalNavigationDrawerToggle.current

  val totalScans = scans.size
  val criticalCount = scans.count { it.riskLabel == RiskLabel.CRITICAL }
  val highThreatScans = scans.count { it.riskLabel == RiskLabel.HIGH }
  val avgScore = if (scans.isNotEmpty()) scans.map { it.riskScore }.average().toInt() else 0
  val cleanScans = scans.count { it.riskLabel == RiskLabel.SAFE || it.riskLabel == RiskLabel.LOW }

  Scaffold(
    topBar = {
      CyberTopAppBar(
        title = "Enterprise Security Console",
        subtitle = "SOC Lead: ${user?.fullName ?: "Alex Mercer"} • Threat Intel Active",
        onMenuClick = toggleDrawer,
        onProfileClick = { viewModel.navigateTo(Screen.PROFILE) }
      )
    },
    containerColor = Color.White
  ) { innerPadding ->
    LazyColumn(
      modifier = Modifier
        .fillMaxSize()
        .background(Color.White)
        .padding(innerPadding)
        .padding(horizontal = 16.dp),
      verticalArrangement = Arrangement.spacedBy(14.dp)
    ) {
      item {
        Spacer(modifier = Modifier.height(4.dp))

        // FOCUS: LARGE APK INVESTIGATION HERO CARD WITH LARGE UPLOAD BUTTON
        Card(
          modifier = Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(8.dp))
            .border(1.dp, ConsoleBorder, RoundedCornerShape(8.dp)),
          colors = CardDefaults.cardColors(containerColor = Color(0xFFF8FAFC)),
          elevation = CardDefaults.cardElevation(defaultElevation = 0.dp)
        ) {
          Column(modifier = Modifier.padding(18.dp)) {
            Row(
              modifier = Modifier.fillMaxWidth(),
              horizontalArrangement = Arrangement.SpaceBetween,
              verticalAlignment = Alignment.CenterVertically
            ) {
              Row(verticalAlignment = Alignment.CenterVertically) {
                Box(
                  modifier = Modifier
                    .size(36.dp)
                    .clip(RoundedCornerShape(6.dp))
                    .background(ConsoleNavy),
                  contentAlignment = Alignment.Center
                ) {
                  Icon(
                    imageVector = Icons.Default.Security,
                    contentDescription = null,
                    tint = Color(0xFF38BDF8),
                    modifier = Modifier.size(20.dp)
                  )
                }
                Spacer(modifier = Modifier.width(10.dp))
                Column {
                  Text(
                    text = "APK SECURITY INVESTIGATION",
                    style = MaterialTheme.typography.titleMedium.copy(
                      fontWeight = FontWeight.Black,
                      letterSpacing = 0.5.sp
                    ),
                    color = Slate900
                  )
                  Text(
                    text = "Static Manifest, Bytecode, Permission & Network Indicator Audit",
                    style = MaterialTheme.typography.bodySmall,
                    color = Slate600
                  )
                }
              }
            }

            Spacer(modifier = Modifier.height(16.dp))

            // LARGE UPLOAD APK BUTTON (PRIMARY FOCUS)
            Button(
              onClick = { viewModel.navigateTo(Screen.UPLOAD) },
              modifier = Modifier
                .fillMaxWidth()
                .height(54.dp)
                .testTag("btn_large_upload_apk"),
              colors = ButtonDefaults.buttonColors(containerColor = ConsoleBluePrimary),
              shape = RoundedCornerShape(6.dp)
            ) {
              Icon(
                imageVector = Icons.Default.UploadFile,
                contentDescription = null,
                modifier = Modifier.size(22.dp)
              )
              Spacer(modifier = Modifier.width(10.dp))
              Text(
                text = "UPLOAD APK FOR INVESTIGATION",
                fontWeight = FontWeight.Bold,
                fontSize = 14.sp,
                letterSpacing = 0.5.sp
              )
            }

            Spacer(modifier = Modifier.height(10.dp))

            Row(
              modifier = Modifier.fillMaxWidth(),
              horizontalArrangement = Arrangement.SpaceBetween
            ) {
              Text(
                text = "• Zero-execution sandbox",
                style = MaterialTheme.typography.labelSmall,
                color = Slate600
              )
              Text(
                text = "• SHA-256 hash provenance",
                style = MaterialTheme.typography.labelSmall,
                color = Slate600
              )
              Text(
                text = "• Full PDF report export",
                style = MaterialTheme.typography.labelSmall,
                color = Slate600
              )
            }
          }
        }
      }

      // ENTERPRISE METRICS STRIP (MINIMAL CARDS, RED/ORANGE THREAT INDICATORS)
      item {
        Text(
          text = "ENTERPRISE THREAT RADAR",
          style = MaterialTheme.typography.labelSmall.copy(
            fontWeight = FontWeight.Bold,
            letterSpacing = 1.sp,
            fontSize = 11.sp
          ),
          color = ConsoleNavy
        )
        Spacer(modifier = Modifier.height(6.dp))

        Row(
          modifier = Modifier.fillMaxWidth(),
          horizontalArrangement = Arrangement.spacedBy(8.dp)
        ) {
          EnterpriseKpiCard(
            label = "TOTAL SCANS",
            value = "$totalScans",
            color = ConsoleBluePrimary,
            modifier = Modifier.weight(1f)
          )
          EnterpriseKpiCard(
            label = "CRITICAL THREATS",
            value = "$criticalCount",
            color = SeverityCritical,
            modifier = Modifier.weight(1f),
            alertBg = criticalCount > 0
          )
          EnterpriseKpiCard(
            label = "HIGH THREATS",
            value = "$highThreatScans",
            color = SeverityHigh,
            modifier = Modifier.weight(1f),
            alertBg = highThreatScans > 0
          )
          EnterpriseKpiCard(
            label = "AVG RISK",
            value = "$avgScore",
            color = if (avgScore > 50) SeverityCritical else ConsoleNavy,
            modifier = Modifier.weight(1f)
          )
        }
      }

      // INVESTIGATION FOCUS: NETWORK INDICATORS & PERMISSION THREATS PREVIEW
      item {
        Card(
          modifier = Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(8.dp))
            .border(1.dp, ConsoleBorder, RoundedCornerShape(8.dp)),
          colors = CardDefaults.cardColors(containerColor = Color.White),
          elevation = CardDefaults.cardElevation(defaultElevation = 0.dp)
        ) {
          Column(modifier = Modifier.padding(14.dp)) {
            Text(
              text = "CORE FORENSIC INVESTIGATION CAPABILITIES",
              style = MaterialTheme.typography.labelSmall.copy(
                fontWeight = FontWeight.Bold,
                letterSpacing = 0.8.sp,
                fontSize = 10.sp
              ),
              color = Slate600
            )

            Spacer(modifier = Modifier.height(10.dp))

            Row(
              modifier = Modifier.fillMaxWidth(),
              horizontalArrangement = Arrangement.spacedBy(8.dp)
            ) {
              CapabilityPill(
                icon = Icons.Default.Policy,
                title = "Permission Analysis",
                desc = "MITRE ATT&CK vectors, background location, SMS & tapjacking checks",
                color = ConsoleBluePrimary,
                modifier = Modifier.weight(1f)
              )
              CapabilityPill(
                icon = Icons.Default.Public,
                title = "Network & Secrets",
                desc = "Cleartext HTTP leaks, hardcoded AWS keys, and C2 endpoints",
                color = SeverityHigh,
                modifier = Modifier.weight(1f)
              )
            }
          }
        }
      }

      // RAPID BENCHMARK TARGETS
      item {
        Row(
          modifier = Modifier.fillMaxWidth(),
          horizontalArrangement = Arrangement.SpaceBetween,
          verticalAlignment = Alignment.CenterVertically
        ) {
          Text(
            text = "VERIFIED INVESTIGATION BENCHMARKS",
            style = MaterialTheme.typography.labelSmall.copy(
              fontWeight = FontWeight.Bold,
              letterSpacing = 1.sp,
              fontSize = 11.sp
            ),
            color = ConsoleNavy
          )
          Surface(
            color = Color(0xFFF1F5F9),
            shape = RoundedCornerShape(3.dp),
            border = androidx.compose.foundation.BorderStroke(1.dp, ConsoleBorder)
          ) {
            Text(
              text = "DEMO DATA",
              style = MaterialTheme.typography.labelSmall.copy(fontSize = 9.sp, fontWeight = FontWeight.Bold),
              color = Slate600,
              modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp)
            )
          }
        }

        Spacer(modifier = Modifier.height(6.dp))

        SampleApkCatalog.benchmarks.take(3).forEach { benchmark ->
          val isCritical = benchmark.expectedRiskScore >= 75
          val isHigh = benchmark.expectedRiskScore in 50..74

          Surface(
            modifier = Modifier
              .fillMaxWidth()
              .padding(vertical = 3.dp)
              .clip(RoundedCornerShape(6.dp))
              .border(1.dp, ConsoleBorder, RoundedCornerShape(6.dp))
              .clickable { viewModel.startBenchmarkAnalysis(benchmark) }
              .testTag("benchmark_btn_${benchmark.id}"),
            color = Color.White
          ) {
            Row(
              modifier = Modifier.padding(12.dp),
              verticalAlignment = Alignment.CenterVertically
            ) {
              // Prominent Score box
              Box(
                modifier = Modifier
                  .size(42.dp)
                  .clip(RoundedCornerShape(4.dp))
                  .background(
                    if (isCritical) SeverityCriticalBg
                    else if (isHigh) SeverityHighBg
                    else Color(0xFFDCFCE7)
                  )
                  .border(
                    1.dp,
                    if (isCritical) SeverityCriticalBorder
                    else if (isHigh) SeverityHighBorder
                    else Color(0xFF86EFAC),
                    RoundedCornerShape(4.dp)
                  ),
                contentAlignment = Alignment.Center
              ) {
                Text(
                  text = "${benchmark.expectedRiskScore}",
                  style = MaterialTheme.typography.titleMedium.copy(
                    fontWeight = FontWeight.Black,
                    fontFamily = FontFamily.Monospace
                  ),
                  color = if (isCritical) SeverityCritical else if (isHigh) SeverityHigh else RiskSafeGreen
                )
              }

              Spacer(modifier = Modifier.width(12.dp))

              Column(modifier = Modifier.weight(1f)) {
                Text(
                  text = benchmark.name,
                  style = MaterialTheme.typography.bodyMedium.copy(fontWeight = FontWeight.Bold),
                  color = Slate900
                )
                Text(
                  text = benchmark.description,
                  style = MaterialTheme.typography.bodySmall.copy(fontSize = 11.sp),
                  color = Slate600,
                  maxLines = 1
                )
              }

              Button(
                onClick = { viewModel.startBenchmarkAnalysis(benchmark) },
                colors = ButtonDefaults.buttonColors(containerColor = ConsoleBluePrimary),
                shape = RoundedCornerShape(4.dp),
                modifier = Modifier.height(34.dp)
              ) {
                Text("Audit", fontSize = 11.sp, fontWeight = FontWeight.Bold)
              }
            }
          }
        }
      }

      // RECENT AUDITS FEED
      item {
        Row(
          modifier = Modifier.fillMaxWidth(),
          horizontalArrangement = Arrangement.SpaceBetween,
          verticalAlignment = Alignment.CenterVertically
        ) {
          Text(
            text = "RECENT FORENSIC AUDITS (${scans.size})",
            style = MaterialTheme.typography.labelSmall.copy(
              fontWeight = FontWeight.Bold,
              letterSpacing = 1.sp,
              fontSize = 11.sp
            ),
            color = ConsoleNavy
          )
          if (scans.isNotEmpty()) {
            Text(
              text = "View All History",
              style = MaterialTheme.typography.labelSmall.copy(fontWeight = FontWeight.Bold),
              color = ConsoleBluePrimary,
              modifier = Modifier
                .clickable { viewModel.navigateTo(Screen.HISTORY) }
                .padding(4.dp)
            )
          }
        }
      }

      if (scans.isEmpty()) {
        item {
          Card(
            modifier = Modifier
              .fillMaxWidth()
              .border(1.dp, ConsoleBorder, RoundedCornerShape(6.dp)),
            colors = CardDefaults.cardColors(containerColor = Color.White)
          ) {
            Column(
              modifier = Modifier.padding(28.dp),
              horizontalAlignment = Alignment.CenterHorizontally
            ) {
              Text("No forensic investigations recorded yet.", style = MaterialTheme.typography.bodyMedium, color = Slate600)
              Spacer(modifier = Modifier.height(10.dp))
              Button(
                onClick = { viewModel.navigateTo(Screen.UPLOAD) },
                colors = ButtonDefaults.buttonColors(containerColor = ConsoleBluePrimary),
                shape = RoundedCornerShape(4.dp)
              ) {
                Text("Start First APK Audit")
              }
            }
          }
        }
      } else {
        items(scans.take(5)) { scan ->
          EnterpriseScanItemCard(
            scan = scan,
            onClick = { viewModel.openHistoricalScan(scan) }
          )
        }
      }

      item {
        Spacer(modifier = Modifier.height(16.dp))
      }
    }
  }
}

@Composable
fun EnterpriseKpiCard(
  label: String,
  value: String,
  color: Color,
  modifier: Modifier = Modifier,
  alertBg: Boolean = false
) {
  Card(
    modifier = modifier
      .clip(RoundedCornerShape(6.dp))
      .border(1.dp, if (alertBg) color.copy(alpha = 0.5f) else ConsoleBorder, RoundedCornerShape(6.dp)),
    colors = CardDefaults.cardColors(
      containerColor = if (alertBg) color.copy(alpha = 0.08f) else Color.White
    ),
    elevation = CardDefaults.cardElevation(defaultElevation = 0.dp)
  ) {
    Column(modifier = Modifier.padding(10.dp), horizontalAlignment = Alignment.CenterHorizontally) {
      Text(
        text = value,
        style = MaterialTheme.typography.titleLarge.copy(
          fontWeight = FontWeight.Black,
          fontFamily = FontFamily.Monospace
        ),
        color = color
      )
      Spacer(modifier = Modifier.height(2.dp))
      Text(
        text = label,
        style = MaterialTheme.typography.labelSmall.copy(
          fontWeight = FontWeight.Bold,
          fontSize = 8.5.sp,
          letterSpacing = 0.5.sp
        ),
        color = Slate600,
        maxLines = 1
      )
    }
  }
}

@Composable
fun CapabilityPill(
  icon: ImageVector,
  title: String,
  desc: String,
  color: Color,
  modifier: Modifier = Modifier
) {
  Surface(
    modifier = modifier
      .clip(RoundedCornerShape(6.dp))
      .border(1.dp, ConsoleBorder, RoundedCornerShape(6.dp)),
    color = Color(0xFFF8FAFC)
  ) {
    Row(modifier = Modifier.padding(10.dp), verticalAlignment = Alignment.CenterVertically) {
      Box(
        modifier = Modifier
          .size(30.dp)
          .clip(CircleShape)
          .background(color.copy(alpha = 0.12f)),
        contentAlignment = Alignment.Center
      ) {
        Icon(icon, contentDescription = null, tint = color, modifier = Modifier.size(16.dp))
      }
      Spacer(modifier = Modifier.width(8.dp))
      Column {
        Text(text = title, style = MaterialTheme.typography.bodySmall.copy(fontWeight = FontWeight.Bold), color = Slate900)
        Text(text = desc, style = MaterialTheme.typography.labelSmall.copy(fontSize = 9.sp), color = Slate600, maxLines = 1)
      }
    }
  }
}

@Composable
fun EnterpriseScanItemCard(
  scan: ScanRecord,
  onClick: () -> Unit
) {
  val dateFormat = SimpleDateFormat("MMM dd, yyyy HH:mm", Locale.getDefault())
  val dateStr = dateFormat.format(Date(scan.completedAt))

  val badgeSeverity = when (scan.riskLabel) {
    RiskLabel.CRITICAL -> Severity.CRITICAL
    RiskLabel.HIGH -> Severity.HIGH
    RiskLabel.MEDIUM -> Severity.MEDIUM
    RiskLabel.LOW -> Severity.LOW
    RiskLabel.SAFE -> Severity.INFO
  }

  val scoreColor = when (scan.riskLabel) {
    RiskLabel.CRITICAL -> SeverityCritical
    RiskLabel.HIGH -> SeverityHigh
    RiskLabel.MEDIUM -> SeverityMedium
    RiskLabel.LOW -> SeverityLow
    RiskLabel.SAFE -> RiskSafeGreen
  }

  Card(
    modifier = Modifier
      .fillMaxWidth()
      .clip(RoundedCornerShape(6.dp))
      .border(1.dp, ConsoleBorder, RoundedCornerShape(6.dp))
      .clickable(onClick = onClick)
      .testTag("scan_item_${scan.id}"),
    colors = CardDefaults.cardColors(containerColor = Color.White),
    elevation = CardDefaults.cardElevation(defaultElevation = 0.dp)
  ) {
    Row(
      modifier = Modifier.padding(12.dp),
      verticalAlignment = Alignment.CenterVertically
    ) {
      // Score Block
      Box(
        modifier = Modifier
          .size(46.dp)
          .clip(RoundedCornerShape(4.dp))
          .background(scoreColor.copy(alpha = 0.12f))
          .border(1.dp, scoreColor.copy(alpha = 0.4f), RoundedCornerShape(4.dp)),
        contentAlignment = Alignment.Center
      ) {
        Column(horizontalAlignment = Alignment.CenterHorizontally) {
          Text(
            text = "${scan.riskScore}",
            style = MaterialTheme.typography.titleMedium.copy(
              fontWeight = FontWeight.Black,
              fontFamily = FontFamily.Monospace
            ),
            color = scoreColor
          )
          Text(text = "SCORE", style = MaterialTheme.typography.labelSmall.copy(fontSize = 7.5.sp, fontWeight = FontWeight.Bold), color = scoreColor)
        }
      }

      Spacer(modifier = Modifier.width(12.dp))

      Column(modifier = Modifier.weight(1f)) {
        Row(
          modifier = Modifier.fillMaxWidth(),
          horizontalArrangement = Arrangement.SpaceBetween,
          verticalAlignment = Alignment.CenterVertically
        ) {
          Text(
            text = scan.appName,
            style = MaterialTheme.typography.bodyMedium.copy(fontWeight = FontWeight.Bold),
            color = Slate900,
            maxLines = 1,
            modifier = Modifier.weight(1f)
          )
          SeverityBadge(severity = badgeSeverity)
        }

        Spacer(modifier = Modifier.height(2.dp))

        Text(
          text = scan.packageName,
          style = MaterialTheme.typography.bodySmall.copy(fontFamily = FontFamily.Monospace, fontSize = 11.sp),
          color = Slate600,
          maxLines = 1
        )

        Spacer(modifier = Modifier.height(4.dp))

        Row(
          modifier = Modifier.fillMaxWidth(),
          horizontalArrangement = Arrangement.SpaceBetween
        ) {
          Text(
            text = "SHA: ${scan.sha256Hash.take(12)}... • ${scan.permissionsCount} perms",
            style = MaterialTheme.typography.labelSmall.copy(fontFamily = FontFamily.Monospace, fontSize = 10.sp),
            color = Slate600
          )
          Text(
            text = dateStr,
            style = MaterialTheme.typography.labelSmall.copy(fontSize = 10.sp),
            color = Slate600
          )
        }
      }
    }
  }
}
