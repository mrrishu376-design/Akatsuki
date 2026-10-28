package com.example.ui.screens

import androidx.compose.foundation.background
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
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.BugReport
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.History
import androidx.compose.material.icons.filled.PlayArrow
import androidx.compose.material.icons.filled.Security
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material.icons.filled.UploadFile
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.LinearProgressIndicator
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
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.example.data.analyzer.SampleApkCatalog
import com.example.data.model.RiskLabel
import com.example.data.model.ScanRecord
import com.example.data.model.Severity
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
import com.example.ui.theme.SeverityLow
import com.example.ui.theme.Slate200
import com.example.ui.theme.Slate600
import com.example.ui.theme.Slate800
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

@Composable
fun DashboardScreen(viewModel: MainViewModel) {
  val user by viewModel.currentUser.collectAsState()
  val scans by viewModel.allScans.collectAsState()

  val totalScans = scans.size
  val highRiskScans = scans.count { it.riskLabel == RiskLabel.CRITICAL || it.riskLabel == RiskLabel.HIGH }
  val avgScore = if (scans.isNotEmpty()) scans.map { it.riskScore }.average().toInt() else 0
  val safeScans = scans.count { it.riskLabel == RiskLabel.SAFE || it.riskLabel == RiskLabel.LOW }

  Scaffold(
    topBar = {
      CyberTopAppBar(
        title = "PS-02 Security Platform",
        subtitle = "${user?.role ?: "SecOps"} • ${user?.fullName ?: "Auditor"}",
        onProfileClick = { viewModel.navigateTo(Screen.PROFILE) }
      )
    }
  ) { innerPadding ->
    LazyColumn(
      modifier = Modifier
        .fillMaxSize()
        .padding(innerPadding)
        .padding(horizontal = 16.dp),
      verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
      item {
        Spacer(modifier = Modifier.height(4.dp))
        // Quick Action Primary Hero Card
        Card(
          modifier = Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(16.dp)),
          colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
          elevation = CardDefaults.cardElevation(defaultElevation = 2.dp)
        ) {
          Column(modifier = Modifier.padding(18.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
              Box(
                modifier = Modifier
                  .size(44.dp)
                  .clip(CircleShape)
                  .background(CyberBluePrimary.copy(alpha = 0.12f)),
                contentAlignment = Alignment.Center
              ) {
                Icon(
                  imageVector = Icons.Default.Security,
                  contentDescription = null,
                  tint = CyberBluePrimary,
                  modifier = Modifier.size(24.dp)
                )
              }
              Spacer(modifier = Modifier.width(12.dp))
              Column {
                Text(
                  text = "Android APK Forensic Analysis",
                  style = MaterialTheme.typography.titleMedium.copy(fontWeight = FontWeight.Bold),
                  color = MaterialTheme.colorScheme.onSurface
                )
                Text(
                  text = "Zero-execution static vulnerability & threat audit",
                  style = MaterialTheme.typography.bodySmall,
                  color = Slate600
                )
              }
            }

            Spacer(modifier = Modifier.height(16.dp))

            Row(
              modifier = Modifier.fillMaxWidth(),
              horizontalArrangement = Arrangement.spacedBy(10.dp)
            ) {
              Button(
                onClick = { viewModel.navigateTo(Screen.UPLOAD) },
                modifier = Modifier
                  .weight(1f)
                  .height(48.dp)
                  .testTag("btn_dashboard_upload_apk"),
                colors = ButtonDefaults.buttonColors(containerColor = CyberBluePrimary),
                shape = RoundedCornerShape(10.dp)
              ) {
                Icon(Icons.Default.UploadFile, contentDescription = null, modifier = Modifier.size(18.dp))
                Spacer(modifier = Modifier.width(6.dp))
                Text("Select / Upload APK", fontWeight = FontWeight.Bold, fontSize = 13.sp)
              }

              OutlinedButton(
                onClick = { viewModel.navigateTo(Screen.HISTORY) },
                modifier = Modifier
                  .height(48.dp)
                  .testTag("btn_dashboard_history"),
                shape = RoundedCornerShape(10.dp)
              ) {
                Icon(Icons.Default.History, contentDescription = null, modifier = Modifier.size(18.dp))
                Spacer(modifier = Modifier.width(4.dp))
                Text("History", fontWeight = FontWeight.SemiBold, fontSize = 13.sp)
              }
            }
          }
        }
      }

      // KPI METRICS
      item {
        Text(
          text = "Security Audit Metrics",
          style = MaterialTheme.typography.titleSmall.copy(fontWeight = FontWeight.Bold),
          color = MaterialTheme.colorScheme.onBackground
        )
        Spacer(modifier = Modifier.height(8.dp))
        Row(
          modifier = Modifier.fillMaxWidth(),
          horizontalArrangement = Arrangement.spacedBy(10.dp)
        ) {
          KpiCard(
            title = "Total Scans",
            value = "$totalScans",
            icon = Icons.Default.Shield,
            tint = CyberBluePrimary,
            modifier = Modifier.weight(1f)
          )
          KpiCard(
            title = "High Threats",
            value = "$highRiskScans",
            icon = Icons.Default.Warning,
            tint = SeverityCritical,
            modifier = Modifier.weight(1f)
          )
          KpiCard(
            title = "Avg Risk Score",
            value = "$avgScore/100",
            icon = Icons.Default.BugReport,
            tint = SeverityHigh,
            modifier = Modifier.weight(1f)
          )
        }
      }

      // QUICK BENCHMARK TARGETS
      item {
        Card(
          modifier = Modifier.fillMaxWidth(),
          colors = CardDefaults.cardColors(containerColor = Color(0xFFF0F9FF)),
          shape = RoundedCornerShape(14.dp)
        ) {
          Column(modifier = Modifier.padding(16.dp)) {
            Row(
              modifier = Modifier.fillMaxWidth(),
              horizontalArrangement = Arrangement.SpaceBetween,
              verticalAlignment = Alignment.CenterVertically
            ) {
              Text(
                text = "Rapid Benchmark Targets",
                style = MaterialTheme.typography.titleSmall.copy(fontWeight = FontWeight.Bold),
                color = CyberBlueDark
              )
              Surface(
                color = Color.White,
                shape = RoundedCornerShape(4.dp)
              ) {
                Text(
                  text = "DEMO DATA",
                  style = MaterialTheme.typography.labelSmall.copy(fontWeight = FontWeight.Bold),
                  color = CyberBluePrimary,
                  modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp)
                )
              }
            }

            Spacer(modifier = Modifier.height(6.dp))
            Text(
              text = "Test the static forensic pipeline instantly with pre-packaged vulnerability benchmarks:",
              style = MaterialTheme.typography.bodySmall,
              color = Slate600
            )

            Spacer(modifier = Modifier.height(12.dp))

            SampleApkCatalog.benchmarks.take(3).forEach { benchmark ->
              Surface(
                modifier = Modifier
                  .fillMaxWidth()
                  .padding(vertical = 4.dp)
                  .clip(RoundedCornerShape(8.dp))
                  .clickable { viewModel.startBenchmarkAnalysis(benchmark) }
                  .testTag("benchmark_card_${benchmark.id}"),
                color = Color.White,
                shadowElevation = 1.dp
              ) {
                Row(
                  modifier = Modifier.padding(12.dp),
                  verticalAlignment = Alignment.CenterVertically
                ) {
                  Box(
                    modifier = Modifier
                      .size(34.dp)
                      .clip(CircleShape)
                      .background(
                        if (benchmark.expectedRiskScore > 70) SeverityCritical.copy(alpha = 0.15f)
                        else if (benchmark.expectedRiskScore > 40) SeverityMedium.copy(alpha = 0.15f)
                        else RiskSafeGreen.copy(alpha = 0.15f)
                      ),
                    contentAlignment = Alignment.Center
                  ) {
                    Icon(
                      imageVector = Icons.Default.PlayArrow,
                      contentDescription = "Run Benchmark",
                      tint = if (benchmark.expectedRiskScore > 70) SeverityCritical else CyberBluePrimary,
                      modifier = Modifier.size(18.dp)
                    )
                  }

                  Spacer(modifier = Modifier.width(10.dp))

                  Column(modifier = Modifier.weight(1f)) {
                    Text(
                      text = benchmark.name,
                      style = MaterialTheme.typography.bodyMedium.copy(fontWeight = FontWeight.Bold),
                      color = MaterialTheme.colorScheme.onSurface
                    )
                    Text(
                      text = "${benchmark.category} • Expected Risk: ${benchmark.expectedRiskScore}/100",
                      style = MaterialTheme.typography.bodySmall,
                      color = Slate600
                    )
                  }
                }
              }
            }
          }
        }
      }

      // RECENT AUDITS SECTION
      item {
        Row(
          modifier = Modifier.fillMaxWidth(),
          horizontalArrangement = Arrangement.SpaceBetween,
          verticalAlignment = Alignment.CenterVertically
        ) {
          Text(
            text = "Recent Forensic Audits",
            style = MaterialTheme.typography.titleSmall.copy(fontWeight = FontWeight.Bold),
            color = MaterialTheme.colorScheme.onBackground
          )
          if (scans.isNotEmpty()) {
            Text(
              text = "View All (${scans.size})",
              style = MaterialTheme.typography.labelMedium.copy(fontWeight = FontWeight.Bold),
              color = CyberBluePrimary,
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
            modifier = Modifier.fillMaxWidth(),
            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
            shape = RoundedCornerShape(12.dp)
          ) {
            Column(
              modifier = Modifier
                .fillMaxWidth()
                .padding(28.dp),
              horizontalAlignment = Alignment.CenterHorizontally
            ) {
              Icon(
                imageVector = Icons.Default.Security,
                contentDescription = null,
                tint = Slate600,
                modifier = Modifier.size(40.dp)
              )
              Spacer(modifier = Modifier.height(10.dp))
              Text(
                text = "No Scans Recorded Yet",
                style = MaterialTheme.typography.titleMedium.copy(fontWeight = FontWeight.Bold),
                color = MaterialTheme.colorScheme.onSurface
              )
              Text(
                text = "Upload an Android APK or choose a benchmark above to perform static vulnerability analysis.",
                style = MaterialTheme.typography.bodySmall,
                color = Slate600,
                textAlign = androidx.compose.ui.text.style.TextAlign.Center,
                modifier = Modifier.padding(horizontal = 16.dp, vertical = 6.dp)
              )
              Spacer(modifier = Modifier.height(12.dp))
              Button(
                onClick = { viewModel.navigateTo(Screen.UPLOAD) },
                colors = ButtonDefaults.buttonColors(containerColor = CyberBluePrimary),
                shape = RoundedCornerShape(8.dp)
              ) {
                Text("Start First APK Scan")
              }
            }
          }
        }
      } else {
        items(scans.take(5)) { scan ->
          ScanRecordItemCard(
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
fun KpiCard(
  title: String,
  value: String,
  icon: ImageVector,
  tint: Color,
  modifier: Modifier = Modifier
) {
  Card(
    modifier = modifier,
    colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
    shape = RoundedCornerShape(12.dp),
    elevation = CardDefaults.cardElevation(defaultElevation = 1.dp)
  ) {
    Column(modifier = Modifier.padding(12.dp)) {
      Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically
      ) {
        Icon(imageVector = icon, contentDescription = null, tint = tint, modifier = Modifier.size(18.dp))
      }
      Spacer(modifier = Modifier.height(6.dp))
      Text(
        text = value,
        style = MaterialTheme.typography.titleLarge.copy(
          fontWeight = FontWeight.Black,
          fontFamily = FontFamily.Monospace
        ),
        color = tint
      )
      Text(
        text = title,
        style = MaterialTheme.typography.labelSmall,
        color = Slate600
      )
    }
  }
}

@Composable
fun ScanRecordItemCard(
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

  Card(
    modifier = Modifier
      .fillMaxWidth()
      .clip(RoundedCornerShape(12.dp))
      .clickable(onClick = onClick)
      .testTag("scan_item_${scan.id}"),
    colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
    elevation = CardDefaults.cardElevation(defaultElevation = 1.dp)
  ) {
    Row(
      modifier = Modifier.padding(14.dp),
      verticalAlignment = Alignment.CenterVertically
    ) {
      Column(
        horizontalAlignment = Alignment.CenterHorizontally,
        modifier = Modifier.width(52.dp)
      ) {
        Text(
          text = "${scan.riskScore}",
          style = MaterialTheme.typography.titleLarge.copy(
            fontWeight = FontWeight.Black,
            fontFamily = FontFamily.Monospace
          ),
          color = when (scan.riskLabel) {
            RiskLabel.CRITICAL -> SeverityCritical
            RiskLabel.HIGH -> SeverityHigh
            RiskLabel.MEDIUM -> SeverityMedium
            RiskLabel.LOW -> SeverityLow
            RiskLabel.SAFE -> RiskSafeGreen
          }
        )
        Text(
          text = "SCORE",
          style = MaterialTheme.typography.labelSmall,
          color = Slate600,
          fontSize = 9.sp
        )
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
            color = MaterialTheme.colorScheme.onSurface,
            maxLines = 1,
            modifier = Modifier.weight(1f)
          )
          SeverityBadge(severity = badgeSeverity)
        }

        Spacer(modifier = Modifier.height(2.dp))

        Text(
          text = scan.packageName,
          style = MaterialTheme.typography.bodySmall.copy(fontFamily = FontFamily.Monospace),
          color = Slate600,
          fontSize = 11.sp,
          maxLines = 1
        )

        Spacer(modifier = Modifier.height(6.dp))

        Row(
          modifier = Modifier.fillMaxWidth(),
          horizontalArrangement = Arrangement.SpaceBetween
        ) {
          Text(
            text = "SHA: ${scan.sha256Hash.take(12)}...",
            style = MaterialTheme.typography.labelSmall.copy(fontFamily = FontFamily.Monospace),
            color = Slate600
          )
          Text(
            text = dateStr,
            style = MaterialTheme.typography.labelSmall,
            color = Slate600
          )
        }
      }
    }
  }
}
