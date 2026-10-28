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
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Assignment
import androidx.compose.material.icons.filled.Calculate
import androidx.compose.material.icons.filled.ChevronRight
import androidx.compose.material.icons.filled.Description
import androidx.compose.material.icons.filled.Info
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.Security
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.ScrollableTabRow
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Tab
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.example.data.model.ScanFinding
import com.example.data.model.Severity
import com.example.ui.MainViewModel
import com.example.ui.components.CyberTopAppBar
import com.example.ui.components.RiskGauge
import com.example.ui.components.SeverityBadge
import com.example.ui.navigation.Screen
import com.example.ui.theme.CyberAccentCyan
import com.example.ui.theme.CyberBlueDark
import com.example.ui.theme.CyberBluePrimary
import com.example.ui.theme.SeverityCritical
import com.example.ui.theme.SeverityHigh
import com.example.ui.theme.SeverityMedium
import com.example.ui.theme.Slate200
import com.example.ui.theme.Slate600
import com.example.ui.theme.Slate800

@Composable
fun AnalysisResultsScreen(viewModel: MainViewModel) {
  val activeResult by viewModel.activeScanResult.collectAsState()
  var selectedCategoryTab by remember { mutableStateOf("ALL") }
  var showFormulaExplanation by remember { mutableStateOf(false) }

  val scan = activeResult?.scan
  val findings = activeResult?.findings ?: emptyList()

  val filteredFindings = if (selectedCategoryTab == "ALL") {
    findings
  } else {
    findings.filter { it.category == selectedCategoryTab }
  }

  Scaffold(
    topBar = {
      CyberTopAppBar(
        title = "Static Analysis Results",
        subtitle = scan?.appName ?: "APK Assessment",
        showBack = true,
        onBackClick = { viewModel.navigateTo(Screen.DASHBOARD) },
        onProfileClick = { viewModel.navigateTo(Screen.PROFILE) }
      )
    }
  ) { innerPadding ->
    if (scan == null) {
      Box(
        modifier = Modifier
          .fillMaxSize()
          .padding(innerPadding),
        contentAlignment = Alignment.Center
      ) {
        Text("No active scan results loaded.")
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

        // DEMO DATA NOTICE IF APPLICABLE
        if (scan.isDemoData) {
          Surface(
            modifier = Modifier.fillMaxWidth(),
            color = Color(0xFFFEF3C7),
            shape = RoundedCornerShape(8.dp)
          ) {
            Row(
              modifier = Modifier.padding(10.dp),
              verticalAlignment = Alignment.CenterVertically
            ) {
              Icon(Icons.Default.Info, contentDescription = null, tint = Color(0xFFD97706), modifier = Modifier.size(18.dp))
              Spacer(modifier = Modifier.width(8.dp))
              Text(
                text = "DEMO BENCHMARK DATA: This evaluation was executed using pre-packaged test target parameters.",
                style = MaterialTheme.typography.bodySmall.copy(fontWeight = FontWeight.Medium),
                color = Color(0xFF92400E)
              )
            }
          }
          Spacer(modifier = Modifier.height(8.dp))
        }

        // RISK SCORE CARD WITH GAUGE
        Card(
          modifier = Modifier.fillMaxWidth(),
          colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
          shape = RoundedCornerShape(16.dp),
          elevation = CardDefaults.cardElevation(defaultElevation = 2.dp)
        ) {
          Column(
            modifier = Modifier
              .fillMaxWidth()
              .padding(20.dp),
            horizontalAlignment = Alignment.CenterHorizontally
          ) {
            Text(
              text = scan.appName,
              style = MaterialTheme.typography.titleLarge.copy(fontWeight = FontWeight.Bold),
              color = MaterialTheme.colorScheme.onSurface
            )
            Text(
              text = "${scan.packageName} • v${scan.versionName}",
              style = MaterialTheme.typography.bodySmall.copy(fontFamily = FontFamily.Monospace),
              color = Slate600
            )

            Spacer(modifier = Modifier.height(16.dp))

            RiskGauge(score = scan.riskScore, riskLabel = scan.riskLabel)

            Spacer(modifier = Modifier.height(14.dp))

            // Score Explanation Toggle
            Surface(
              modifier = Modifier
                .clip(RoundedCornerShape(8.dp))
                .clickable { showFormulaExplanation = !showFormulaExplanation }
                .padding(horizontal = 12.dp, vertical = 6.dp),
              color = Color(0xFFF1F5F9)
            ) {
              Row(verticalAlignment = Alignment.CenterVertically) {
                Icon(Icons.Default.Calculate, contentDescription = null, tint = CyberBluePrimary, modifier = Modifier.size(16.dp))
                Spacer(modifier = Modifier.width(6.dp))
                Text(
                  text = if (showFormulaExplanation) "Hide Risk Formula" else "How is this score calculated?",
                  style = MaterialTheme.typography.labelMedium.copy(fontWeight = FontWeight.Bold),
                  color = CyberBluePrimary
                )
              }
            }

            if (showFormulaExplanation) {
              Spacer(modifier = Modifier.height(10.dp))
              Surface(
                modifier = Modifier.fillMaxWidth(),
                color = Color(0xFFF8FAFC),
                shape = RoundedCornerShape(8.dp)
              ) {
                Column(modifier = Modifier.padding(12.dp)) {
                  Text(
                    text = "Risk Calculation Formula (0-100):",
                    style = MaterialTheme.typography.labelMedium.copy(fontWeight = FontWeight.Bold),
                    color = CyberBlueDark
                  )
                  Text(
                    text = "Score = Min(100, (Critical x 25) + (High x 15) + (Medium x 8) + (Low x 3))\n" +
                        "• Critical (${scan.criticalCount}x) = ${scan.criticalCount * 25} pts\n" +
                        "• High (${scan.highCount}x) = ${scan.highCount * 15} pts\n" +
                        "• Medium (${scan.mediumCount}x) = ${scan.mediumCount * 8} pts\n" +
                        "• Low (${scan.lowCount}x) = ${scan.lowCount * 3} pts\n" +
                        "Raw Score = ${(scan.criticalCount * 25) + (scan.highCount * 15) + (scan.mediumCount * 8) + (scan.lowCount * 3)} -> Final Capped Score: ${scan.riskScore}/100",
                    style = MaterialTheme.typography.bodySmall.copy(
                      fontFamily = FontFamily.Monospace,
                      fontSize = 11.sp,
                      lineHeight = 16.sp
                    ),
                    color = Slate600
                  )
                }
              }
            }

            Spacer(modifier = Modifier.height(14.dp))
            HorizontalDivider(color = Color(0xFFE2E8F0))
            Spacer(modifier = Modifier.height(12.dp))

            // Finding count pill indicators
            Row(
              modifier = Modifier.fillMaxWidth(),
              horizontalArrangement = Arrangement.SpaceEvenly
            ) {
              CountPill(label = "Critical", count = scan.criticalCount, color = SeverityCritical)
              CountPill(label = "High", count = scan.highCount, color = SeverityHigh)
              CountPill(label = "Medium", count = scan.mediumCount, color = SeverityMedium)
              CountPill(label = "Perms", count = scan.permissionsCount, color = CyberBluePrimary)
            }
          }
        }
      }

      // PRIMARY ACTION SHORTCUTS (Permissions & Forensic Report)
      item {
        Row(
          modifier = Modifier.fillMaxWidth(),
          horizontalArrangement = Arrangement.spacedBy(10.dp)
        ) {
          Button(
            onClick = { viewModel.navigateTo(Screen.PERMISSIONS) },
            modifier = Modifier
              .weight(1f)
              .height(48.dp)
              .testTag("btn_view_permissions_threats"),
            colors = ButtonDefaults.buttonColors(containerColor = CyberBluePrimary),
            shape = RoundedCornerShape(10.dp)
          ) {
            Icon(Icons.Default.Security, contentDescription = null, modifier = Modifier.size(18.dp))
            Spacer(modifier = Modifier.width(6.dp))
            Text("Permissions & Threats", fontWeight = FontWeight.Bold, fontSize = 12.sp)
          }

          Button(
            onClick = { viewModel.navigateTo(Screen.REPORT) },
            modifier = Modifier
              .weight(1f)
              .height(48.dp)
              .testTag("btn_view_forensic_report"),
            colors = ButtonDefaults.buttonColors(containerColor = CyberBlueDark),
            shape = RoundedCornerShape(10.dp)
          ) {
            Icon(Icons.Default.Description, contentDescription = null, modifier = Modifier.size(18.dp))
            Spacer(modifier = Modifier.width(6.dp))
            Text("Forensic Dossier", fontWeight = FontWeight.Bold, fontSize = 12.sp)
          }
        }
      }

      // FINDINGS CATEGORY TABS
      item {
        Text(
          text = "Identified Static Vulnerabilities (${findings.size})",
          style = MaterialTheme.typography.titleSmall.copy(fontWeight = FontWeight.Bold),
          color = MaterialTheme.colorScheme.onBackground
        )

        Spacer(modifier = Modifier.height(6.dp))

        val categories = listOf("ALL", "PERMISSIONS", "MANIFEST_CONFIG", "EXPORTED_COMPONENTS", "SECRETS_STRINGS", "NETWORK_SECURITY")

        ScrollableTabRow(
          selectedTabIndex = categories.indexOf(selectedCategoryTab).coerceAtLeast(0),
          edgePadding = 0.dp,
          containerColor = Color.Transparent,
          contentColor = CyberBluePrimary
        ) {
          categories.forEach { cat ->
            Tab(
              selected = selectedCategoryTab == cat,
              onClick = { selectedCategoryTab = cat },
              text = {
                Text(
                  text = cat.replace("_", " "),
                  fontSize = 11.sp,
                  fontWeight = if (selectedCategoryTab == cat) FontWeight.Bold else FontWeight.Normal
                )
              }
            )
          }
        }
      }

      if (filteredFindings.isEmpty()) {
        item {
          Card(
            modifier = Modifier.fillMaxWidth(),
            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)
          ) {
            Box(modifier = Modifier.padding(24.dp), contentAlignment = Alignment.Center) {
              Text(
                text = "No findings recorded in this category.",
                style = MaterialTheme.typography.bodyMedium,
                color = Slate600
              )
            }
          }
        }
      } else {
        items(filteredFindings) { finding ->
          FindingCard(finding = finding)
        }
      }

      item {
        Spacer(modifier = Modifier.height(20.dp))
      }
    }
  }
}

@Composable
fun CountPill(label: String, count: Int, color: Color) {
  Column(horizontalAlignment = Alignment.CenterHorizontally) {
    Text(
      text = "$count",
      style = MaterialTheme.typography.titleMedium.copy(
        fontWeight = FontWeight.Black,
        fontFamily = FontFamily.Monospace
      ),
      color = color
    )
    Text(text = label, style = MaterialTheme.typography.labelSmall, color = Slate600)
  }
}

@Composable
fun FindingCard(finding: ScanFinding) {
  Card(
    modifier = Modifier
      .fillMaxWidth()
      .clip(RoundedCornerShape(12.dp))
      .testTag("finding_card_${finding.ruleId}"),
    colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
    elevation = CardDefaults.cardElevation(defaultElevation = 1.dp)
  ) {
    Column(modifier = Modifier.padding(14.dp)) {
      Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically
      ) {
        Surface(
          color = Color(0xFFF1F5F9),
          shape = RoundedCornerShape(4.dp)
        ) {
          Text(
            text = "${finding.ruleId} • ${finding.cweId}",
            style = MaterialTheme.typography.labelSmall.copy(
              fontWeight = FontWeight.Bold,
              fontFamily = FontFamily.Monospace
            ),
            color = Slate800,
            modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp)
          )
        }

        SeverityBadge(severity = finding.severity)
      }

      Spacer(modifier = Modifier.height(8.dp))

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
        Spacer(modifier = Modifier.height(8.dp))
        Surface(
          modifier = Modifier.fillMaxWidth(),
          color = Color(0xFF0F172A),
          shape = RoundedCornerShape(6.dp)
        ) {
          Text(
            text = finding.evidence,
            style = MaterialTheme.typography.labelSmall.copy(
              fontFamily = FontFamily.Monospace,
              fontSize = 11.sp
            ),
            color = Color(0xFF38BDF8),
            modifier = Modifier.padding(8.dp)
          )
        }
      }

      Spacer(modifier = Modifier.height(8.dp))

      Row(verticalAlignment = Alignment.Top) {
        Text(
          text = "Remediation: ",
          style = MaterialTheme.typography.labelSmall.copy(fontWeight = FontWeight.Bold),
          color = CyberBlueDark
        )
        Text(
          text = finding.recommendation,
          style = MaterialTheme.typography.labelSmall,
          color = Slate600
        )
      }
    }
  }
}
