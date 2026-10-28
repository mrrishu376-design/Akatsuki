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
import androidx.compose.material.icons.filled.Calculate
import androidx.compose.material.icons.filled.Code
import androidx.compose.material.icons.filled.Description
import androidx.compose.material.icons.filled.Info
import androidx.compose.material.icons.filled.Key
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.Public
import androidx.compose.material.icons.filled.Security
import androidx.compose.material.icons.filled.Terminal
import androidx.compose.material.icons.filled.Warning
import com.example.data.model.Confidence
import com.example.data.model.HeuristicAnalysisSummary
import com.example.data.model.HeuristicCategory
import com.example.data.model.HeuristicFinding
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
import com.example.LocalNavigationDrawerToggle
import com.example.data.model.RiskLabel
import com.example.data.model.ScanFinding
import com.example.data.model.Severity
import com.example.ui.MainViewModel
import com.example.ui.components.CyberTopAppBar
import com.example.ui.components.RiskGauge
import com.example.ui.components.SeverityBadge
import com.example.ui.navigation.Screen
import com.example.ui.theme.ConsoleBluePrimary
import com.example.ui.theme.ConsoleBorder
import com.example.ui.theme.ConsoleNavy
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

@Composable
fun AnalysisResultsScreen(viewModel: MainViewModel) {
  val activeResult by viewModel.activeScanResult.collectAsState()
  val heuristicFindings by viewModel.activeHeuristicFindings.collectAsState()
  val heuristicSummary by viewModel.activeHeuristicSummary.collectAsState()
  val toggleDrawer = LocalNavigationDrawerToggle.current
  var selectedCategoryTab by remember { mutableStateOf("ALL") }
  var selectedHeuristicTab by remember { mutableStateOf<HeuristicCategory?>(null) }
  var showFormulaExplanation by remember { mutableStateOf(false) }

  val scan = activeResult?.scan
  val findings = activeResult?.findings ?: emptyList()
  val extractedUrls = activeResult?.extractedUrls ?: emptyList()
  val detectedSecrets = activeResult?.detectedSecrets ?: emptyList()

  val filteredFindings = if (selectedCategoryTab == "ALL") {
    findings
  } else {
    findings.filter { it.category == selectedCategoryTab }
  }

  Scaffold(
    topBar = {
      CyberTopAppBar(
        title = "Forensic Investigation Results",
        subtitle = scan?.appName ?: "APK Assessment",
        showBack = true,
        onBackClick = { viewModel.navigateTo(Screen.DASHBOARD) },
        onMenuClick = toggleDrawer,
        onProfileClick = { viewModel.navigateTo(Screen.PROFILE) }
      )
    },
    containerColor = Color.White
  ) { innerPadding ->
    if (scan == null) {
      Box(
        modifier = Modifier
          .fillMaxSize()
          .background(Color.White)
          .padding(innerPadding),
        contentAlignment = Alignment.Center
      ) {
        Text("No active investigation results loaded.", color = Slate600)
      }
      return@Scaffold
    }

    val riskColor = when (scan.riskLabel) {
      RiskLabel.CRITICAL -> SeverityCritical
      RiskLabel.HIGH -> SeverityHigh
      RiskLabel.MEDIUM -> SeverityMedium
      RiskLabel.LOW -> SeverityLow
      RiskLabel.SAFE -> RiskSafeGreen
    }

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

        // DEMO NOTICE IF BENCHMARK
        if (scan.isDemoData) {
          Surface(
            modifier = Modifier
              .fillMaxWidth()
              .clip(RoundedCornerShape(4.dp))
              .border(1.dp, SeverityMediumBorder, RoundedCornerShape(4.dp)),
            color = SeverityMediumBg
          ) {
            Row(modifier = Modifier.padding(10.dp), verticalAlignment = Alignment.CenterVertically) {
              Icon(Icons.Default.Info, contentDescription = null, tint = SeverityMedium, modifier = Modifier.size(16.dp))
              Spacer(modifier = Modifier.width(8.dp))
              Text(
                text = "DEMO BENCHMARK AUDIT: Evaluated using pre-packaged test target parameters.",
                style = MaterialTheme.typography.labelSmall.copy(fontWeight = FontWeight.Bold, color = Color(0xFF92400E))
              )
            }
          }
        }
      }

      // PROMINENT RISK SCORE CONSOLE PANEL
      item {
        Card(
          modifier = Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(8.dp))
            .border(1.dp, ConsoleBorder, RoundedCornerShape(8.dp)),
          colors = CardDefaults.cardColors(containerColor = Color(0xFFF8FAFC)),
          elevation = CardDefaults.cardElevation(defaultElevation = 0.dp)
        ) {
          Column(
            modifier = Modifier
              .fillMaxWidth()
              .padding(18.dp),
            horizontalAlignment = Alignment.CenterHorizontally
          ) {
            Row(
              modifier = Modifier.fillMaxWidth(),
              horizontalArrangement = Arrangement.SpaceBetween,
              verticalAlignment = Alignment.CenterVertically
            ) {
              Column {
                Text(
                  text = scan.appName,
                  style = MaterialTheme.typography.titleLarge.copy(fontWeight = FontWeight.Black),
                  color = Slate900
                )
                Text(
                  text = "${scan.packageName} • v${scan.versionName}",
                  style = MaterialTheme.typography.bodySmall.copy(fontFamily = FontFamily.Monospace, fontSize = 11.sp),
                  color = Slate600
                )
              }

              Surface(
                color = when (scan.riskLabel) {
                  RiskLabel.CRITICAL -> SeverityCriticalBg
                  RiskLabel.HIGH -> SeverityHighBg
                  RiskLabel.MEDIUM -> SeverityMediumBg
                  else -> Color(0xFFDCFCE7)
                },
                shape = RoundedCornerShape(4.dp),
                border = androidx.compose.foundation.BorderStroke(1.dp, riskColor)
              ) {
                Text(
                  text = scan.riskLabel.name,
                  style = MaterialTheme.typography.labelSmall.copy(fontWeight = FontWeight.Bold, letterSpacing = 0.8.sp),
                  color = riskColor,
                  modifier = Modifier.padding(horizontal = 8.dp, vertical = 3.dp)
                )
              }
            }

            Spacer(modifier = Modifier.height(16.dp))

            // PROMINENT RISK GAUGE
            RiskGauge(score = scan.riskScore, riskLabel = scan.riskLabel, size = 160.dp)

            Spacer(modifier = Modifier.height(12.dp))

            // Toggleable Formula Card
            Surface(
              modifier = Modifier
                .clip(RoundedCornerShape(4.dp))
                .border(1.dp, ConsoleBorder, RoundedCornerShape(4.dp))
                .clickable { showFormulaExplanation = !showFormulaExplanation }
                .padding(horizontal = 10.dp, vertical = 5.dp),
              color = Color.White
            ) {
              Row(verticalAlignment = Alignment.CenterVertically) {
                Icon(Icons.Default.Calculate, contentDescription = null, tint = ConsoleBluePrimary, modifier = Modifier.size(15.dp))
                Spacer(modifier = Modifier.width(6.dp))
                Text(
                  text = if (showFormulaExplanation) "Hide Risk Formula Breakdown" else "View Risk Scoring Formula",
                  style = MaterialTheme.typography.labelSmall.copy(fontWeight = FontWeight.Bold, color = ConsoleBluePrimary)
                )
              }
            }

            if (showFormulaExplanation) {
              Spacer(modifier = Modifier.height(10.dp))
              Surface(
                modifier = Modifier
                  .fillMaxWidth()
                  .clip(RoundedCornerShape(4.dp))
                  .border(1.dp, ConsoleBorder, RoundedCornerShape(4.dp)),
                color = Color.White
              ) {
                Column(modifier = Modifier.padding(12.dp)) {
                  Text(
                    text = "Risk Calculation Formula (0-100 Capped):",
                    style = MaterialTheme.typography.labelSmall.copy(fontWeight = FontWeight.Bold, color = ConsoleNavy)
                  )
                  Spacer(modifier = Modifier.height(4.dp))
                  Text(
                    text = "Score = Min(100, (Critical x 25) + (High x 15) + (Medium x 8) + (Low x 3))\n" +
                        "• Critical Findings (${scan.criticalCount}) = ${scan.criticalCount * 25} pts\n" +
                        "• High Threats (${scan.highCount}) = ${scan.highCount * 15} pts\n" +
                        "• Medium Risks (${scan.mediumCount}) = ${scan.mediumCount * 8} pts\n" +
                        "• Low Flags (${scan.lowCount}) = ${scan.lowCount * 3} pts\n" +
                        "Total Weighted Score: ${scan.riskScore} / 100",
                    style = MaterialTheme.typography.labelSmall.copy(
                      fontFamily = FontFamily.Monospace,
                      fontSize = 10.5.sp,
                      lineHeight = 15.sp
                    ),
                    color = Slate700
                  )
                }
              }
            }

            Spacer(modifier = Modifier.height(14.dp))
            HorizontalDivider(color = ConsoleBorder)
            Spacer(modifier = Modifier.height(12.dp))

            // THREAT SEVERITY METRICS STRIP
            Row(
              modifier = Modifier.fillMaxWidth(),
              horizontalArrangement = Arrangement.SpaceEvenly
            ) {
              ConsoleMetricPill("CRITICAL", "${scan.criticalCount}", SeverityCritical)
              ConsoleMetricPill("HIGH", "${scan.highCount}", SeverityHigh)
              ConsoleMetricPill("MEDIUM", "${scan.mediumCount}", SeverityMedium)
              ConsoleMetricPill("PERMS", "${scan.permissionsCount}", ConsoleBluePrimary)
            }
          }
        }
      }

      // PRIMARY ACTION BUTTONS (BLUE PRIMARY)
      item {
        Row(
          modifier = Modifier.fillMaxWidth(),
          horizontalArrangement = Arrangement.spacedBy(8.dp)
        ) {
          Button(
            onClick = { viewModel.navigateTo(Screen.PERMISSIONS) },
            modifier = Modifier
              .weight(1f)
              .height(46.dp)
              .testTag("btn_view_permissions_threats"),
            colors = ButtonDefaults.buttonColors(containerColor = ConsoleBluePrimary),
            shape = RoundedCornerShape(6.dp)
          ) {
            Icon(Icons.Default.Security, contentDescription = null, modifier = Modifier.size(17.dp))
            Spacer(modifier = Modifier.width(6.dp))
            Text("Permissions Matrix", fontWeight = FontWeight.Bold, fontSize = 12.sp)
          }

          Button(
            onClick = { viewModel.navigateTo(Screen.REPORT) },
            modifier = Modifier
              .weight(1f)
              .height(46.dp)
              .testTag("btn_view_forensic_report"),
            colors = ButtonDefaults.buttonColors(containerColor = ConsoleNavy),
            shape = RoundedCornerShape(6.dp)
          ) {
            Icon(Icons.Default.Description, contentDescription = null, modifier = Modifier.size(17.dp))
            Spacer(modifier = Modifier.width(6.dp))
            Text("Forensic Dossier / PDF", fontWeight = FontWeight.Bold, fontSize = 12.sp)
          }
        }
      }

      // HEURISTIC MALICIOUS PATTERN SCANNER CARD
      item {
        HeuristicThreatConsoleCard(
          heuristicFindings = heuristicFindings,
          summary = heuristicSummary,
          selectedFilter = selectedHeuristicTab,
          onSelectFilter = { selectedHeuristicTab = it }
        )
      }

      // NETWORK INDICATORS AND EVIDENCE PANEL
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
            Row(verticalAlignment = Alignment.CenterVertically) {
              Icon(Icons.Default.Public, contentDescription = null, tint = ConsoleBluePrimary, modifier = Modifier.size(18.dp))
              Spacer(modifier = Modifier.width(8.dp))
              Text(
                text = "NETWORK INDICATORS & EXFILTRATION EVIDENCE",
                style = MaterialTheme.typography.labelSmall.copy(
                  fontWeight = FontWeight.Bold,
                  letterSpacing = 0.8.sp,
                  fontSize = 11.sp
                ),
                color = ConsoleNavy
              )
            }

            Spacer(modifier = Modifier.height(10.dp))

            // Cleartext HTTP indicator
            Row(
              modifier = Modifier
                .fillMaxWidth()
                .clip(RoundedCornerShape(4.dp))
                .background(if (scan.usesCleartextTraffic) SeverityHighBg else Color(0xFFDCFCE7))
                .border(1.dp, if (scan.usesCleartextTraffic) SeverityHighBorder else Color(0xFF86EFAC), RoundedCornerShape(4.dp))
                .padding(horizontal = 10.dp, vertical = 8.dp),
              verticalAlignment = Alignment.CenterVertically,
              horizontalArrangement = Arrangement.SpaceBetween
            ) {
              Text(
                text = "Cleartext HTTP Traffic",
                style = MaterialTheme.typography.bodySmall.copy(fontWeight = FontWeight.Bold),
                color = if (scan.usesCleartextTraffic) SeverityHigh else RiskSafeGreen
              )
              Text(
                text = if (scan.usesCleartextTraffic) "PERMITTED (VULNERABLE)" else "ENFORCED HTTPS (SECURE)",
                style = MaterialTheme.typography.labelSmall.copy(
                  fontWeight = FontWeight.Black,
                  fontFamily = FontFamily.Monospace,
                  fontSize = 10.sp
                ),
                color = if (scan.usesCleartextTraffic) SeverityHigh else RiskSafeGreen
              )
            }

            // Extracted Network Endpoints
            if (extractedUrls.isNotEmpty()) {
              Spacer(modifier = Modifier.height(10.dp))
              Text(
                text = "Extracted Network Endpoints (${extractedUrls.size}):",
                style = MaterialTheme.typography.labelSmall.copy(fontWeight = FontWeight.Bold),
                color = Slate700
              )
              Spacer(modifier = Modifier.height(4.dp))

              extractedUrls.take(4).forEach { url ->
                val isPlaintext = url.startsWith("http://")
                Surface(
                  modifier = Modifier
                    .fillMaxWidth()
                    .padding(vertical = 2.dp),
                  color = Color(0xFFF8FAFC),
                  shape = RoundedCornerShape(3.dp),
                  border = androidx.compose.foundation.BorderStroke(1.dp, ConsoleBorder)
                ) {
                  Row(
                    modifier = Modifier.padding(horizontal = 8.dp, vertical = 4.dp),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.SpaceBetween
                  ) {
                    Text(
                      text = url,
                      style = MaterialTheme.typography.labelSmall.copy(
                        fontFamily = FontFamily.Monospace,
                        fontSize = 10.sp
                      ),
                      color = if (isPlaintext) SeverityHigh else ConsoleBluePrimary,
                      maxLines = 1,
                      modifier = Modifier.weight(1f)
                    )
                    if (isPlaintext) {
                      Text(
                        text = "CLEARTEXT",
                        style = MaterialTheme.typography.labelSmall.copy(
                          fontWeight = FontWeight.Bold,
                          fontSize = 8.sp
                        ),
                        color = SeverityHigh
                      )
                    }
                  }
                }
              }
            }

            // Detected Secrets in Bytecode
            if (detectedSecrets.isNotEmpty()) {
              Spacer(modifier = Modifier.height(10.dp))
              Text(
                text = "Hardcoded Secrets & Token Evidence:",
                style = MaterialTheme.typography.labelSmall.copy(fontWeight = FontWeight.Bold),
                color = Slate700
              )
              Spacer(modifier = Modifier.height(4.dp))

              detectedSecrets.forEach { secret ->
                Surface(
                  modifier = Modifier
                    .fillMaxWidth()
                    .padding(vertical = 2.dp),
                  color = Color(0xFF0F172A),
                  shape = RoundedCornerShape(3.dp)
                ) {
                  Row(
                    modifier = Modifier.padding(horizontal = 8.dp, vertical = 5.dp),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.SpaceBetween
                  ) {
                    Column {
                      Text(
                        text = secret.type,
                        style = MaterialTheme.typography.labelSmall.copy(fontWeight = FontWeight.Bold, fontSize = 9.sp),
                        color = Color(0xFF38BDF8)
                      )
                      Text(
                        text = secret.maskedValue,
                        style = MaterialTheme.typography.labelSmall.copy(fontFamily = FontFamily.Monospace, fontSize = 10.sp),
                        color = Color.White
                      )
                    }
                    SeverityBadge(severity = secret.severity)
                  }
                }
              }
            }
          }
        }
      }

      // CATEGORIZED VULNERABILITY FINDINGS
      item {
        Text(
          text = "IDENTIFIED FINDINGS & EVIDENCE (${findings.size})",
          style = MaterialTheme.typography.labelSmall.copy(
            fontWeight = FontWeight.Bold,
            letterSpacing = 1.sp,
            fontSize = 11.sp
          ),
          color = ConsoleNavy
        )

        Spacer(modifier = Modifier.height(6.dp))

        val categories = listOf(
          "ALL",
          "HEURISTIC_DCL",
          "HEURISTIC_OBFUSCATION",
          "HEURISTIC_REFLECTION",
          "PERMISSIONS",
          "MANIFEST_CONFIG",
          "EXPORTED_COMPONENTS",
          "SECRETS_STRINGS",
          "NETWORK_SECURITY"
        )

        ScrollableTabRow(
          selectedTabIndex = categories.indexOf(selectedCategoryTab).coerceAtLeast(0),
          edgePadding = 0.dp,
          containerColor = Color.White,
          contentColor = ConsoleBluePrimary
        ) {
          categories.forEach { cat ->
            val tabTitle = when (cat) {
              "ALL" -> "ALL"
              "HEURISTIC_DCL" -> "DYNAMIC LOADING"
              "HEURISTIC_OBFUSCATION" -> "OBFUSCATION / PACKERS"
              "HEURISTIC_REFLECTION" -> "REFLECTION"
              else -> cat.replace("_", " ")
            }
            Tab(
              selected = selectedCategoryTab == cat,
              onClick = { selectedCategoryTab = cat },
              text = {
                Text(
                  text = tabTitle,
                  fontSize = 11.sp,
                  fontWeight = if (selectedCategoryTab == cat) FontWeight.Bold else FontWeight.Medium
                )
              }
            )
          }
        }
      }

      if (filteredFindings.isEmpty()) {
        item {
          Surface(
            modifier = Modifier
              .fillMaxWidth()
              .clip(RoundedCornerShape(6.dp))
              .border(1.dp, ConsoleBorder, RoundedCornerShape(6.dp)),
            color = Color.White
          ) {
            Box(modifier = Modifier.padding(20.dp), contentAlignment = Alignment.Center) {
              Text("No findings observed in category '$selectedCategoryTab'.", color = Slate600, fontSize = 12.sp)
            }
          }
        }
      } else {
        items(filteredFindings) { finding ->
          EnterpriseFindingCard(finding = finding)
        }
      }

      item {
        Spacer(modifier = Modifier.height(20.dp))
      }
    }
  }
}

@Composable
fun ConsoleMetricPill(label: String, count: String, color: Color) {
  Column(horizontalAlignment = Alignment.CenterHorizontally) {
    Text(
      text = count,
      style = MaterialTheme.typography.titleMedium.copy(
        fontWeight = FontWeight.Black,
        fontFamily = FontFamily.Monospace
      ),
      color = color
    )
    Text(
      text = label,
      style = MaterialTheme.typography.labelSmall.copy(
        fontWeight = FontWeight.Bold,
        fontSize = 9.sp,
        letterSpacing = 0.5.sp
      ),
      color = Slate600
    )
  }
}

@Composable
fun EnterpriseFindingCard(finding: ScanFinding) {
  Card(
    modifier = Modifier
      .fillMaxWidth()
      .clip(RoundedCornerShape(6.dp))
      .border(1.dp, ConsoleBorder, RoundedCornerShape(6.dp))
      .testTag("finding_card_${finding.ruleId}"),
    colors = CardDefaults.cardColors(containerColor = Color.White),
    elevation = CardDefaults.cardElevation(defaultElevation = 0.dp)
  ) {
    Column(modifier = Modifier.padding(14.dp)) {
      Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically
      ) {
        Surface(
          color = Color(0xFFF1F5F9),
          shape = RoundedCornerShape(3.dp),
          border = androidx.compose.foundation.BorderStroke(1.dp, ConsoleBorder)
        ) {
          Text(
            text = "${finding.ruleId} • ${finding.cweId}",
            style = MaterialTheme.typography.labelSmall.copy(
              fontWeight = FontWeight.Bold,
              fontFamily = FontFamily.Monospace,
              fontSize = 10.sp
            ),
            color = Slate800,
            modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp)
          )
        }

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
        style = MaterialTheme.typography.bodySmall.copy(fontSize = 11.sp),
        color = Slate600
      )

      // Evidence Code Snippet Box
      if (finding.evidence.isNotBlank()) {
        Spacer(modifier = Modifier.height(6.dp))
        Surface(
          modifier = Modifier.fillMaxWidth(),
          color = Color(0xFF0F172A),
          shape = RoundedCornerShape(4.dp)
        ) {
          Text(
            text = finding.evidence,
            style = MaterialTheme.typography.labelSmall.copy(
              fontFamily = FontFamily.Monospace,
              fontSize = 10.sp
            ),
            color = Color(0xFF38BDF8),
            modifier = Modifier.padding(8.dp)
          )
        }
      }

      Spacer(modifier = Modifier.height(6.dp))

      Row(verticalAlignment = Alignment.Top) {
        Text(
          text = "Remediation: ",
          style = MaterialTheme.typography.labelSmall.copy(fontWeight = FontWeight.Bold, fontSize = 10.5.sp),
          color = ConsoleNavy
        )
        Text(
          text = finding.recommendation,
          style = MaterialTheme.typography.labelSmall.copy(fontSize = 10.5.sp),
          color = Slate700
        )
      }
    }
  }
}

@Composable
fun HeuristicThreatConsoleCard(
  heuristicFindings: List<HeuristicFinding>,
  summary: HeuristicAnalysisSummary?,
  selectedFilter: HeuristicCategory?,
  onSelectFilter: (HeuristicCategory?) -> Unit
) {
  val displayedFindings = if (selectedFilter == null) {
    heuristicFindings
  } else {
    heuristicFindings.filter { it.category == selectedFilter }
  }

  Card(
    modifier = Modifier
      .fillMaxWidth()
      .clip(RoundedCornerShape(8.dp))
      .border(1.dp, ConsoleBorder, RoundedCornerShape(8.dp))
      .testTag("card_heuristic_threat_analysis"),
    colors = CardDefaults.cardColors(containerColor = Color.White),
    elevation = CardDefaults.cardElevation(defaultElevation = 0.dp)
  ) {
    Column(modifier = Modifier.padding(14.dp)) {
      Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically
      ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
          Icon(Icons.Default.BugReport, contentDescription = null, tint = ConsoleBluePrimary, modifier = Modifier.size(18.dp))
          Spacer(modifier = Modifier.width(8.dp))
          Text(
            text = "HEURISTIC MALICIOUS PATTERN SCANNER",
            style = MaterialTheme.typography.labelSmall.copy(
              fontWeight = FontWeight.Bold,
              letterSpacing = 0.8.sp,
              fontSize = 11.sp
            ),
            color = ConsoleNavy
          )
        }

        Surface(
          color = if (heuristicFindings.isNotEmpty()) SeverityCriticalBg else Color(0xFFDCFCE7),
          shape = RoundedCornerShape(4.dp),
          border = androidx.compose.foundation.BorderStroke(1.dp, if (heuristicFindings.isNotEmpty()) SeverityCriticalBorder else Color(0xFF86EFAC))
        ) {
          Text(
            text = if (heuristicFindings.isNotEmpty()) "${heuristicFindings.size} THREATS DETECTED" else "HEURISTICS CLEAR",
            style = MaterialTheme.typography.labelSmall.copy(fontWeight = FontWeight.Black, fontSize = 9.sp),
            color = if (heuristicFindings.isNotEmpty()) SeverityCritical else RiskSafeGreen,
            modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp)
          )
        }
      }

      Spacer(modifier = Modifier.height(10.dp))

      // 3 Diagnostic Summary Pills (DCL, Obfuscation, Reflection)
      Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.spacedBy(6.dp)
      ) {
        val dclActive = (summary?.dclCount ?: 0) > 0
        val obfActive = (summary?.obfuscationCount ?: 0) > 0
        val reflActive = (summary?.reflectionCount ?: 0) > 0

        HeuristicVectorPill(
          icon = Icons.Default.Code,
          title = "DCL Loading",
          subtitle = if (dclActive) "${summary?.dclCount} Vector(s)" else "None Detected",
          isAlert = dclActive,
          isSelected = selectedFilter == HeuristicCategory.DYNAMIC_CODE_LOADING,
          onClick = {
            onSelectFilter(if (selectedFilter == HeuristicCategory.DYNAMIC_CODE_LOADING) null else HeuristicCategory.DYNAMIC_CODE_LOADING)
          },
          modifier = Modifier.weight(1f)
        )

        HeuristicVectorPill(
          icon = Icons.Default.Lock,
          title = "Packers & Obf",
          subtitle = summary?.packerIdentified ?: (if (obfActive) "${summary?.obfuscationCount} Indicator(s)" else "Standard Bytecode"),
          isAlert = obfActive,
          isSelected = selectedFilter == HeuristicCategory.OBFUSCATION_PACKERS,
          onClick = {
            onSelectFilter(if (selectedFilter == HeuristicCategory.OBFUSCATION_PACKERS) null else HeuristicCategory.OBFUSCATION_PACKERS)
          },
          modifier = Modifier.weight(1f)
        )

        HeuristicVectorPill(
          icon = Icons.Default.Terminal,
          title = "Reflection",
          subtitle = if (reflActive) "${summary?.reflectionCount} Dynamic Call(s)" else "Normal Invocations",
          isAlert = reflActive,
          isSelected = selectedFilter == HeuristicCategory.SUSPICIOUS_REFLECTION,
          onClick = {
            onSelectFilter(if (selectedFilter == HeuristicCategory.SUSPICIOUS_REFLECTION) null else HeuristicCategory.SUSPICIOUS_REFLECTION)
          },
          modifier = Modifier.weight(1f)
        )
      }

      Spacer(modifier = Modifier.height(12.dp))

      // Findings list or Clear message
      if (displayedFindings.isEmpty()) {
        Surface(
          modifier = Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(4.dp))
            .border(1.dp, Color(0xFF86EFAC), RoundedCornerShape(4.dp)),
          color = Color(0xFFF0FDF4)
        ) {
          Row(modifier = Modifier.padding(10.dp), verticalAlignment = Alignment.CenterVertically) {
            Icon(Icons.Default.Security, contentDescription = null, tint = RiskSafeGreen, modifier = Modifier.size(16.dp))
            Spacer(modifier = Modifier.width(8.dp))
            Text(
              text = if (selectedFilter != null) "No heuristic detections under ${selectedFilter.displayName}." else "No malicious dynamic loading, known packers, or suspicious reflection calls detected in application bytecode.",
              style = MaterialTheme.typography.bodySmall.copy(fontSize = 11.sp),
              color = Color(0xFF166534)
            )
          }
        }
      } else {
        Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
          displayedFindings.forEach { finding ->
            HeuristicFindingItemRow(finding = finding)
          }
        }
      }
    }
  }
}

@Composable
fun HeuristicVectorPill(
  icon: androidx.compose.ui.graphics.vector.ImageVector,
  title: String,
  subtitle: String,
  isAlert: Boolean,
  isSelected: Boolean,
  onClick: () -> Unit,
  modifier: Modifier = Modifier
) {
  val borderColor = if (isSelected) ConsoleBluePrimary else if (isAlert) SeverityHighBorder else ConsoleBorder
  val bgColor = if (isSelected) Color(0xFFEFF6FF) else if (isAlert) Color(0xFFFFF7ED) else Color(0xFFF8FAFC)

  Surface(
    modifier = modifier
      .clip(RoundedCornerShape(4.dp))
      .border(if (isSelected) 1.5.dp else 1.dp, borderColor, RoundedCornerShape(4.dp))
      .clickable { onClick() },
    color = bgColor
  ) {
    Column(modifier = Modifier.padding(8.dp)) {
      Row(verticalAlignment = Alignment.CenterVertically) {
        Icon(icon, contentDescription = null, tint = if (isAlert) SeverityHigh else ConsoleNavy, modifier = Modifier.size(13.dp))
        Spacer(modifier = Modifier.width(4.dp))
        Text(text = title, style = MaterialTheme.typography.labelSmall.copy(fontWeight = FontWeight.Bold, fontSize = 10.sp), color = Slate800, maxLines = 1)
      }
      Spacer(modifier = Modifier.height(2.dp))
      Text(
        text = subtitle,
        style = MaterialTheme.typography.bodySmall.copy(
          fontSize = 9.sp,
          fontWeight = if (isAlert) FontWeight.Bold else FontWeight.Normal,
          color = if (isAlert) SeverityHigh else Slate600
        ),
        maxLines = 1
      )
    }
  }
}

@Composable
fun HeuristicFindingItemRow(finding: HeuristicFinding) {
  Surface(
    modifier = Modifier
      .fillMaxWidth()
      .clip(RoundedCornerShape(4.dp))
      .border(1.dp, ConsoleBorder, RoundedCornerShape(4.dp))
      .testTag("heuristic_item_${finding.ruleId}"),
    color = Color.White
  ) {
    Column(modifier = Modifier.padding(10.dp)) {
      Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically
      ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
          Surface(
            color = Color(0xFF0A192F),
            shape = RoundedCornerShape(3.dp)
          ) {
            Text(
              text = finding.ruleId,
              style = MaterialTheme.typography.labelSmall.copy(
                fontFamily = FontFamily.Monospace,
                fontSize = 9.sp,
                fontWeight = FontWeight.Bold
              ),
              color = Color.White,
              modifier = Modifier.padding(horizontal = 5.dp, vertical = 2.dp)
            )
          }
          Spacer(modifier = Modifier.width(6.dp))
          Surface(
            color = Color(0xFFE2E8F0),
            shape = RoundedCornerShape(3.dp)
          ) {
            Text(
              text = "MITRE: ${finding.mitreAttackId}",
              style = MaterialTheme.typography.labelSmall.copy(fontSize = 9.sp, fontWeight = FontWeight.Bold),
              color = Slate700,
              modifier = Modifier.padding(horizontal = 4.dp, vertical = 2.dp)
            )
          }
        }

        SeverityBadge(severity = finding.severity)
      }

      Spacer(modifier = Modifier.height(6.dp))

      Text(
        text = finding.title,
        style = MaterialTheme.typography.bodySmall.copy(fontWeight = FontWeight.Black, fontSize = 12.sp),
        color = Slate900
      )

      Spacer(modifier = Modifier.height(3.dp))

      Text(
        text = finding.description,
        style = MaterialTheme.typography.bodySmall.copy(fontSize = 10.5.sp, lineHeight = 14.sp),
        color = Slate600
      )

      Spacer(modifier = Modifier.height(6.dp))

      // Terminal-style evidence container
      Surface(
        modifier = Modifier.fillMaxWidth(),
        color = Color(0xFF0F172A),
        shape = RoundedCornerShape(3.dp)
      ) {
        Column(modifier = Modifier.padding(6.dp)) {
          Text(
            text = "EVIDENCE [${finding.location}]:",
            style = MaterialTheme.typography.labelSmall.copy(
              fontFamily = FontFamily.Monospace,
              fontSize = 8.5.sp,
              fontWeight = FontWeight.Bold
            ),
            color = Color(0xFF94A3B8)
          )
          Text(
            text = finding.evidenceSnippet,
            style = MaterialTheme.typography.labelSmall.copy(
              fontFamily = FontFamily.Monospace,
              fontSize = 9.5.sp
            ),
            color = Color(0xFF38BDF8)
          )
        }
      }

      Spacer(modifier = Modifier.height(5.dp))

      Text(
        text = "Remediation: ${finding.remediation}",
        style = MaterialTheme.typography.labelSmall.copy(fontSize = 9.5.sp, fontStyle = androidx.compose.ui.text.font.FontStyle.Italic),
        color = ConsoleBluePrimary
      )
    }
  }
}

