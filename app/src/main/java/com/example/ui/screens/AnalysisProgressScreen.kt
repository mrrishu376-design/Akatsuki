package com.example.ui.screens

import androidx.compose.animation.core.LinearEasing
import androidx.compose.animation.core.RepeatMode
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.tween
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
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Check
import androidx.compose.material.icons.filled.Security
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.scale
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.example.ui.MainViewModel
import com.example.ui.components.CyberTopAppBar
import com.example.ui.theme.ConsoleBlueBg
import com.example.ui.theme.ConsoleBluePrimary
import com.example.ui.theme.ConsoleBorder
import com.example.ui.theme.ConsoleNavy
import com.example.ui.theme.ConsoleWhite
import com.example.ui.theme.RiskSafeGreen
import com.example.ui.theme.Slate200
import com.example.ui.theme.Slate600
import com.example.ui.theme.Slate800
import com.example.ui.theme.Slate900

@Composable
fun AnalysisProgressScreen(viewModel: MainViewModel) {
  val progress by viewModel.analysisProgress.collectAsState()

  val infiniteTransition = rememberInfiniteTransition(label = "pulse")
  val pulseScale by infiniteTransition.animateFloat(
    initialValue = 0.96f,
    targetValue = 1.04f,
    animationSpec = infiniteRepeatable(
      animation = tween(1200, easing = LinearEasing),
      repeatMode = RepeatMode.Reverse
    ),
    label = "pulseScale"
  )

  val stages = listOf(
    "APK Ingestion & Cryptographic Hashing",
    "AndroidManifest.xml & Architecture Inspection",
    "Permission Threat Profiling vs MITRE Matrix",
    "Component IPC & Build Configuration Audit",
    "DEX Bytecode String & Secret Extraction"
  )

  Scaffold(
    topBar = {
      CyberTopAppBar(
        title = "Static Analysis Engine",
        subtitle = "Processing byte pipeline"
      )
    },
    containerColor = ConsoleWhite
  ) { innerPadding ->
    Column(
      modifier = Modifier
        .fillMaxSize()
        .padding(innerPadding)
        .padding(horizontal = 20.dp, vertical = 12.dp)
        .verticalScroll(rememberScrollState()),
      horizontalAlignment = Alignment.CenterHorizontally
    ) {
      Spacer(modifier = Modifier.height(10.dp))

      // ENTERPRISE RADAR BADGE
      Box(
        modifier = Modifier
          .size(92.dp)
          .scale(pulseScale)
          .clip(CircleShape)
          .background(ConsoleBlueBg),
        contentAlignment = Alignment.Center
      ) {
        Box(
          modifier = Modifier
            .size(64.dp)
            .clip(CircleShape)
            .background(ConsoleNavy),
          contentAlignment = Alignment.Center
        ) {
          Icon(
            imageVector = Icons.Default.Shield,
            contentDescription = "Scanning",
            tint = ConsoleWhite,
            modifier = Modifier.size(32.dp)
          )
        }
      }

      Spacer(modifier = Modifier.height(18.dp))

      Text(
        text = progress.stepName.ifEmpty { "Executing Static Forensic Audit" },
        style = MaterialTheme.typography.titleMedium.copy(fontWeight = FontWeight.Bold),
        color = Slate900
      )

      Spacer(modifier = Modifier.height(4.dp))

      Text(
        text = progress.details.ifEmpty { "Computing SHA-256 and evaluating manifest vectors..." },
        style = MaterialTheme.typography.bodySmall,
        color = Slate600
      )

      Spacer(modifier = Modifier.height(16.dp))

      // PROGRESS BAR & PERCENT
      Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically
      ) {
        Text(
          text = "ANALYSIS PROGRESS",
          style = MaterialTheme.typography.labelSmall.copy(fontWeight = FontWeight.Bold, letterSpacing = 1.sp),
          color = ConsoleBluePrimary
        )
        Text(
          text = "${(progress.progressPercent * 100).toInt()}%",
          style = MaterialTheme.typography.labelSmall.copy(
            fontWeight = FontWeight.Bold,
            fontFamily = FontFamily.Monospace
          ),
          color = ConsoleBluePrimary
        )
      }

      Spacer(modifier = Modifier.height(6.dp))

      LinearProgressIndicator(
        progress = { progress.progressPercent },
        modifier = Modifier
          .fillMaxWidth()
          .height(8.dp)
          .clip(RoundedCornerShape(4.dp))
          .testTag("analysis_progress_bar"),
        color = ConsoleBluePrimary,
        trackColor = Color(0xFFE2E8F0)
      )

      Spacer(modifier = Modifier.height(20.dp))

      // STAGE STEPPER CARDS
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
            text = "Forensic Inspection Pipeline",
            style = MaterialTheme.typography.titleSmall.copy(fontWeight = FontWeight.Bold),
            color = Slate900
          )

          Spacer(modifier = Modifier.height(12.dp))

          stages.forEachIndexed { index, stageTitle ->
            val isCompleted = index < progress.stepIndex
            val isCurrent = index == progress.stepIndex

            Row(
              modifier = Modifier
                .fillMaxWidth()
                .padding(vertical = 6.dp),
              verticalAlignment = Alignment.CenterVertically
            ) {
              Box(
                modifier = Modifier
                  .size(26.dp)
                  .clip(CircleShape)
                  .background(
                    when {
                      isCompleted -> RiskSafeGreen
                      isCurrent -> ConsoleBluePrimary
                      else -> Color(0xFFE2E8F0)
                    }
                  ),
                contentAlignment = Alignment.Center
              ) {
                if (isCompleted) {
                  Icon(Icons.Default.Check, contentDescription = null, tint = ConsoleWhite, modifier = Modifier.size(15.dp))
                } else if (isCurrent) {
                  CircularProgressIndicator(
                    modifier = Modifier.size(14.dp),
                    color = ConsoleWhite,
                    strokeWidth = 2.dp
                  )
                } else {
                  Text(
                    text = "${index + 1}",
                    style = MaterialTheme.typography.labelSmall.copy(fontWeight = FontWeight.Bold),
                    color = Slate600,
                    fontSize = 11.sp
                  )
                }
              }

              Spacer(modifier = Modifier.width(12.dp))

              Text(
                text = stageTitle,
                style = MaterialTheme.typography.bodySmall.copy(
                  fontWeight = if (isCurrent) FontWeight.Bold else FontWeight.Normal
                ),
                color = if (isCurrent) ConsoleBluePrimary else Slate800
              )
            }
          }
        }
      }

      Spacer(modifier = Modifier.height(16.dp))

      // TERMINAL LOG CARD (NAVY CONSOLE BOX)
      Card(
        modifier = Modifier
          .fillMaxWidth()
          .border(1.dp, Color(0xFF1E3A5F), RoundedCornerShape(8.dp)),
        colors = CardDefaults.cardColors(containerColor = ConsoleNavy),
        shape = RoundedCornerShape(8.dp),
        elevation = CardDefaults.cardElevation(defaultElevation = 0.dp)
      ) {
        Column(modifier = Modifier.padding(14.dp)) {
          Row(verticalAlignment = Alignment.CenterVertically) {
            Box(modifier = Modifier.size(8.dp).clip(CircleShape).background(Color(0xFFEF4444)))
            Spacer(modifier = Modifier.width(6.dp))
            Box(modifier = Modifier.size(8.dp).clip(CircleShape).background(Color(0xFFF59E0B)))
            Spacer(modifier = Modifier.width(6.dp))
            Box(modifier = Modifier.size(8.dp).clip(CircleShape).background(RiskSafeGreen))
            Spacer(modifier = Modifier.width(10.dp))
            Text(
              text = "secops-engine: ~/$",
              style = MaterialTheme.typography.labelSmall.copy(fontFamily = FontFamily.Monospace),
              color = Color(0xFF94A3B8)
            )
          }
          Spacer(modifier = Modifier.height(8.dp))
          Text(
            text = "[+] Ingesting APK central directory & SHA-256 computation\n" +
                "[+] Decoding AndroidManifest.xml string chunk pool\n" +
                "[+] Evaluating permission intent vectors & MITRE ATT&CK matrix\n" +
                "[+] Scanning bytecode for hardcoded keys & exfiltration endpoints\n" +
                "[~] Status: ${progress.details.ifEmpty { "Executing rules engine..." }}",
            style = MaterialTheme.typography.bodySmall.copy(
              fontFamily = FontFamily.Monospace,
              fontSize = 11.sp,
              lineHeight = 16.sp
            ),
            color = Color(0xFF38BDF8)
          )
        }
      }

      Spacer(modifier = Modifier.height(20.dp))
    }
  }
}
