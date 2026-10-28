package com.example.ui.screens

import androidx.compose.animation.core.LinearEasing
import androidx.compose.animation.core.RepeatMode
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.tween
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
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Check
import androidx.compose.material.icons.filled.Code
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.Policy
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
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.example.ui.MainViewModel
import com.example.ui.components.CyberTopAppBar
import com.example.ui.theme.CyberAccentCyan
import com.example.ui.theme.CyberBlueDark
import com.example.ui.theme.CyberBluePrimary
import com.example.ui.theme.RiskSafeGreen
import com.example.ui.theme.Slate200
import com.example.ui.theme.Slate600
import com.example.ui.theme.Slate800

@Composable
fun AnalysisProgressScreen(viewModel: MainViewModel) {
  val progress by viewModel.analysisProgress.collectAsState()

  val infiniteTransition = rememberInfiniteTransition(label = "pulse")
  val pulseScale by infiniteTransition.animateFloat(
    initialValue = 0.95f,
    targetValue = 1.05f,
    animationSpec = infiniteRepeatable(
      animation = tween(1000, easing = LinearEasing),
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
    }
  ) { innerPadding ->
    Column(
      modifier = Modifier
        .fillMaxSize()
        .padding(innerPadding)
        .padding(20.dp)
        .verticalScroll(rememberScrollState()),
      horizontalAlignment = Alignment.CenterHorizontally
    ) {
      Spacer(modifier = Modifier.height(10.dp))

      // PULSING CYBER SHIELD
      Box(
        modifier = Modifier
          .size(100.dp)
          .scale(pulseScale)
          .clip(CircleShape)
          .background(
            Brush.radialGradient(
              colors = listOf(CyberAccentCyan.copy(alpha = 0.3f), CyberBluePrimary.copy(alpha = 0.1f))
            )
          ),
        contentAlignment = Alignment.Center
      ) {
        Box(
          modifier = Modifier
            .size(72.dp)
            .clip(CircleShape)
            .background(
              Brush.linearGradient(
                colors = listOf(CyberBluePrimary, CyberBlueDark)
              )
            ),
          contentAlignment = Alignment.Center
        ) {
          Icon(
            imageVector = Icons.Default.Shield,
            contentDescription = "Scanning",
            tint = Color.White,
            modifier = Modifier.size(36.dp)
          )
        }
      }

      Spacer(modifier = Modifier.height(20.dp))

      Text(
        text = progress.stepName.ifEmpty { "Executing Static Forensic Audit" },
        style = MaterialTheme.typography.titleMedium.copy(fontWeight = FontWeight.Bold),
        color = MaterialTheme.colorScheme.onBackground
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
          color = CyberBluePrimary
        )
        Text(
          text = "${(progress.progressPercent * 100).toInt()}%",
          style = MaterialTheme.typography.labelSmall.copy(
            fontWeight = FontWeight.Bold,
            fontFamily = FontFamily.Monospace
          ),
          color = CyberBluePrimary
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
        color = CyberBluePrimary,
        trackColor = Color(0xFFE2E8F0)
      )

      Spacer(modifier = Modifier.height(24.dp))

      // STAGE STEPPER CARDS
      Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
        shape = RoundedCornerShape(14.dp),
        elevation = CardDefaults.cardElevation(defaultElevation = 1.dp)
      ) {
        Column(modifier = Modifier.padding(16.dp)) {
          Text(
            text = "Forensic Inspection Pipeline",
            style = MaterialTheme.typography.titleSmall.copy(fontWeight = FontWeight.Bold),
            color = MaterialTheme.colorScheme.onSurface
          )

          Spacer(modifier = Modifier.height(12.dp))

          stages.forEachIndexed { index, stageTitle ->
            val isCompleted = index < progress.stepIndex
            val isCurrent = index == progress.stepIndex

            Row(
              modifier = Modifier
                .fillMaxWidth()
                .padding(vertical = 8.dp),
              verticalAlignment = Alignment.CenterVertically
            ) {
              Box(
                modifier = Modifier
                  .size(28.dp)
                  .clip(CircleShape)
                  .background(
                    when {
                      isCompleted -> RiskSafeGreen
                      isCurrent -> CyberBluePrimary
                      else -> Color(0xFFE2E8F0)
                    }
                  ),
                contentAlignment = Alignment.Center
              ) {
                if (isCompleted) {
                  Icon(Icons.Default.Check, contentDescription = null, tint = Color.White, modifier = Modifier.size(16.dp))
                } else if (isCurrent) {
                  CircularProgressIndicator(
                    modifier = Modifier.size(16.dp),
                    color = Color.White,
                    strokeWidth = 2.dp
                  )
                } else {
                  Text(
                    text = "${index + 1}",
                    style = MaterialTheme.typography.labelSmall.copy(fontWeight = FontWeight.Bold),
                    color = Slate600
                  )
                }
              }

              Spacer(modifier = Modifier.width(12.dp))

              Text(
                text = stageTitle,
                style = MaterialTheme.typography.bodySmall.copy(
                  fontWeight = if (isCurrent) FontWeight.Bold else FontWeight.Normal
                ),
                color = if (isCurrent) CyberBluePrimary else MaterialTheme.colorScheme.onSurface
              )
            }
          }
        }
      }

      Spacer(modifier = Modifier.height(20.dp))

      // TERMINAL LOG CARD
      Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = Slate800),
        shape = RoundedCornerShape(10.dp)
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
            text = "[+] Verifying ZIP central directory structure\n" +
                "[+] Ingesting binary XML string pool\n" +
                "[+] Mapping capabilities to CWE definitions\n" +
                "[+] Evaluating high-entropy string tokens\n" +
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
    }
  }
}
