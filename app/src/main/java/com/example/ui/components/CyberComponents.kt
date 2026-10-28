package com.example.ui.components

import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.tween
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.AccountCircle
import androidx.compose.material.icons.filled.Menu
import androidx.compose.material.icons.filled.Public
import androidx.compose.material.icons.filled.Security
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.example.data.model.RiskLabel
import com.example.data.model.Severity
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
import com.example.ui.theme.SeverityInfo
import com.example.ui.theme.SeverityInfoBg
import com.example.ui.theme.SeverityLow
import com.example.ui.theme.SeverityLowBg
import com.example.ui.theme.SeverityMedium
import com.example.ui.theme.SeverityMediumBg
import com.example.ui.theme.SeverityMediumBorder
import com.example.ui.theme.Slate200
import com.example.ui.theme.Slate600
import com.example.ui.theme.Slate700
import com.example.ui.theme.Slate800

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun CyberTopAppBar(
  title: String,
  showBack: Boolean = false,
  onBackClick: () -> Unit = {},
  onProfileClick: () -> Unit = {},
  onMenuClick: (() -> Unit)? = null,
  subtitle: String? = null
) {
  TopAppBar(
    title = {
      Row(verticalAlignment = Alignment.CenterVertically) {
        Box(
          modifier = Modifier
            .size(32.dp)
            .clip(RoundedCornerShape(6.dp))
            .background(ConsoleNavyBorder),
          contentAlignment = Alignment.Center
        ) {
          Icon(
            imageVector = Icons.Default.Shield,
            contentDescription = "PS-02 Console",
            tint = Color(0xFF38BDF8),
            modifier = Modifier.size(18.dp)
          )
        }
        Spacer(modifier = Modifier.width(10.dp))
        Column {
          Row(verticalAlignment = Alignment.CenterVertically) {
            Text(
              text = title,
              style = MaterialTheme.typography.titleMedium.copy(
                fontWeight = FontWeight.Bold,
                letterSpacing = 0.3.sp
              ),
              color = Color.White,
              maxLines = 1
            )
            Spacer(modifier = Modifier.width(8.dp))
            Surface(
              color = Color(0xFF166534), // SOC Active badge
              shape = RoundedCornerShape(3.dp)
            ) {
              Text(
                text = "SEC-OPS CONSOLE",
                style = MaterialTheme.typography.labelSmall.copy(
                  fontSize = 8.sp,
                  fontWeight = FontWeight.Bold,
                  letterSpacing = 0.5.sp
                ),
                color = Color(0xFFDCFCE7),
                modifier = Modifier.padding(horizontal = 4.dp, vertical = 1.dp)
              )
            }
          }
          if (subtitle != null) {
            Text(
              text = subtitle,
              style = MaterialTheme.typography.bodySmall.copy(fontSize = 11.sp),
              color = Color(0xFF94A3B8),
              maxLines = 1
            )
          }
        }
      }
    },
    navigationIcon = {
      if (showBack) {
        IconButton(
          onClick = onBackClick,
          modifier = Modifier.testTag("nav_back_button")
        ) {
          Icon(
            imageVector = Icons.AutoMirrored.Filled.ArrowBack,
            contentDescription = "Back",
            tint = Color.White
          )
        }
      } else if (onMenuClick != null) {
        IconButton(
          onClick = onMenuClick,
          modifier = Modifier.testTag("nav_drawer_toggle")
        ) {
          Icon(
            imageVector = Icons.Default.Menu,
            contentDescription = "Toggle Console Sidebar",
            tint = Color.White
          )
        }
      }
    },
    actions = {
      IconButton(
        onClick = onProfileClick,
        modifier = Modifier.testTag("nav_profile_button")
      ) {
        Icon(
          imageVector = Icons.Default.AccountCircle,
          contentDescription = "Auditor Profile",
          tint = Color(0xFFBAE6FD),
          modifier = Modifier.size(26.dp)
        )
      }
    },
    colors = TopAppBarDefaults.topAppBarColors(
      containerColor = ConsoleNavy
    )
  )
}

@Composable
fun SeverityBadge(
  severity: Severity,
  modifier: Modifier = Modifier
) {
  val (bgColor, textColor, borderColor) = when (severity) {
    Severity.CRITICAL -> Triple(SeverityCriticalBg, SeverityCritical, SeverityCriticalBorder)
    Severity.HIGH -> Triple(SeverityHighBg, SeverityHigh, SeverityHighBorder)
    Severity.MEDIUM -> Triple(SeverityMediumBg, SeverityMedium, SeverityMediumBorder)
    Severity.LOW -> Triple(SeverityLowBg, SeverityLow, Color(0xFF86EFAC))
    Severity.INFO -> Triple(SeverityInfoBg, SeverityInfo, Color(0xFF93C5FD))
  }

  Surface(
    modifier = modifier
      .clip(RoundedCornerShape(4.dp))
      .border(1.dp, borderColor, RoundedCornerShape(4.dp)),
    color = bgColor
  ) {
    Text(
      text = severity.label,
      modifier = Modifier.padding(horizontal = 7.dp, vertical = 2.dp),
      style = MaterialTheme.typography.labelSmall.copy(
        fontWeight = FontWeight.Bold,
        letterSpacing = 0.6.sp,
        fontSize = 10.sp
      ),
      color = textColor
    )
  }
}

@Composable
fun RiskGauge(
  score: Int,
  riskLabel: RiskLabel,
  size: Dp = 150.dp,
  strokeWidth: Dp = 10.dp
) {
  val targetSweep = (score / 100f) * 240f
  val animatedSweep by animateFloatAsState(
    targetValue = targetSweep,
    animationSpec = tween(durationMillis = 800),
    label = "riskGauge"
  )

  val gaugeColor = when (riskLabel) {
    RiskLabel.CRITICAL -> SeverityCritical
    RiskLabel.HIGH -> SeverityHigh
    RiskLabel.MEDIUM -> SeverityMedium
    RiskLabel.LOW -> SeverityLow
    RiskLabel.SAFE -> RiskSafeGreen
  }

  Box(
    modifier = Modifier.size(size),
    contentAlignment = Alignment.Center
  ) {
    Canvas(modifier = Modifier.size(size)) {
      val diameter = size.toPx()
      val strokePx = strokeWidth.toPx()

      // Track arc
      drawArc(
        color = Color(0xFFE2E8F0),
        startAngle = 150f,
        sweepAngle = 240f,
        useCenter = false,
        style = Stroke(width = strokePx, cap = StrokeCap.Round)
      )

      // Value arc in red/orange/amber
      drawArc(
        color = gaugeColor,
        startAngle = 150f,
        sweepAngle = animatedSweep,
        useCenter = false,
        style = Stroke(width = strokePx, cap = StrokeCap.Round)
      )
    }

    Column(
      horizontalAlignment = Alignment.CenterHorizontally,
      verticalArrangement = Arrangement.Center
    ) {
      Text(
        text = "$score",
        style = MaterialTheme.typography.displaySmall.copy(
          fontWeight = FontWeight.Black,
          fontFamily = FontFamily.Monospace
        ),
        color = gaugeColor
      )
      Text(
        text = "RISK SCORE / 100",
        style = MaterialTheme.typography.labelSmall.copy(
          fontWeight = FontWeight.Bold,
          letterSpacing = 0.5.sp,
          fontSize = 9.sp
        ),
        color = Slate600
      )
      Spacer(modifier = Modifier.height(4.dp))
      Surface(
        color = when (riskLabel) {
          RiskLabel.CRITICAL -> SeverityCriticalBg
          RiskLabel.HIGH -> SeverityHighBg
          RiskLabel.MEDIUM -> SeverityMediumBg
          else -> Color(0xFFDCFCE7)
        },
        shape = RoundedCornerShape(3.dp),
        border = androidx.compose.foundation.BorderStroke(1.dp, gaugeColor.copy(alpha = 0.5f))
      ) {
        Text(
          text = riskLabel.name,
          style = MaterialTheme.typography.labelMedium.copy(
            fontWeight = FontWeight.Bold,
            letterSpacing = 0.8.sp,
            fontSize = 11.sp
          ),
          color = gaugeColor,
          modifier = Modifier.padding(horizontal = 8.dp, vertical = 2.dp)
        )
      }
    }
  }
}
