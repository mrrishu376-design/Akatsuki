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
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.AccountCircle
import androidx.compose.material.icons.filled.Security
import androidx.compose.material.icons.filled.Shield
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
import androidx.compose.ui.graphics.Brush
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
import com.example.ui.theme.CyberAccentCyan
import com.example.ui.theme.CyberBlueDark
import com.example.ui.theme.CyberBluePrimary
import com.example.ui.theme.CyberNavy
import com.example.ui.theme.RiskSafeGreen
import com.example.ui.theme.SeverityCritical
import com.example.ui.theme.SeverityCriticalBg
import com.example.ui.theme.SeverityHigh
import com.example.ui.theme.SeverityHighBg
import com.example.ui.theme.SeverityInfo
import com.example.ui.theme.SeverityInfoBg
import com.example.ui.theme.SeverityLow
import com.example.ui.theme.SeverityLowBg
import com.example.ui.theme.SeverityMedium
import com.example.ui.theme.SeverityMediumBg
import com.example.ui.theme.Slate200
import com.example.ui.theme.Slate600
import com.example.ui.theme.Slate800

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun CyberTopAppBar(
  title: String,
  showBack: Boolean = false,
  onBackClick: () -> Unit = {},
  onProfileClick: () -> Unit = {},
  subtitle: String? = null
) {
  TopAppBar(
    title = {
      Row(verticalAlignment = Alignment.CenterVertically) {
        Box(
          modifier = Modifier
            .size(36.dp)
            .clip(RoundedCornerShape(8.dp))
            .background(
              Brush.linearGradient(
                colors = listOf(CyberBluePrimary, CyberBlueDark)
              )
            ),
          contentAlignment = Alignment.Center
        ) {
          Icon(
            imageVector = Icons.Default.Shield,
            contentDescription = "PS-02 Shield Logo",
            tint = Color.White,
            modifier = Modifier.size(20.dp)
          )
        }
        Spacer(modifier = Modifier.width(10.dp))
        Column {
          Text(
            text = title,
            style = MaterialTheme.typography.titleMedium.copy(
              fontWeight = FontWeight.Bold,
              letterSpacing = 0.3.sp
            ),
            color = MaterialTheme.colorScheme.onSurface,
            maxLines = 1
          )
          if (subtitle != null) {
            Text(
              text = subtitle,
              style = MaterialTheme.typography.bodySmall,
              color = Slate600,
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
            tint = MaterialTheme.colorScheme.onSurface
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
          tint = CyberBluePrimary,
          modifier = Modifier.size(28.dp)
        )
      }
    },
    colors = TopAppBarDefaults.topAppBarColors(
      containerColor = MaterialTheme.colorScheme.surface
    )
  )
}

@Composable
fun SeverityBadge(
  severity: Severity,
  modifier: Modifier = Modifier
) {
  val (bgColor, textColor, borderColor) = when (severity) {
    Severity.CRITICAL -> Triple(SeverityCriticalBg, SeverityCritical, SeverityCritical.copy(alpha = 0.4f))
    Severity.HIGH -> Triple(SeverityHighBg, SeverityHigh, SeverityHigh.copy(alpha = 0.4f))
    Severity.MEDIUM -> Triple(SeverityMediumBg, SeverityMedium, SeverityMedium.copy(alpha = 0.4f))
    Severity.LOW -> Triple(SeverityLowBg, SeverityLow, SeverityLow.copy(alpha = 0.4f))
    Severity.INFO -> Triple(SeverityInfoBg, SeverityInfo, SeverityInfo.copy(alpha = 0.4f))
  }

  Surface(
    modifier = modifier
      .clip(RoundedCornerShape(6.dp))
      .border(1.dp, borderColor, RoundedCornerShape(6.dp)),
    color = bgColor
  ) {
    Text(
      text = severity.label,
      modifier = Modifier.padding(horizontal = 8.dp, vertical = 2.dp),
      style = MaterialTheme.typography.labelSmall.copy(
        fontWeight = FontWeight.Bold,
        letterSpacing = 0.5.sp
      ),
      color = textColor
    )
  }
}

@Composable
fun RiskGauge(
  score: Int,
  riskLabel: RiskLabel,
  size: Dp = 160.dp,
  strokeWidth: Dp = 12.dp
) {
  val targetSweep = (score / 100f) * 240f
  val animatedSweep by animateFloatAsState(
    targetValue = targetSweep,
    animationSpec = tween(durationMillis = 900),
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
      val radius = (diameter - strokePx) / 2f

      // Background Arc
      drawArc(
        color = Color(0xFFE2E8F0),
        startAngle = 150f,
        sweepAngle = 240f,
        useCenter = false,
        style = Stroke(width = strokePx, cap = StrokeCap.Round)
      )

      // Value Arc
      drawArc(
        brush = Brush.sweepGradient(
          0.0f to gaugeColor.copy(alpha = 0.7f),
          1.0f to gaugeColor
        ),
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
        text = "/ 100",
        style = MaterialTheme.typography.labelSmall,
        color = Slate600
      )
      Spacer(modifier = Modifier.size(4.dp))
      Surface(
        color = gaugeColor.copy(alpha = 0.15f),
        shape = RoundedCornerShape(4.dp),
        border = androidx.compose.foundation.BorderStroke(1.dp, gaugeColor.copy(alpha = 0.3f))
      ) {
        Text(
          text = riskLabel.name,
          style = MaterialTheme.typography.labelMedium.copy(
            fontWeight = FontWeight.Bold,
            letterSpacing = 0.8.sp
          ),
          color = gaugeColor,
          modifier = Modifier.padding(horizontal = 8.dp, vertical = 2.dp)
        )
      }
    }
  }
}
