package com.example.ui.screens

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
import androidx.compose.material.icons.filled.Info
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.Policy
import androidx.compose.material.icons.filled.Security
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.FilterChip
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
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
import com.example.data.model.PermissionThreatItem
import com.example.data.model.Severity
import com.example.ui.MainViewModel
import com.example.ui.components.CyberTopAppBar
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
fun PermissionsScreen(viewModel: MainViewModel) {
  val activeResult by viewModel.activeScanResult.collectAsState()
  var selectedProtectionFilter by remember { mutableStateOf("ALL") }

  val permissions = activeResult?.permissions ?: emptyList()
  val scan = activeResult?.scan

  val filteredPermissions = when (selectedProtectionFilter) {
    "DANGEROUS" -> permissions.filter { it.protectionLevel == "DANGEROUS" }
    "NORMAL" -> permissions.filter { it.protectionLevel == "NORMAL" }
    "SPECIAL" -> permissions.filter { it.protectionLevel == "SPECIAL" || it.protectionLevel.contains("SIGNATURE") }
    else -> permissions
  }

  Scaffold(
    topBar = {
      CyberTopAppBar(
        title = "Permissions & Threat Matrix",
        subtitle = scan?.appName ?: "Capability Analysis",
        showBack = true,
        onBackClick = { viewModel.navigateTo(Screen.RESULTS) },
        onProfileClick = { viewModel.navigateTo(Screen.PROFILE) }
      )
    }
  ) { innerPadding ->
    LazyColumn(
      modifier = Modifier
        .fillMaxSize()
        .padding(innerPadding)
        .padding(16.dp),
      verticalArrangement = Arrangement.spacedBy(14.dp)
    ) {
      // FORENSIC METHODOLOGY NOTICE
      item {
        Card(
          modifier = Modifier.fillMaxWidth(),
          colors = CardDefaults.cardColors(containerColor = Color(0xFFF0F9FF)),
          shape = RoundedCornerShape(12.dp)
        ) {
          Row(
            modifier = Modifier.padding(14.dp),
            verticalAlignment = Alignment.CenterVertically
          ) {
            Icon(Icons.Default.Info, contentDescription = null, tint = CyberBluePrimary, modifier = Modifier.size(22.dp))
            Spacer(modifier = Modifier.width(10.dp))
            Column {
              Text(
                text = "Heuristic Capability Principle",
                style = MaterialTheme.typography.titleSmall.copy(fontWeight = FontWeight.Bold),
                color = CyberBlueDark
              )
              Text(
                text = "Permissions represent granted OS capabilities and must not alone be considered proof of malware. The platform flags excessive or high-risk capability clusters.",
                style = MaterialTheme.typography.bodySmall,
                color = Slate600
              )
            }
          }
        }
      }

      // METRICS SUMMARY
      item {
        Row(
          modifier = Modifier.fillMaxWidth(),
          horizontalArrangement = Arrangement.spacedBy(8.dp)
        ) {
          PermissionMetricCard(
            title = "Declared",
            count = "${permissions.size}",
            color = CyberBluePrimary,
            modifier = Modifier.weight(1f)
          )
          PermissionMetricCard(
            title = "Dangerous",
            count = "${permissions.count { it.protectionLevel == "DANGEROUS" }}",
            color = SeverityCritical,
            modifier = Modifier.weight(1f)
          )
          PermissionMetricCard(
            title = "Normal",
            count = "${permissions.count { it.protectionLevel == "NORMAL" }}",
            color = Slate800,
            modifier = Modifier.weight(1f)
          )
        }
      }

      // FILTER CHIPS
      item {
        Row(
          modifier = Modifier.fillMaxWidth(),
          horizontalArrangement = Arrangement.spacedBy(8.dp)
        ) {
          listOf("ALL", "DANGEROUS", "NORMAL", "SPECIAL").forEach { chip ->
            FilterChip(
              selected = selectedProtectionFilter == chip,
              onClick = { selectedProtectionFilter = chip },
              label = { Text(chip, fontSize = 11.sp, fontWeight = FontWeight.SemiBold) },
              modifier = Modifier.testTag("filter_perm_$chip")
            )
          }
        }
      }

      if (filteredPermissions.isEmpty()) {
        item {
          Card(
            modifier = Modifier.fillMaxWidth(),
            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)
          ) {
            Box(modifier = Modifier.padding(24.dp), contentAlignment = Alignment.Center) {
              Text(text = "No permissions found under '$selectedProtectionFilter'.", color = Slate600)
            }
          }
        }
      } else {
        items(filteredPermissions) { item ->
          PermissionItemCard(item = item)
        }
      }

      item {
        Spacer(modifier = Modifier.height(20.dp))
      }
    }
  }
}

@Composable
fun PermissionMetricCard(title: String, count: String, color: Color, modifier: Modifier = Modifier) {
  Card(
    modifier = modifier,
    colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
    shape = RoundedCornerShape(10.dp)
  ) {
    Column(modifier = Modifier.padding(10.dp), horizontalAlignment = Alignment.CenterHorizontally) {
      Text(
        text = count,
        style = MaterialTheme.typography.titleMedium.copy(
          fontWeight = FontWeight.Black,
          fontFamily = FontFamily.Monospace
        ),
        color = color
      )
      Text(text = title, style = MaterialTheme.typography.labelSmall, color = Slate600)
    }
  }
}

@Composable
fun PermissionItemCard(item: PermissionThreatItem) {
  Card(
    modifier = Modifier
      .fillMaxWidth()
      .clip(RoundedCornerShape(12.dp))
      .testTag("perm_card_${item.humanName}"),
    colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
    elevation = CardDefaults.cardElevation(defaultElevation = 1.dp)
  ) {
    Column(modifier = Modifier.padding(14.dp)) {
      Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically
      ) {
        Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.weight(1f)) {
          Box(
            modifier = Modifier
              .size(28.dp)
              .clip(CircleShape)
              .background(
                if (item.threatLevel == Severity.CRITICAL || item.threatLevel == Severity.HIGH) SeverityCritical.copy(alpha = 0.12f)
                else CyberBluePrimary.copy(alpha = 0.12f)
              ),
            contentAlignment = Alignment.Center
          ) {
            Icon(
              imageVector = if (item.threatLevel == Severity.CRITICAL || item.threatLevel == Severity.HIGH) Icons.Default.Warning else Icons.Default.Policy,
              contentDescription = null,
              tint = if (item.threatLevel == Severity.CRITICAL || item.threatLevel == Severity.HIGH) SeverityCritical else CyberBluePrimary,
              modifier = Modifier.size(16.dp)
            )
          }

          Spacer(modifier = Modifier.width(10.dp))

          Column {
            Text(
              text = item.humanName,
              style = MaterialTheme.typography.bodyMedium.copy(fontWeight = FontWeight.Bold),
              color = MaterialTheme.colorScheme.onSurface
            )
            Text(
              text = item.protectionLevel,
              style = MaterialTheme.typography.labelSmall.copy(fontWeight = FontWeight.SemiBold),
              color = if (item.protectionLevel == "DANGEROUS") SeverityCritical else Slate600
            )
          }
        }

        SeverityBadge(severity = item.threatLevel)
      }

      Spacer(modifier = Modifier.height(8.dp))

      Surface(
        modifier = Modifier.fillMaxWidth(),
        color = Color(0xFFF8FAFC),
        shape = RoundedCornerShape(6.dp)
      ) {
        Text(
          text = item.permission,
          style = MaterialTheme.typography.labelSmall.copy(
            fontFamily = FontFamily.Monospace,
            fontSize = 11.sp
          ),
          color = Color(0xFF0369A1),
          modifier = Modifier.padding(horizontal = 8.dp, vertical = 4.dp)
        )
      }

      Spacer(modifier = Modifier.height(6.dp))

      Text(
        text = item.description,
        style = MaterialTheme.typography.bodySmall,
        color = Slate600
      )

      if (item.threatImpact.isNotBlank()) {
        Spacer(modifier = Modifier.height(6.dp))
        Row(verticalAlignment = Alignment.CenterVertically) {
          Text(
            text = "Threat Vector: ",
            style = MaterialTheme.typography.labelSmall.copy(fontWeight = FontWeight.Bold),
            color = CyberBlueDark
          )
          Text(
            text = item.threatImpact,
            style = MaterialTheme.typography.labelSmall.copy(fontWeight = FontWeight.SemiBold),
            color = if (item.threatLevel == Severity.CRITICAL || item.threatLevel == Severity.HIGH) SeverityCritical else Slate800
          )
        }
      }
    }
  }
}
