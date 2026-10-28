package com.example.ui.screens

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
import androidx.compose.material.icons.filled.Info
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.Policy
import androidx.compose.material.icons.filled.Security
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.FilterChip
import androidx.compose.material3.FilterChipDefaults
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
import com.example.ui.theme.ConsoleBlueBg
import com.example.ui.theme.ConsoleBluePrimary
import com.example.ui.theme.ConsoleBorder
import com.example.ui.theme.ConsoleNavy
import com.example.ui.theme.ConsoleWhite
import com.example.ui.theme.SeverityCritical
import com.example.ui.theme.SeverityCriticalBg
import com.example.ui.theme.SeverityHigh
import com.example.ui.theme.SeverityHighBg
import com.example.ui.theme.SeverityMedium
import com.example.ui.theme.Slate200
import com.example.ui.theme.Slate600
import com.example.ui.theme.Slate800
import com.example.ui.theme.Slate900

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

  val dangerousCount = permissions.count { it.protectionLevel == "DANGEROUS" }
  val normalCount = permissions.count { it.protectionLevel == "NORMAL" }
  val specialCount = permissions.count { it.protectionLevel == "SPECIAL" || it.protectionLevel.contains("SIGNATURE") }

  Scaffold(
    topBar = {
      CyberTopAppBar(
        title = "Permissions & Threat Matrix",
        subtitle = scan?.appName ?: "Manifest Capability Audit",
        showBack = true,
        onBackClick = { viewModel.navigateTo(Screen.RESULTS) },
        onProfileClick = { viewModel.navigateTo(Screen.PROFILE) }
      )
    },
    containerColor = ConsoleWhite
  ) { innerPadding ->
    LazyColumn(
      modifier = Modifier
        .fillMaxSize()
        .padding(innerPadding)
        .padding(horizontal = 16.dp, vertical = 12.dp),
      verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
      // FORENSIC METHODOLOGY NOTICE
      item {
        Card(
          modifier = Modifier
            .fillMaxWidth()
            .border(1.dp, Color(0xFFBAE6FD), RoundedCornerShape(8.dp)),
          colors = CardDefaults.cardColors(containerColor = ConsoleBlueBg),
          shape = RoundedCornerShape(8.dp),
          elevation = CardDefaults.cardElevation(defaultElevation = 0.dp)
        ) {
          Row(
            modifier = Modifier.padding(14.dp),
            verticalAlignment = Alignment.CenterVertically
          ) {
            Icon(Icons.Default.Info, contentDescription = null, tint = ConsoleBluePrimary, modifier = Modifier.size(22.dp))
            Spacer(modifier = Modifier.width(10.dp))
            Column {
              Text(
                text = "Heuristic Capability Principle",
                style = MaterialTheme.typography.titleSmall.copy(fontWeight = FontWeight.Bold),
                color = ConsoleNavy
              )
              Text(
                text = "Permissions represent OS-level capabilities requested by the APK and are not proof of malware on their own. Our static analysis highlights excessive privilege clustering and dangerous intent patterns.",
                style = MaterialTheme.typography.bodySmall,
                color = Slate600
              )
            }
          }
        }
      }

      // METRICS SUMMARY CARDS
      item {
        Row(
          modifier = Modifier.fillMaxWidth(),
          horizontalArrangement = Arrangement.spacedBy(8.dp)
        ) {
          PermissionMetricCard(
            title = "Declared",
            count = "${permissions.size}",
            color = ConsoleBluePrimary,
            modifier = Modifier.weight(1f)
          )
          PermissionMetricCard(
            title = "Dangerous",
            count = "$dangerousCount",
            color = SeverityCritical,
            modifier = Modifier.weight(1f)
          )
          PermissionMetricCard(
            title = "Signature/Special",
            count = "$specialCount",
            color = SeverityHigh,
            modifier = Modifier.weight(1f)
          )
          PermissionMetricCard(
            title = "Normal",
            count = "$normalCount",
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
          listOf("ALL", "DANGEROUS", "SPECIAL", "NORMAL").forEach { chip ->
            FilterChip(
              selected = selectedProtectionFilter == chip,
              onClick = { selectedProtectionFilter = chip },
              label = { Text(chip, fontSize = 11.sp, fontWeight = FontWeight.Bold) },
              modifier = Modifier.testTag("filter_perm_$chip"),
              colors = FilterChipDefaults.filterChipColors(
                selectedContainerColor = ConsoleNavy,
                selectedLabelColor = ConsoleWhite,
                containerColor = ConsoleWhite,
                labelColor = Slate800
              ),
              border = FilterChipDefaults.filterChipBorder(
                enabled = true,
                selected = selectedProtectionFilter == chip,
                borderColor = if (selectedProtectionFilter == chip) ConsoleNavy else ConsoleBorder
              ),
              shape = RoundedCornerShape(6.dp)
            )
          }
        }
      }

      if (filteredPermissions.isEmpty()) {
        item {
          Card(
            modifier = Modifier
              .fillMaxWidth()
              .border(1.dp, ConsoleBorder, RoundedCornerShape(8.dp)),
            colors = CardDefaults.cardColors(containerColor = ConsoleWhite),
            elevation = CardDefaults.cardElevation(defaultElevation = 0.dp),
            shape = RoundedCornerShape(8.dp)
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
    modifier = modifier.border(1.dp, ConsoleBorder, RoundedCornerShape(8.dp)),
    colors = CardDefaults.cardColors(containerColor = ConsoleWhite),
    shape = RoundedCornerShape(8.dp),
    elevation = CardDefaults.cardElevation(defaultElevation = 0.dp)
  ) {
    Column(
      modifier = Modifier.padding(10.dp),
      horizontalAlignment = Alignment.CenterHorizontally
    ) {
      Text(
        text = count,
        style = MaterialTheme.typography.titleMedium.copy(
          fontWeight = FontWeight.Black,
          fontFamily = FontFamily.Monospace
        ),
        color = color
      )
      Text(
        text = title,
        style = MaterialTheme.typography.labelSmall.copy(fontWeight = FontWeight.Medium),
        color = Slate600,
        maxLines = 1
      )
    }
  }
}

@Composable
fun PermissionItemCard(item: PermissionThreatItem) {
  val isHighThreat = item.threatLevel == Severity.CRITICAL || item.threatLevel == Severity.HIGH

  Card(
    modifier = Modifier
      .fillMaxWidth()
      .border(1.dp, if (isHighThreat) SeverityCritical.copy(alpha = 0.4f) else ConsoleBorder, RoundedCornerShape(8.dp))
      .testTag("perm_card_${item.humanName}"),
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
        Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.weight(1f)) {
          Box(
            modifier = Modifier
              .size(28.dp)
              .clip(RoundedCornerShape(6.dp))
              .background(
                if (isHighThreat) SeverityCriticalBg
                else ConsoleBlueBg
              ),
            contentAlignment = Alignment.Center
          ) {
            Icon(
              imageVector = if (isHighThreat) Icons.Default.Warning else Icons.Default.Policy,
              contentDescription = null,
              tint = if (isHighThreat) SeverityCritical else ConsoleBluePrimary,
              modifier = Modifier.size(16.dp)
            )
          }

          Spacer(modifier = Modifier.width(10.dp))

          Column {
            Text(
              text = item.humanName,
              style = MaterialTheme.typography.bodyMedium.copy(fontWeight = FontWeight.Bold),
              color = Slate900
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
        shape = RoundedCornerShape(4.dp),
        border = androidx.compose.foundation.BorderStroke(1.dp, Color(0xFFE2E8F0))
      ) {
        Text(
          text = item.permission,
          style = MaterialTheme.typography.labelSmall.copy(
            fontFamily = FontFamily.Monospace,
            fontSize = 11.sp
          ),
          color = ConsoleBluePrimary,
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
            color = ConsoleNavy
          )
          Text(
            text = item.threatImpact,
            style = MaterialTheme.typography.labelSmall.copy(fontWeight = FontWeight.SemiBold),
            color = if (isHighThreat) SeverityCritical else Slate800
          )
        }
      }
    }
  }
}
