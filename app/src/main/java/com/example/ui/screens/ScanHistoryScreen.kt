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
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.DeleteOutline
import androidx.compose.material.icons.filled.History
import androidx.compose.material.icons.filled.Search
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.FilterChip
import androidx.compose.material3.FilterChipDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.OutlinedTextFieldDefaults
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
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
import com.example.data.model.RiskLabel
import com.example.data.model.ScanRecord
import com.example.ui.MainViewModel
import com.example.ui.components.CyberTopAppBar
import com.example.ui.navigation.Screen
import com.example.ui.theme.ConsoleBlueBg
import com.example.ui.theme.ConsoleBluePrimary
import com.example.ui.theme.ConsoleBorder
import com.example.ui.theme.ConsoleNavy
import com.example.ui.theme.ConsoleWhite
import com.example.ui.theme.RiskSafeGreen
import com.example.ui.theme.SeverityCritical
import com.example.ui.theme.SeverityCriticalBg
import com.example.ui.theme.SeverityHigh
import com.example.ui.theme.SeverityHighBg
import com.example.ui.theme.SeverityMedium
import com.example.ui.theme.SeverityMediumBg
import com.example.ui.theme.Slate200
import com.example.ui.theme.Slate600
import com.example.ui.theme.Slate700
import com.example.ui.theme.Slate800
import com.example.ui.theme.Slate900
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

@Composable
fun ScanHistoryScreen(viewModel: MainViewModel) {
  val scans by viewModel.allScans.collectAsState()
  val searchQuery by viewModel.historySearchQuery.collectAsState()
  val severityFilter by viewModel.historyFilterSeverity.collectAsState()

  var scanToDelete by remember { mutableStateOf<ScanRecord?>(null) }

  val filteredScans = scans.filter { scan ->
    val matchesQuery = searchQuery.isBlank() ||
        scan.appName.contains(searchQuery, ignoreCase = true) ||
        scan.packageName.contains(searchQuery, ignoreCase = true) ||
        scan.sha256Hash.contains(searchQuery, ignoreCase = true)

    val matchesSeverity = when (severityFilter) {
      "CRITICAL" -> scan.riskLabel == RiskLabel.CRITICAL
      "HIGH" -> scan.riskLabel == RiskLabel.HIGH
      "MEDIUM" -> scan.riskLabel == RiskLabel.MEDIUM
      "LOW" -> scan.riskLabel == RiskLabel.LOW
      "SAFE" -> scan.riskLabel == RiskLabel.SAFE
      else -> true
    }

    matchesQuery && matchesSeverity
  }

  Scaffold(
    topBar = {
      CyberTopAppBar(
        title = "Scan History & Audits",
        subtitle = "${scans.size} total forensic evaluations",
        showBack = true,
        onBackClick = { viewModel.navigateTo(Screen.DASHBOARD) },
        onProfileClick = { viewModel.navigateTo(Screen.PROFILE) }
      )
    },
    containerColor = ConsoleWhite
  ) { innerPadding ->
    Column(
      modifier = Modifier
        .fillMaxSize()
        .padding(innerPadding)
        .padding(horizontal = 16.dp, vertical = 12.dp)
    ) {
      // ENTERPRISE SEARCH BAR
      OutlinedTextField(
        value = searchQuery,
        onValueChange = { viewModel.setHistorySearch(it) },
        label = { Text("Filter by app name, package, or SHA-256 hash") },
        leadingIcon = { Icon(Icons.Default.Search, contentDescription = null, tint = ConsoleBluePrimary) },
        modifier = Modifier
          .fillMaxWidth()
          .testTag("input_history_search"),
        singleLine = true,
        colors = OutlinedTextFieldDefaults.colors(
          focusedBorderColor = ConsoleBluePrimary,
          unfocusedBorderColor = ConsoleBorder,
          focusedContainerColor = ConsoleWhite,
          unfocusedContainerColor = ConsoleWhite
        ),
        shape = RoundedCornerShape(8.dp)
      )

      Spacer(modifier = Modifier.height(10.dp))

      // SEVERITY FILTER CHIPS
      Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.spacedBy(6.dp)
      ) {
        listOf("ALL", "CRITICAL", "HIGH", "MEDIUM", "SAFE").forEach { filter ->
          FilterChip(
            selected = severityFilter == filter,
            onClick = { viewModel.setHistoryFilter(filter) },
            label = { Text(filter, fontSize = 11.sp, fontWeight = FontWeight.Bold) },
            modifier = Modifier.testTag("filter_history_$filter"),
            colors = FilterChipDefaults.filterChipColors(
              selectedContainerColor = ConsoleNavy,
              selectedLabelColor = ConsoleWhite,
              containerColor = ConsoleWhite,
              labelColor = Slate800
            ),
            border = FilterChipDefaults.filterChipBorder(
              enabled = true,
              selected = severityFilter == filter,
              borderColor = if (severityFilter == filter) ConsoleNavy else ConsoleBorder
            ),
            shape = RoundedCornerShape(6.dp)
          )
        }
      }

      Spacer(modifier = Modifier.height(12.dp))

      if (filteredScans.isEmpty()) {
        Card(
          modifier = Modifier
            .fillMaxWidth()
            .border(1.dp, ConsoleBorder, RoundedCornerShape(8.dp)),
          colors = CardDefaults.cardColors(containerColor = ConsoleWhite),
          shape = RoundedCornerShape(8.dp),
          elevation = CardDefaults.cardElevation(defaultElevation = 0.dp)
        ) {
          Column(
            modifier = Modifier
              .fillMaxWidth()
              .padding(32.dp),
            horizontalAlignment = Alignment.CenterHorizontally
          ) {
            Icon(Icons.Default.History, contentDescription = null, tint = Slate600, modifier = Modifier.size(36.dp))
            Spacer(modifier = Modifier.height(10.dp))
            Text(
              text = if (scans.isEmpty()) "No Forensic Audits Recorded" else "No matching scans found",
              style = MaterialTheme.typography.titleMedium.copy(fontWeight = FontWeight.Bold),
              color = Slate900
            )
            Spacer(modifier = Modifier.height(6.dp))
            Text(
              text = "Adjust search criteria or upload an APK package to conduct an investigation.",
              style = MaterialTheme.typography.bodySmall,
              color = Slate600
            )
            Spacer(modifier = Modifier.height(14.dp))
            Button(
              onClick = { viewModel.navigateTo(Screen.UPLOAD) },
              colors = ButtonDefaults.buttonColors(containerColor = ConsoleBluePrimary),
              shape = RoundedCornerShape(6.dp),
              modifier = Modifier.testTag("btn_audit_new_apk_empty")
            ) {
              Text("Audit New APK Package", fontWeight = FontWeight.Bold)
            }
          }
        }
      } else {
        LazyColumn(
          modifier = Modifier.fillMaxSize(),
          verticalArrangement = Arrangement.spacedBy(8.dp)
        ) {
          items(filteredScans, key = { it.id }) { scan ->
            HistoryItemCard(
              scan = scan,
              onClick = { viewModel.openHistoricalScan(scan) },
              onDelete = { scanToDelete = scan }
            )
          }
        }
      }
    }
  }

  // DELETE CONFIRMATION DIALOG
  if (scanToDelete != null) {
    AlertDialog(
      onDismissRequest = { scanToDelete = null },
      containerColor = ConsoleWhite,
      title = { Text("Delete Forensic Record?", fontWeight = FontWeight.Bold, color = Slate900) },
      text = {
        Text("Are you sure you want to delete the forensic record for '${scanToDelete?.appName}'? This action removes the scan record and all associated findings.", color = Slate700)
      },
      confirmButton = {
        Button(
          onClick = {
            scanToDelete?.let { viewModel.deleteScan(it.id) }
            scanToDelete = null
          },
          colors = ButtonDefaults.buttonColors(containerColor = SeverityCritical),
          shape = RoundedCornerShape(6.dp)
        ) {
          Text("Delete Record", fontWeight = FontWeight.Bold)
        }
      },
      dismissButton = {
        TextButton(onClick = { scanToDelete = null }) {
          Text("Cancel", color = Slate800, fontWeight = FontWeight.Medium)
        }
      }
    )
  }
}

@Composable
fun HistoryItemCard(
  scan: ScanRecord,
  onClick: () -> Unit,
  onDelete: () -> Unit
) {
  val dateFormat = SimpleDateFormat("MMM dd, yyyy HH:mm", Locale.getDefault())
  val dateStr = dateFormat.format(Date(scan.completedAt))

  val (scoreColor, scoreBg) = when (scan.riskLabel) {
    RiskLabel.CRITICAL -> SeverityCritical to SeverityCriticalBg
    RiskLabel.HIGH -> SeverityHigh to SeverityHighBg
    RiskLabel.MEDIUM -> SeverityMedium to SeverityMediumBg
    RiskLabel.LOW -> SeverityMedium to SeverityMediumBg
    RiskLabel.SAFE -> RiskSafeGreen to Color(0xFFDCFCE7)
  }

  Card(
    modifier = Modifier
      .fillMaxWidth()
      .border(1.dp, ConsoleBorder, RoundedCornerShape(8.dp))
      .clickable(onClick = onClick)
      .testTag("history_card_${scan.id}"),
    colors = CardDefaults.cardColors(containerColor = ConsoleWhite),
    shape = RoundedCornerShape(8.dp),
    elevation = CardDefaults.cardElevation(defaultElevation = 0.dp)
  ) {
    Row(
      modifier = Modifier.padding(14.dp),
      verticalAlignment = Alignment.CenterVertically
    ) {
      // Risk Score Box
      Box(
        modifier = Modifier
          .width(52.dp)
          .height(52.dp)
          .clip(RoundedCornerShape(6.dp))
          .background(scoreBg),
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
          Text(
            text = scan.riskLabel.name,
            style = MaterialTheme.typography.labelSmall.copy(fontWeight = FontWeight.Bold),
            fontSize = 8.sp,
            color = scoreColor
          )
        }
      }

      Spacer(modifier = Modifier.width(12.dp))

      Column(modifier = Modifier.weight(1f)) {
        Text(
          text = scan.appName,
          style = MaterialTheme.typography.bodyMedium.copy(fontWeight = FontWeight.Bold),
          color = Slate900,
          maxLines = 1
        )
        Text(
          text = scan.packageName,
          style = MaterialTheme.typography.bodySmall.copy(fontFamily = FontFamily.Monospace),
          color = Slate600,
          fontSize = 11.sp,
          maxLines = 1
        )
        Spacer(modifier = Modifier.height(4.dp))
        Row(verticalAlignment = Alignment.CenterVertically) {
          Text(
            text = "SHA: ${scan.sha256Hash.take(10)}... • $dateStr",
            style = MaterialTheme.typography.labelSmall.copy(fontFamily = FontFamily.Monospace),
            color = Slate600,
            fontSize = 10.sp
          )
        }
      }

      IconButton(
        onClick = onDelete,
        modifier = Modifier.testTag("btn_delete_scan_${scan.id}")
      ) {
        Icon(Icons.Default.DeleteOutline, contentDescription = "Delete", tint = SeverityCritical)
      }
    }
  }
}
