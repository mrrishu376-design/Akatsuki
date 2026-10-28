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
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.History
import androidx.compose.material.icons.filled.Search
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.FilterChip
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
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
import com.example.data.model.Severity
import com.example.ui.MainViewModel
import com.example.ui.components.CyberTopAppBar
import com.example.ui.components.SeverityBadge
import com.example.ui.navigation.Screen
import com.example.ui.theme.CyberBlueDark
import com.example.ui.theme.CyberBluePrimary
import com.example.ui.theme.RiskSafeGreen
import com.example.ui.theme.SeverityCritical
import com.example.ui.theme.SeverityHigh
import com.example.ui.theme.SeverityMedium
import com.example.ui.theme.Slate200
import com.example.ui.theme.Slate600
import com.example.ui.theme.Slate800
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
        subtitle = "${scans.size} total evaluations",
        showBack = true,
        onBackClick = { viewModel.navigateTo(Screen.DASHBOARD) },
        onProfileClick = { viewModel.navigateTo(Screen.PROFILE) }
      )
    }
  ) { innerPadding ->
    Column(
      modifier = Modifier
        .fillMaxSize()
        .padding(innerPadding)
        .padding(16.dp)
    ) {
      // SEARCH BAR
      OutlinedTextField(
        value = searchQuery,
        onValueChange = { viewModel.setHistorySearch(it) },
        label = { Text("Search by name, package, or SHA-256") },
        leadingIcon = { Icon(Icons.Default.Search, contentDescription = null, tint = CyberBluePrimary) },
        modifier = Modifier
          .fillMaxWidth()
          .testTag("input_history_search"),
        singleLine = true
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
            modifier = Modifier.testTag("filter_history_$filter")
          )
        }
      }

      Spacer(modifier = Modifier.height(14.dp))

      if (filteredScans.isEmpty()) {
        Card(
          modifier = Modifier.fillMaxWidth(),
          colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
          shape = RoundedCornerShape(12.dp)
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
              text = if (scans.isEmpty()) "No Scans Recorded Yet" else "No matching scans found",
              style = MaterialTheme.typography.titleMedium.copy(fontWeight = FontWeight.Bold),
              color = MaterialTheme.colorScheme.onSurface
            )
            Spacer(modifier = Modifier.height(6.dp))
            Text(
              text = "Adjust search filters or upload a new APK package for evaluation.",
              style = MaterialTheme.typography.bodySmall,
              color = Slate600
            )
            Spacer(modifier = Modifier.height(12.dp))
            Button(
              onClick = { viewModel.navigateTo(Screen.UPLOAD) },
              colors = ButtonDefaults.buttonColors(containerColor = CyberBluePrimary),
              shape = RoundedCornerShape(8.dp)
            ) {
              Text("Audit New APK")
            }
          }
        }
      } else {
        LazyColumn(
          modifier = Modifier.fillMaxSize(),
          verticalArrangement = Arrangement.spacedBy(10.dp)
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
      title = { Text("Delete Audit Record?", fontWeight = FontWeight.Bold) },
      text = {
        Text("Are you sure you want to delete the forensic record for '${scanToDelete?.appName}'? This action removes the scan record and all associated findings.")
      },
      confirmButton = {
        Button(
          onClick = {
            scanToDelete?.let { viewModel.deleteScan(it.id) }
            scanToDelete = null
          },
          colors = ButtonDefaults.buttonColors(containerColor = SeverityCritical)
        ) {
          Text("Delete Record")
        }
      },
      dismissButton = {
        TextButton(onClick = { scanToDelete = null }) {
          Text("Cancel")
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

  Card(
    modifier = Modifier
      .fillMaxWidth()
      .clip(RoundedCornerShape(12.dp))
      .clickable(onClick = onClick)
      .testTag("history_card_${scan.id}"),
    colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
    elevation = CardDefaults.cardElevation(defaultElevation = 1.dp)
  ) {
    Row(
      modifier = Modifier.padding(14.dp),
      verticalAlignment = Alignment.CenterVertically
    ) {
      Column(
        horizontalAlignment = Alignment.CenterHorizontally,
        modifier = Modifier.width(48.dp)
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
            RiskLabel.LOW -> SeverityMedium
            RiskLabel.SAFE -> RiskSafeGreen
          }
        )
        Text(text = scan.riskLabel.name, style = MaterialTheme.typography.labelSmall, fontSize = 9.sp, color = Slate600)
      }

      Spacer(modifier = Modifier.width(12.dp))

      Column(modifier = Modifier.weight(1f)) {
        Text(
          text = scan.appName,
          style = MaterialTheme.typography.bodyMedium.copy(fontWeight = FontWeight.Bold),
          color = MaterialTheme.colorScheme.onSurface,
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
        Text(
          text = "SHA: ${scan.sha256Hash.take(12)}... • $dateStr",
          style = MaterialTheme.typography.labelSmall.copy(fontFamily = FontFamily.Monospace),
          color = Slate600
        )
      }

      IconButton(
        onClick = onDelete,
        modifier = Modifier.testTag("btn_delete_scan_${scan.id}")
      ) {
        Icon(Icons.Default.Delete, contentDescription = "Delete", tint = Color(0xFFEF4444))
      }
    }
  }
}
