package com.example.ui.screens

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.net.Uri
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
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
import androidx.compose.material.icons.automirrored.filled.ArrowForward
import androidx.compose.material.icons.filled.Apps
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.CloudUpload
import androidx.compose.material.icons.filled.Info
import androidx.compose.material.icons.filled.PlayArrow
import androidx.compose.material.icons.filled.Security
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material.icons.filled.UploadFile
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.example.data.analyzer.SampleApkCatalog
import com.example.ui.MainViewModel
import com.example.ui.components.CyberTopAppBar
import com.example.ui.navigation.Screen
import com.example.ui.theme.CyberAccentCyan
import com.example.ui.theme.CyberBlueDark
import com.example.ui.theme.CyberBluePrimary
import com.example.ui.theme.RiskSafeGreen
import com.example.ui.theme.SeverityCritical
import com.example.ui.theme.SeverityHigh
import com.example.ui.theme.SeverityMedium
import com.example.ui.theme.Slate200
import com.example.ui.theme.Slate600
import com.example.ui.theme.Slate800
import java.io.File

data class InstalledAppItem(
  val appName: String,
  val packageName: String,
  val apkPath: String
)

@Composable
fun ApkUploadScreen(viewModel: MainViewModel) {
  val context = LocalContext.current
  var showInstalledAppsDialog by remember { mutableStateOf(false) }
  var installedApps by remember { mutableStateOf<List<InstalledAppItem>>(emptyList()) }

  // SAF Document Launcher for picking real APKs
  val apkPickerLauncher = rememberLauncherForActivityResult(
    contract = ActivityResultContracts.GetContent()
  ) { uri: Uri? ->
    if (uri != null) {
      val filename = uri.lastPathSegment?.substringAfterLast("/") ?: "uploaded_app.apk"
      viewModel.startRealApkAnalysis(uri, filename)
    }
  }

  Scaffold(
    topBar = {
      CyberTopAppBar(
        title = "APK File Ingestion",
        subtitle = "Select package for static analysis",
        showBack = true,
        onBackClick = { viewModel.navigateTo(Screen.DASHBOARD) },
        onProfileClick = { viewModel.navigateTo(Screen.PROFILE) }
      )
    }
  ) { innerPadding ->
    LazyColumn(
      modifier = Modifier
        .fillMaxSize()
        .padding(innerPadding)
        .padding(16.dp),
      verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
      // NON-EXECUTION SAFETY DISCLAIMER
      item {
        Card(
          modifier = Modifier.fillMaxWidth(),
          colors = CardDefaults.cardColors(containerColor = Color(0xFFEFF6FF)),
          shape = RoundedCornerShape(12.dp)
        ) {
          Row(
            modifier = Modifier.padding(14.dp),
            verticalAlignment = Alignment.CenterVertically
          ) {
            Icon(
              imageVector = Icons.Default.Info,
              contentDescription = null,
              tint = CyberBluePrimary,
              modifier = Modifier.size(24.dp)
            )
            Spacer(modifier = Modifier.width(12.dp))
            Column {
              Text(
                text = "Safe Forensic Sandbox Guarantee",
                style = MaterialTheme.typography.titleSmall.copy(fontWeight = FontWeight.Bold),
                color = CyberBlueDark
              )
              Text(
                text = "Zero execution policy: Uploaded APK files are inspected strictly via static byte stream and manifest parsing. No dynamic execution occurs.",
                style = MaterialTheme.typography.bodySmall,
                color = Slate600
              )
            }
          }
        }
      }

      // PRIMARY UPLOAD ZONE
      item {
        Card(
          modifier = Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(16.dp))
            .border(2.dp, CyberBluePrimary.copy(alpha = 0.4f), RoundedCornerShape(16.dp))
            .clickable { apkPickerLauncher.launch("*/*") }
            .testTag("upload_zone_clickable"),
          colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
          elevation = CardDefaults.cardElevation(defaultElevation = 2.dp)
        ) {
          Column(
            modifier = Modifier
              .fillMaxWidth()
              .padding(32.dp),
            horizontalAlignment = Alignment.CenterHorizontally
          ) {
            Box(
              modifier = Modifier
                .size(68.dp)
                .clip(CircleShape)
                .background(CyberBluePrimary.copy(alpha = 0.1f)),
              contentAlignment = Alignment.Center
            ) {
              Icon(
                imageVector = Icons.Default.CloudUpload,
                contentDescription = null,
                tint = CyberBluePrimary,
                modifier = Modifier.size(36.dp)
              )
            }

            Spacer(modifier = Modifier.height(14.dp))

            Text(
              text = "Choose Android APK File",
              style = MaterialTheme.typography.titleMedium.copy(fontWeight = FontWeight.Bold),
              color = MaterialTheme.colorScheme.onSurface
            )

            Spacer(modifier = Modifier.height(4.dp))

            Text(
              text = "Tap to browse local device storage (.apk up to 100 MiB)",
              style = MaterialTheme.typography.bodySmall,
              color = Slate600
            )

            Spacer(modifier = Modifier.height(16.dp))

            Button(
              onClick = { apkPickerLauncher.launch("*/*") },
              modifier = Modifier.testTag("btn_browse_apk_files"),
              colors = ButtonDefaults.buttonColors(containerColor = CyberBluePrimary),
              shape = RoundedCornerShape(8.dp)
            ) {
              Icon(Icons.Default.UploadFile, contentDescription = null, modifier = Modifier.size(18.dp))
              Spacer(modifier = Modifier.width(8.dp))
              Text("Browse APK Files", fontWeight = FontWeight.Bold)
            }
          }
        }
      }

      // INSPECT INSTALLED APPS OPTION
      item {
        Card(
          modifier = Modifier.fillMaxWidth(),
          colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
          shape = RoundedCornerShape(12.dp)
        ) {
          Row(
            modifier = Modifier
              .fillMaxWidth()
              .clickable {
                installedApps = getDeviceInstalledApps(context)
                showInstalledAppsDialog = true
              }
              .padding(16.dp)
              .testTag("btn_select_installed_app"),
            verticalAlignment = Alignment.CenterVertically
          ) {
            Box(
              modifier = Modifier
                .size(40.dp)
                .clip(CircleShape)
                .background(Color(0xFFE0F2FE)),
              contentAlignment = Alignment.Center
            ) {
              Icon(Icons.Default.Apps, contentDescription = null, tint = CyberBluePrimary)
            }
            Spacer(modifier = Modifier.width(12.dp))
            Column(modifier = Modifier.weight(1f)) {
              Text(
                text = "Inspect Installed Device Application",
                style = MaterialTheme.typography.bodyMedium.copy(fontWeight = FontWeight.Bold),
                color = MaterialTheme.colorScheme.onSurface
              )
              Text(
                text = "Audit permissions and components of apps installed on this device",
                style = MaterialTheme.typography.bodySmall,
                color = Slate600
              )
            }
            Icon(Icons.AutoMirrored.Filled.ArrowForward, contentDescription = null, tint = Slate600)
          }
        }
      }

      // BENCHMARK REPOSITORY (DEMO DATA)
      item {
        Row(
          modifier = Modifier.fillMaxWidth(),
          horizontalArrangement = Arrangement.SpaceBetween,
          verticalAlignment = Alignment.CenterVertically
        ) {
          Text(
            text = "Pre-Configured Benchmark Artifacts",
            style = MaterialTheme.typography.titleSmall.copy(fontWeight = FontWeight.Bold),
            color = MaterialTheme.colorScheme.onBackground
          )
          Surface(color = Color(0xFFF1F5F9), shape = RoundedCornerShape(4.dp)) {
            Text(
              text = "DEMO REPO",
              style = MaterialTheme.typography.labelSmall.copy(fontWeight = FontWeight.Bold),
              color = Slate600,
              modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp)
            )
          }
        }
      }

      items(SampleApkCatalog.benchmarks) { benchmark ->
        Card(
          modifier = Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(12.dp))
            .clickable { viewModel.startBenchmarkAnalysis(benchmark) }
            .testTag("upload_benchmark_${benchmark.id}"),
          colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
          elevation = CardDefaults.cardElevation(defaultElevation = 1.dp)
        ) {
          Row(
            modifier = Modifier.padding(14.dp),
            verticalAlignment = Alignment.CenterVertically
          ) {
            Box(
              modifier = Modifier
                .size(42.dp)
                .clip(CircleShape)
                .background(
                  if (benchmark.expectedRiskScore > 75) SeverityCritical.copy(alpha = 0.12f)
                  else if (benchmark.expectedRiskScore > 40) SeverityMedium.copy(alpha = 0.12f)
                  else RiskSafeGreen.copy(alpha = 0.12f)
                ),
              contentAlignment = Alignment.Center
            ) {
              Icon(
                imageVector = Icons.Default.PlayArrow,
                contentDescription = null,
                tint = if (benchmark.expectedRiskScore > 75) SeverityCritical else CyberBluePrimary
              )
            }

            Spacer(modifier = Modifier.width(12.dp))

            Column(modifier = Modifier.weight(1f)) {
              Text(
                text = benchmark.name,
                style = MaterialTheme.typography.bodyMedium.copy(fontWeight = FontWeight.Bold),
                color = MaterialTheme.colorScheme.onSurface
              )
              Text(
                text = benchmark.description,
                style = MaterialTheme.typography.bodySmall,
                color = Slate600,
                maxLines = 2
              )
              Spacer(modifier = Modifier.height(4.dp))
              Row(verticalAlignment = Alignment.CenterVertically) {
                Text(
                  text = "${benchmark.filename} • ${benchmark.fileSizeFormatted}",
                  style = MaterialTheme.typography.labelSmall.copy(fontFamily = FontFamily.Monospace),
                  color = Slate600
                )
                Spacer(modifier = Modifier.width(8.dp))
                Text(
                  text = "Risk: ${benchmark.expectedRiskScore}/100",
                  style = MaterialTheme.typography.labelSmall.copy(
                    fontWeight = FontWeight.Bold,
                    color = if (benchmark.expectedRiskScore > 70) SeverityCritical else CyberBluePrimary
                  )
                )
              }
            }
          }
        }
      }

      item {
        Spacer(modifier = Modifier.height(20.dp))
      }
    }
  }

  // DIALOG FOR INSTALLED APPS
  if (showInstalledAppsDialog) {
    AlertDialog(
      onDismissRequest = { showInstalledAppsDialog = false },
      title = { Text("Select Installed App to Audit", fontWeight = FontWeight.Bold) },
      text = {
        LazyColumn(
          modifier = Modifier
            .fillMaxWidth()
            .height(350.dp),
          verticalArrangement = Arrangement.spacedBy(8.dp)
        ) {
          items(installedApps) { app ->
            Surface(
              modifier = Modifier
                .fillMaxWidth()
                .clip(RoundedCornerShape(8.dp))
                .clickable {
                  showInstalledAppsDialog = false
                  val file = File(app.apkPath)
                  if (file.exists()) {
                    viewModel.startRealApkAnalysis(Uri.fromFile(file), "${app.packageName}.apk")
                  }
                },
              color = Color(0xFFF8FAFC)
            ) {
              Column(modifier = Modifier.padding(10.dp)) {
                Text(text = app.appName, fontWeight = FontWeight.Bold, style = MaterialTheme.typography.bodyMedium)
                Text(text = app.packageName, style = MaterialTheme.typography.bodySmall, color = Slate600)
              }
            }
          }
        }
      },
      confirmButton = {
        TextButton(onClick = { showInstalledAppsDialog = false }) {
          Text("Close")
        }
      }
    )
  }
}

fun getDeviceInstalledApps(context: Context): List<InstalledAppItem> {
  val pm = context.packageManager
  val packages = pm.getInstalledApplications(PackageManager.GET_META_DATA)
  return packages
    .filter { it.sourceDir != null }
    .take(20)
    .map { appInfo ->
      InstalledAppItem(
        appName = appInfo.loadLabel(pm).toString(),
        packageName = appInfo.packageName,
        apkPath = appInfo.sourceDir
      )
    }
}
