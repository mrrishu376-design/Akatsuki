package com.example.ui.screens

import android.content.Context
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
import androidx.compose.material.icons.filled.CloudUpload
import androidx.compose.material.icons.filled.Info
import androidx.compose.material.icons.filled.PlayArrow
import androidx.compose.material.icons.filled.Security
import androidx.compose.material.icons.filled.UploadFile
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
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
import com.example.LocalNavigationDrawerToggle
import com.example.data.analyzer.SampleApkCatalog
import com.example.ui.MainViewModel
import com.example.ui.components.CyberTopAppBar
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
import com.example.ui.theme.SeverityMedium
import com.example.ui.theme.Slate600
import com.example.ui.theme.Slate700
import com.example.ui.theme.Slate800
import com.example.ui.theme.Slate900
import java.io.File

@Composable
fun ApkUploadScreen(viewModel: MainViewModel) {
  val context = LocalContext.current
  val toggleDrawer = LocalNavigationDrawerToggle.current
  var showInstalledAppsDialog by remember { mutableStateOf(false) }
  var installedApps by remember { mutableStateOf<List<InstalledAppItem>>(emptyList()) }

  // SAF Document Launcher for picking real APK files
  val apkPickerLauncher = rememberLauncherForActivityResult(
    contract = ActivityResultContracts.GetContent()
  ) { uri: Uri? ->
    if (uri != null) {
      val filename = uri.lastPathSegment?.substringAfterLast("/") ?: "target_application.apk"
      viewModel.startRealApkAnalysis(uri, filename)
    }
  }

  Scaffold(
    topBar = {
      CyberTopAppBar(
        title = "APK Investigation Intake",
        subtitle = "Zero-Execution Ingestion & Analysis Engine",
        showBack = true,
        onBackClick = { viewModel.navigateTo(Screen.DASHBOARD) },
        onMenuClick = toggleDrawer,
        onProfileClick = { viewModel.navigateTo(Screen.PROFILE) }
      )
    },
    containerColor = Color.White
  ) { innerPadding ->
    LazyColumn(
      modifier = Modifier
        .fillMaxSize()
        .background(Color.White)
        .padding(innerPadding)
        .padding(16.dp),
      verticalArrangement = Arrangement.spacedBy(14.dp)
    ) {
      // PROMINENT LARGE UPLOAD ZONE
      item {
        Card(
          modifier = Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(8.dp))
            .border(2.dp, ConsoleBluePrimary, RoundedCornerShape(8.dp))
            .background(Color(0xFFF8FAFC))
            .testTag("upload_zone_clickable"),
          colors = CardDefaults.cardColors(containerColor = Color(0xFFF8FAFC)),
          elevation = CardDefaults.cardElevation(defaultElevation = 0.dp)
        ) {
          Column(
            modifier = Modifier
              .fillMaxWidth()
              .padding(28.dp),
            horizontalAlignment = Alignment.CenterHorizontally
          ) {
            Box(
              modifier = Modifier
                .size(64.dp)
                .clip(CircleShape)
                .background(ConsoleNavy),
              contentAlignment = Alignment.Center
            ) {
              Icon(
                imageVector = Icons.Default.CloudUpload,
                contentDescription = null,
                tint = Color(0xFF38BDF8),
                modifier = Modifier.size(34.dp)
              )
            }

            Spacer(modifier = Modifier.height(14.dp))

            Text(
              text = "SELECT TARGET APK FOR AUDIT",
              style = MaterialTheme.typography.titleMedium.copy(
                fontWeight = FontWeight.Black,
                letterSpacing = 0.8.sp
              ),
              color = Slate900
            )

            Spacer(modifier = Modifier.height(4.dp))

            Text(
              text = "Supports standard Android packages (.apk up to 100 MiB)",
              style = MaterialTheme.typography.bodySmall,
              color = Slate600
            )

            Spacer(modifier = Modifier.height(16.dp))

            // LARGE PRIMARY BLUE UPLOAD BUTTON
            Button(
              onClick = { apkPickerLauncher.launch("*/*") },
              modifier = Modifier
                .fillMaxWidth()
                .height(52.dp)
                .testTag("btn_browse_apk_files"),
              colors = ButtonDefaults.buttonColors(containerColor = ConsoleBluePrimary),
              shape = RoundedCornerShape(6.dp)
            ) {
              Icon(Icons.Default.UploadFile, contentDescription = null, modifier = Modifier.size(20.dp))
              Spacer(modifier = Modifier.width(8.dp))
              Text(
                text = "BROWSE AND SELECT APK",
                fontWeight = FontWeight.Bold,
                fontSize = 13.sp,
                letterSpacing = 0.5.sp
              )
            }

            Spacer(modifier = Modifier.height(10.dp))

            Text(
              text = "SHA-256 and MD5 cryptographic hashes will be computed automatically upon selection.",
              style = MaterialTheme.typography.labelSmall.copy(fontSize = 10.sp),
              color = Slate600
            )
          }
        }
      }

      // INSPECT INSTALLED APPS OPTION
      item {
        Surface(
          modifier = Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(6.dp))
            .border(1.dp, ConsoleBorder, RoundedCornerShape(6.dp))
            .clickable {
              installedApps = getDeviceInstalledApps(context)
              showInstalledAppsDialog = true
            }
            .testTag("btn_select_installed_app"),
          color = Color.White
        ) {
          Row(
            modifier = Modifier.padding(14.dp),
            verticalAlignment = Alignment.CenterVertically
          ) {
            Box(
              modifier = Modifier
                .size(36.dp)
                .clip(RoundedCornerShape(4.dp))
                .background(Color(0xFFEFF6FF)),
              contentAlignment = Alignment.Center
            ) {
              Icon(Icons.Default.Apps, contentDescription = null, tint = ConsoleBluePrimary, modifier = Modifier.size(20.dp))
            }
            Spacer(modifier = Modifier.width(12.dp))
            Column(modifier = Modifier.weight(1f)) {
              Text(
                text = "Audit Installed Device Application",
                style = MaterialTheme.typography.bodyMedium.copy(fontWeight = FontWeight.Bold),
                color = Slate900
              )
              Text(
                text = "Select from applications currently deployed on this Android device",
                style = MaterialTheme.typography.bodySmall.copy(fontSize = 11.sp),
                color = Slate600
              )
            }
            Icon(Icons.AutoMirrored.Filled.ArrowForward, contentDescription = null, tint = Slate600, modifier = Modifier.size(18.dp))
          }
        }
      }

      // ENTERPRISE INVESTIGATION BENCHMARKS (DEMO TARGETS)
      item {
        Row(
          modifier = Modifier.fillMaxWidth(),
          horizontalArrangement = Arrangement.SpaceBetween,
          verticalAlignment = Alignment.CenterVertically
        ) {
          Text(
            text = "VERIFIED THREAT INVESTIGATION TARGETS",
            style = MaterialTheme.typography.labelSmall.copy(
              fontWeight = FontWeight.Bold,
              letterSpacing = 1.sp,
              fontSize = 11.sp
            ),
            color = ConsoleNavy
          )
          Surface(
            color = Color(0xFFF1F5F9),
            shape = RoundedCornerShape(3.dp),
            border = androidx.compose.foundation.BorderStroke(1.dp, ConsoleBorder)
          ) {
            Text(
              text = "DEMO DATA",
              style = MaterialTheme.typography.labelSmall.copy(fontSize = 9.sp, fontWeight = FontWeight.Bold),
              color = Slate600,
              modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp)
            )
          }
        }
      }

      items(SampleApkCatalog.benchmarks) { benchmark ->
        val isCritical = benchmark.expectedRiskScore >= 75
        val isHigh = benchmark.expectedRiskScore in 50..74

        Card(
          modifier = Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(6.dp))
            .border(1.dp, ConsoleBorder, RoundedCornerShape(6.dp))
            .clickable { viewModel.startBenchmarkAnalysis(benchmark) }
            .testTag("upload_benchmark_${benchmark.id}"),
          colors = CardDefaults.cardColors(containerColor = Color.White),
          elevation = CardDefaults.cardElevation(defaultElevation = 0.dp)
        ) {
          Row(
            modifier = Modifier.padding(14.dp),
            verticalAlignment = Alignment.CenterVertically
          ) {
            // Prominent Risk Score Box
            Box(
              modifier = Modifier
                .size(46.dp)
                .clip(RoundedCornerShape(4.dp))
                .background(
                  if (isCritical) SeverityCriticalBg
                  else if (isHigh) SeverityHighBg
                  else Color(0xFFDCFCE7)
                )
                .border(
                  1.dp,
                  if (isCritical) SeverityCriticalBorder
                  else if (isHigh) SeverityHighBorder
                  else Color(0xFF86EFAC),
                  RoundedCornerShape(4.dp)
                ),
              contentAlignment = Alignment.Center
            ) {
              Column(horizontalAlignment = Alignment.CenterHorizontally) {
                Text(
                  text = "${benchmark.expectedRiskScore}",
                  style = MaterialTheme.typography.titleMedium.copy(
                    fontWeight = FontWeight.Black,
                    fontFamily = FontFamily.Monospace
                  ),
                  color = if (isCritical) SeverityCritical else if (isHigh) SeverityHigh else RiskSafeGreen
                )
                Text(
                  text = "EXP RISK",
                  style = MaterialTheme.typography.labelSmall.copy(fontSize = 7.sp, fontWeight = FontWeight.Bold),
                  color = if (isCritical) SeverityCritical else if (isHigh) SeverityHigh else RiskSafeGreen
                )
              }
            }

            Spacer(modifier = Modifier.width(12.dp))

            Column(modifier = Modifier.weight(1f)) {
              Text(
                text = benchmark.name,
                style = MaterialTheme.typography.bodyMedium.copy(fontWeight = FontWeight.Bold),
                color = Slate900
              )
              Text(
                text = benchmark.description,
                style = MaterialTheme.typography.bodySmall.copy(fontSize = 11.sp),
                color = Slate600,
                maxLines = 2
              )
              Spacer(modifier = Modifier.height(4.dp))
              Text(
                text = "${benchmark.filename} • ${benchmark.fileSizeFormatted}",
                style = MaterialTheme.typography.labelSmall.copy(fontFamily = FontFamily.Monospace, fontSize = 10.sp),
                color = Slate600
              )
            }

            Button(
              onClick = { viewModel.startBenchmarkAnalysis(benchmark) },
              colors = ButtonDefaults.buttonColors(containerColor = ConsoleBluePrimary),
              shape = RoundedCornerShape(4.dp),
              modifier = Modifier.height(36.dp)
            ) {
              Text("Audit", fontSize = 11.sp, fontWeight = FontWeight.Bold)
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
      title = { Text("Select Target Application", fontWeight = FontWeight.Bold) },
      text = {
        LazyColumn(
          modifier = Modifier
            .fillMaxWidth()
            .height(350.dp),
          verticalArrangement = Arrangement.spacedBy(6.dp)
        ) {
          items(installedApps) { app ->
            Surface(
              modifier = Modifier
                .fillMaxWidth()
                .clip(RoundedCornerShape(4.dp))
                .border(1.dp, ConsoleBorder, RoundedCornerShape(4.dp))
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
                Text(text = app.appName, fontWeight = FontWeight.Bold, style = MaterialTheme.typography.bodyMedium, color = Slate900)
                Text(text = app.packageName, style = MaterialTheme.typography.bodySmall.copy(fontFamily = FontFamily.Monospace, fontSize = 11.sp), color = Slate600)
              }
            }
          }
        }
      },
      confirmButton = {
        TextButton(onClick = { showInstalledAppsDialog = false }) {
          Text("Cancel", fontWeight = FontWeight.Bold)
        }
      }
    )
  }
}

data class InstalledAppItem(
  val appName: String,
  val packageName: String,
  val apkPath: String
)

fun getDeviceInstalledApps(context: Context): List<InstalledAppItem> {
  return try {
    val pm = context.packageManager
    val packages = pm.getInstalledPackages(0)
    packages.mapNotNull { pkg ->
      val sourceDir = pkg.applicationInfo?.sourceDir
      val name = pkg.applicationInfo?.loadLabel(pm)?.toString() ?: pkg.packageName
      if (sourceDir != null && !pkg.packageName.startsWith("com.android.internal")) {
        InstalledAppItem(appName = name, packageName = pkg.packageName, apkPath = sourceDir)
      } else null
    }.take(30)
  } catch (e: Exception) {
    emptyList()
  }
}
