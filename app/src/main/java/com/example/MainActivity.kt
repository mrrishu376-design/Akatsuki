package com.example

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.BackHandler
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.viewModels
import androidx.compose.animation.Crossfade
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.CloudUpload
import androidx.compose.material.icons.filled.Dashboard
import androidx.compose.material.icons.filled.History
import androidx.compose.material.icons.filled.Person
import androidx.compose.material.icons.filled.Security
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.NavigationBarItemDefaults
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.example.data.analyzer.SampleApkCatalog
import com.example.ui.MainViewModel
import com.example.ui.navigation.Screen
import com.example.ui.screens.AnalysisProgressScreen
import com.example.ui.screens.AnalysisResultsScreen
import com.example.ui.screens.ApkUploadScreen
import com.example.ui.screens.AuthScreen
import com.example.ui.screens.DashboardScreen
import com.example.ui.screens.ForensicReportScreen
import com.example.ui.screens.PermissionsScreen
import com.example.ui.screens.ProfileSettingsScreen
import com.example.ui.screens.ScanHistoryScreen
import com.example.ui.theme.CyberBlueDark
import com.example.ui.theme.CyberBluePrimary
import com.example.ui.theme.MyApplicationTheme
import com.example.ui.theme.Slate600

class MainActivity : ComponentActivity() {
  private val viewModel: MainViewModel by viewModels()

  override fun onCreate(savedInstanceState: Bundle?) {
    super.onCreate(savedInstanceState)
    enableEdgeToEdge()

    setContent {
      MyApplicationTheme {
        MainAppContent(viewModel = viewModel)
      }
    }
  }
}

@Composable
fun MainAppContent(viewModel: MainViewModel) {
  val currentScreen by viewModel.currentScreen.collectAsState()
  val currentUser by viewModel.currentUser.collectAsState()
  val scans by viewModel.allScans.collectAsState()

  // Seed benchmark on first run if database is clean
  LaunchedEffect(scans) {
    if (scans.isEmpty()) {
      SampleApkCatalog.benchmarks.firstOrNull()?.let { benchmark ->
        viewModel.scanRepo.analyzeBenchmark(benchmark, currentUser?.id ?: "usr_secops") { _ -> }
      }
    }
  }

  // Handle system back gesture
  BackHandler(enabled = currentScreen != Screen.DASHBOARD && currentScreen != Screen.AUTH) {
    when (currentScreen) {
      Screen.PERMISSIONS, Screen.REPORT -> viewModel.navigateTo(Screen.RESULTS)
      Screen.RESULTS, Screen.UPLOAD, Screen.HISTORY, Screen.PROFILE -> viewModel.navigateTo(Screen.DASHBOARD)
      Screen.PROGRESS -> viewModel.navigateTo(Screen.UPLOAD)
      else -> viewModel.navigateTo(Screen.DASHBOARD)
    }
  }

  val showBottomBar = currentUser != null && currentScreen in listOf(
    Screen.DASHBOARD,
    Screen.UPLOAD,
    Screen.HISTORY,
    Screen.PROFILE
  )

  Scaffold(
    modifier = Modifier.fillMaxSize(),
    bottomBar = {
      if (showBottomBar) {
        NavigationBar(
          containerColor = MaterialTheme.colorScheme.surface,
          tonalElevation = 6.dp,
          modifier = Modifier.testTag("main_navigation_bar")
        ) {
          NavigationBarItem(
            selected = currentScreen == Screen.DASHBOARD,
            onClick = { viewModel.navigateTo(Screen.DASHBOARD) },
            icon = { Icon(Icons.Default.Dashboard, contentDescription = "Dashboard") },
            label = { Text("Dashboard", fontSize = 11.sp, fontWeight = FontWeight.SemiBold) },
            colors = NavigationBarItemDefaults.colors(
              selectedIconColor = CyberBluePrimary,
              selectedTextColor = CyberBluePrimary,
              indicatorColor = CyberBluePrimary.copy(alpha = 0.15f)
            ),
            modifier = Modifier.testTag("nav_item_dashboard")
          )

          NavigationBarItem(
            selected = currentScreen == Screen.UPLOAD,
            onClick = { viewModel.navigateTo(Screen.UPLOAD) },
            icon = { Icon(Icons.Default.CloudUpload, contentDescription = "Scan APK") },
            label = { Text("Audit APK", fontSize = 11.sp, fontWeight = FontWeight.SemiBold) },
            colors = NavigationBarItemDefaults.colors(
              selectedIconColor = CyberBluePrimary,
              selectedTextColor = CyberBluePrimary,
              indicatorColor = CyberBluePrimary.copy(alpha = 0.15f)
            ),
            modifier = Modifier.testTag("nav_item_upload")
          )

          NavigationBarItem(
            selected = currentScreen == Screen.HISTORY,
            onClick = { viewModel.navigateTo(Screen.HISTORY) },
            icon = { Icon(Icons.Default.History, contentDescription = "History") },
            label = { Text("History", fontSize = 11.sp, fontWeight = FontWeight.SemiBold) },
            colors = NavigationBarItemDefaults.colors(
              selectedIconColor = CyberBluePrimary,
              selectedTextColor = CyberBluePrimary,
              indicatorColor = CyberBluePrimary.copy(alpha = 0.15f)
            ),
            modifier = Modifier.testTag("nav_item_history")
          )

          NavigationBarItem(
            selected = currentScreen == Screen.PROFILE,
            onClick = { viewModel.navigateTo(Screen.PROFILE) },
            icon = { Icon(Icons.Default.Person, contentDescription = "Auditor") },
            label = { Text("Settings", fontSize = 11.sp, fontWeight = FontWeight.SemiBold) },
            colors = NavigationBarItemDefaults.colors(
              selectedIconColor = CyberBluePrimary,
              selectedTextColor = CyberBluePrimary,
              indicatorColor = CyberBluePrimary.copy(alpha = 0.15f)
            ),
            modifier = Modifier.testTag("nav_item_profile")
          )
        }
      }
    }
  ) { innerPadding ->
    Box(
      modifier = Modifier
        .fillMaxSize()
        .padding(bottom = if (showBottomBar) innerPadding.calculateBottomPadding() else 0.dp)
    ) {
      Crossfade(targetState = currentScreen, label = "screenTransition") { targetScreen ->
        when (targetScreen) {
          Screen.AUTH -> AuthScreen(viewModel = viewModel)
          Screen.DASHBOARD -> DashboardScreen(viewModel = viewModel)
          Screen.UPLOAD -> ApkUploadScreen(viewModel = viewModel)
          Screen.PROGRESS -> AnalysisProgressScreen(viewModel = viewModel)
          Screen.RESULTS -> AnalysisResultsScreen(viewModel = viewModel)
          Screen.PERMISSIONS -> PermissionsScreen(viewModel = viewModel)
          Screen.REPORT -> ForensicReportScreen(viewModel = viewModel)
          Screen.HISTORY -> ScanHistoryScreen(viewModel = viewModel)
          Screen.PROFILE -> ProfileSettingsScreen(viewModel = viewModel)
        }
      }
    }
  }
}
