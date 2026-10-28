package com.example

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.BackHandler
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.viewModels
import androidx.compose.animation.Crossfade
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.AccountCircle
import androidx.compose.material.icons.filled.CloudUpload
import androidx.compose.material.icons.filled.Dashboard
import androidx.compose.material.icons.filled.Description
import androidx.compose.material.icons.filled.History
import androidx.compose.material.icons.filled.Policy
import androidx.compose.material.icons.filled.Public
import androidx.compose.material.icons.filled.Security
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material.icons.filled.UploadFile
import androidx.compose.material3.DrawerValue
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalDrawerSheet
import androidx.compose.material3.ModalNavigationDrawer
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.NavigationBarItemDefaults
import androidx.compose.material3.NavigationDrawerItem
import androidx.compose.material3.NavigationDrawerItemDefaults
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.rememberDrawerState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.compositionLocalOf
import androidx.compose.runtime.getValue
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontFamily
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
import com.example.ui.theme.ConsoleBluePrimary
import com.example.ui.theme.ConsoleNavy
import com.example.ui.theme.ConsoleNavyBorder
import com.example.ui.theme.ConsoleNavySurface
import com.example.ui.theme.MyApplicationTheme
import com.example.ui.theme.RiskSafeGreen
import com.example.ui.theme.Slate600
import kotlinx.coroutines.launch

val LocalNavigationDrawerToggle = compositionLocalOf<() -> Unit> { {} }

class MainActivity : ComponentActivity() {
  private val viewModel: MainViewModel by viewModels()

  override fun onCreate(savedInstanceState: Bundle?) {
    super.onCreate(savedInstanceState)
    enableEdgeToEdge()

    setContent {
      MyApplicationTheme {
        EnterpriseConsoleApp(viewModel = viewModel)
      }
    }
  }
}

@Composable
fun EnterpriseConsoleApp(viewModel: MainViewModel) {
  val currentScreen by viewModel.currentScreen.collectAsState()
  val currentUser by viewModel.currentUser.collectAsState()
  val scans by viewModel.allScans.collectAsState()

  val drawerState = rememberDrawerState(initialValue = DrawerValue.Closed)
  val scope = rememberCoroutineScope()

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

  val showConsoleChrome = currentUser != null && currentScreen != Screen.AUTH

  ModalNavigationDrawer(
    drawerState = drawerState,
    gesturesEnabled = showConsoleChrome,
    drawerContent = {
      if (showConsoleChrome) {
        NavyConsoleSidebar(
          currentScreen = currentScreen,
          currentUserEmail = currentUser?.email ?: "analyst@cyberdefense.org",
          currentUserName = currentUser?.fullName ?: "Alex Mercer",
          currentUserRole = currentUser?.role ?: "Senior Forensic Auditor",
          onSelectScreen = { screen ->
            viewModel.navigateTo(screen)
            scope.launch { drawerState.close() }
          }
        )
      }
    }
  ) {
    CompositionLocalProvider(
      LocalNavigationDrawerToggle provides {
        scope.launch {
          if (drawerState.isClosed) drawerState.open() else drawerState.close()
        }
      }
    ) {
      Scaffold(
        modifier = Modifier.fillMaxSize(),
        bottomBar = {
          if (showConsoleChrome && currentScreen in listOf(Screen.DASHBOARD, Screen.UPLOAD, Screen.HISTORY, Screen.PROFILE)) {
            EnterpriseConsoleBottomBar(
              currentScreen = currentScreen,
              onNavigate = { viewModel.navigateTo(it) }
            )
          }
        }
      ) { innerPadding ->
        Box(
          modifier = Modifier
            .fillMaxSize()
            .background(Color.White)
            .padding(bottom = if (showConsoleChrome && currentScreen in listOf(Screen.DASHBOARD, Screen.UPLOAD, Screen.HISTORY, Screen.PROFILE)) innerPadding.calculateBottomPadding() else 0.dp)
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
  }
}

/**
 * Enterprise Navy-Blue Console Sidebar
 */
@Composable
fun NavyConsoleSidebar(
  currentScreen: Screen,
  currentUserEmail: String,
  currentUserName: String,
  currentUserRole: String,
  onSelectScreen: (Screen) -> Unit
) {
  ModalDrawerSheet(
    modifier = Modifier.width(300.dp),
    drawerContainerColor = ConsoleNavy,
    drawerContentColor = Color.White
  ) {
    Column(
      modifier = Modifier
        .fillMaxHeight()
        .padding(16.dp),
      verticalArrangement = Arrangement.SpaceBetween
    ) {
      Column {
        Spacer(modifier = Modifier.height(24.dp))

        // Console Brand Header
        Row(verticalAlignment = Alignment.CenterVertically) {
          Box(
            modifier = Modifier
              .size(38.dp)
              .clip(RoundedCornerShape(8.dp))
              .background(ConsoleBluePrimary),
            contentAlignment = Alignment.Center
          ) {
            Icon(
              imageVector = Icons.Default.Shield,
              contentDescription = "PS-02 Security",
              tint = Color.White,
              modifier = Modifier.size(22.dp)
            )
          }
          Spacer(modifier = Modifier.width(12.dp))
          Column {
            Text(
              text = "PS-02 CONSOLE",
              style = MaterialTheme.typography.titleMedium.copy(
                fontWeight = FontWeight.Black,
                letterSpacing = 1.sp
              ),
              color = Color.White
            )
            Text(
              text = "Android Forensic Platform",
              style = MaterialTheme.typography.labelSmall,
              color = Color(0xFF94A3B8)
            )
          }
        }

        Spacer(modifier = Modifier.height(24.dp))
        HorizontalDivider(color = ConsoleNavyBorder)
        Spacer(modifier = Modifier.height(16.dp))

        Text(
          text = "INVESTIGATION TOOLS",
          style = MaterialTheme.typography.labelSmall.copy(
            fontWeight = FontWeight.Bold,
            letterSpacing = 1.2.sp,
            fontSize = 10.sp
          ),
          color = Color(0xFF64748B),
          modifier = Modifier.padding(horizontal = 12.dp, vertical = 6.dp)
        )

        // Navigation Items
        SidebarNavItem(
          label = "Security Dashboard",
          icon = Icons.Default.Dashboard,
          selected = currentScreen == Screen.DASHBOARD,
          onClick = { onSelectScreen(Screen.DASHBOARD) }
        )

        SidebarNavItem(
          label = "APK Investigation",
          icon = Icons.Default.UploadFile,
          selected = currentScreen == Screen.UPLOAD || currentScreen == Screen.PROGRESS,
          isHighlight = true,
          onClick = { onSelectScreen(Screen.UPLOAD) }
        )

        SidebarNavItem(
          label = "Analysis Results",
          icon = Icons.Default.Security,
          selected = currentScreen == Screen.RESULTS,
          onClick = { onSelectScreen(Screen.RESULTS) }
        )

        SidebarNavItem(
          label = "Permission Matrix",
          icon = Icons.Default.Policy,
          selected = currentScreen == Screen.PERMISSIONS,
          onClick = { onSelectScreen(Screen.PERMISSIONS) }
        )

        SidebarNavItem(
          label = "Forensic Dossier",
          icon = Icons.Default.Description,
          selected = currentScreen == Screen.REPORT,
          onClick = { onSelectScreen(Screen.REPORT) }
        )

        SidebarNavItem(
          label = "Investigation History",
          icon = Icons.Default.History,
          selected = currentScreen == Screen.HISTORY,
          onClick = { onSelectScreen(Screen.HISTORY) }
        )

        SidebarNavItem(
          label = "System & RLS Database",
          icon = Icons.Default.Settings,
          selected = currentScreen == Screen.PROFILE,
          onClick = { onSelectScreen(Screen.PROFILE) }
        )
      }

      // Sidebar Footer (Auditor Profile Status)
      Column {
        HorizontalDivider(color = ConsoleNavyBorder)
        Spacer(modifier = Modifier.height(14.dp))

        Row(
          modifier = Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(8.dp))
            .background(ConsoleNavySurface)
            .clickable { onSelectScreen(Screen.PROFILE) }
            .padding(10.dp),
          verticalAlignment = Alignment.CenterVertically
        ) {
          Box(
            modifier = Modifier
              .size(36.dp)
              .clip(CircleShape)
              .background(ConsoleBluePrimary),
            contentAlignment = Alignment.Center
          ) {
            Icon(Icons.Default.AccountCircle, contentDescription = null, tint = Color.White)
          }

          Spacer(modifier = Modifier.width(10.dp))

          Column(modifier = Modifier.weight(1f)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
              Text(
                text = currentUserName,
                style = MaterialTheme.typography.bodyMedium.copy(fontWeight = FontWeight.Bold),
                color = Color.White,
                maxLines = 1
              )
              Spacer(modifier = Modifier.width(6.dp))
              Box(modifier = Modifier.size(6.dp).clip(CircleShape).background(RiskSafeGreen))
            }
            Text(
              text = currentUserRole,
              style = MaterialTheme.typography.labelSmall.copy(fontSize = 10.sp),
              color = Color(0xFF94A3B8),
              maxLines = 1
            )
          }
        }
        Spacer(modifier = Modifier.height(12.dp))
      }
    }
  }
}

@Composable
fun SidebarNavItem(
  label: String,
  icon: ImageVector,
  selected: Boolean,
  isHighlight: Boolean = false,
  onClick: () -> Unit
) {
  val bgColor = when {
    selected -> ConsoleBluePrimary
    isHighlight -> Color(0xFF1E3A5F)
    else -> Color.Transparent
  }

  Surface(
    modifier = Modifier
      .fillMaxWidth()
      .padding(vertical = 3.dp)
      .clip(RoundedCornerShape(6.dp))
      .clickable(onClick = onClick)
      .testTag("sidebar_nav_${label.replace(" ", "_")}"),
    color = bgColor
  ) {
    Row(
      modifier = Modifier.padding(horizontal = 12.dp, vertical = 10.dp),
      verticalAlignment = Alignment.CenterVertically
    ) {
      Icon(
        imageVector = icon,
        contentDescription = label,
        tint = if (selected || isHighlight) Color.White else Color(0xFF94A3B8),
        modifier = Modifier.size(18.dp)
      )
      Spacer(modifier = Modifier.width(12.dp))
      Text(
        text = label,
        style = MaterialTheme.typography.bodyMedium.copy(
          fontWeight = if (selected) FontWeight.Bold else FontWeight.Medium,
          fontSize = 13.sp
        ),
        color = if (selected || isHighlight) Color.White else Color(0xFFE2E8F0)
      )
    }
  }
}

/**
 * Clean Enterprise Console Bottom Navigation Bar
 */
@Composable
fun EnterpriseConsoleBottomBar(
  currentScreen: Screen,
  onNavigate: (Screen) -> Unit
) {
  NavigationBar(
    containerColor = ConsoleNavy,
    tonalElevation = 0.dp,
    modifier = Modifier
      .border(1.dp, ConsoleNavyBorder)
      .testTag("enterprise_bottom_navigation")
  ) {
    NavigationBarItem(
      selected = currentScreen == Screen.DASHBOARD,
      onClick = { onNavigate(Screen.DASHBOARD) },
      icon = { Icon(Icons.Default.Dashboard, contentDescription = "Dashboard") },
      label = { Text("Dashboard", fontSize = 10.sp, fontWeight = FontWeight.Bold) },
      colors = NavigationBarItemDefaults.colors(
        selectedIconColor = Color.White,
        selectedTextColor = Color.White,
        indicatorColor = ConsoleBluePrimary,
        unselectedIconColor = Color(0xFF94A3B8),
        unselectedTextColor = Color(0xFF94A3B8)
      ),
      modifier = Modifier.testTag("nav_bottom_dashboard")
    )

    NavigationBarItem(
      selected = currentScreen == Screen.UPLOAD || currentScreen == Screen.PROGRESS,
      onClick = { onNavigate(Screen.UPLOAD) },
      icon = { Icon(Icons.Default.UploadFile, contentDescription = "Investigate APK") },
      label = { Text("Audit APK", fontSize = 10.sp, fontWeight = FontWeight.Bold) },
      colors = NavigationBarItemDefaults.colors(
        selectedIconColor = Color.White,
        selectedTextColor = Color.White,
        indicatorColor = ConsoleBluePrimary,
        unselectedIconColor = Color(0xFF94A3B8),
        unselectedTextColor = Color(0xFF94A3B8)
      ),
      modifier = Modifier.testTag("nav_bottom_upload")
    )

    NavigationBarItem(
      selected = currentScreen == Screen.HISTORY,
      onClick = { onNavigate(Screen.HISTORY) },
      icon = { Icon(Icons.Default.History, contentDescription = "History") },
      label = { Text("History", fontSize = 10.sp, fontWeight = FontWeight.Bold) },
      colors = NavigationBarItemDefaults.colors(
        selectedIconColor = Color.White,
        selectedTextColor = Color.White,
        indicatorColor = ConsoleBluePrimary,
        unselectedIconColor = Color(0xFF94A3B8),
        unselectedTextColor = Color(0xFF94A3B8)
      ),
      modifier = Modifier.testTag("nav_bottom_history")
    )

    NavigationBarItem(
      selected = currentScreen == Screen.PROFILE,
      onClick = { onNavigate(Screen.PROFILE) },
      icon = { Icon(Icons.Default.Settings, contentDescription = "Settings") },
      label = { Text("Settings", fontSize = 10.sp, fontWeight = FontWeight.Bold) },
      colors = NavigationBarItemDefaults.colors(
        selectedIconColor = Color.White,
        selectedTextColor = Color.White,
        indicatorColor = ConsoleBluePrimary,
        unselectedIconColor = Color(0xFF94A3B8),
        unselectedTextColor = Color(0xFF94A3B8)
      ),
      modifier = Modifier.testTag("nav_bottom_profile")
    )
  }
}
