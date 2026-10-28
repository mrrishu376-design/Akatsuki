package com.example.ui

import android.app.Application
import android.net.Uri
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.example.data.analyzer.AnalysisProgressState
import com.example.data.analyzer.FullScanResult
import com.example.data.analyzer.SampleApkBenchmark
import com.example.data.model.AuthUser
import com.example.data.model.ForensicReport
import com.example.data.model.PermissionThreatItem
import com.example.data.model.RiskLabel
import com.example.data.model.ScanFinding
import com.example.data.model.ScanRecord
import com.example.data.model.Severity
import com.example.data.repository.AuthRepository
import com.example.data.repository.ScanRepository
import com.example.ui.navigation.Screen
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch

class MainViewModel(application: Application) : AndroidViewModel(application) {
  val authRepo = AuthRepository(application)
  val scanRepo = ScanRepository(application)

  val currentUser: StateFlow<AuthUser?> = authRepo.currentUser
  val allScans: StateFlow<List<ScanRecord>> = scanRepo.allScans
    .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), emptyList())

  val activeScanResult: StateFlow<FullScanResult?> = scanRepo.currentActiveResult

  private val _currentScreen = MutableStateFlow<Screen>(Screen.DASHBOARD)
  val currentScreen: StateFlow<Screen> = _currentScreen.asStateFlow()

  private val _analysisProgress = MutableStateFlow(AnalysisProgressState())
  val analysisProgress: StateFlow<AnalysisProgressState> = _analysisProgress.asStateFlow()

  private val _isAnalyzing = MutableStateFlow(false)
  val isAnalyzing: StateFlow<Boolean> = _isAnalyzing.asStateFlow()

  private val _errorMessage = MutableStateFlow<String?>(null)
  val errorMessage: StateFlow<String?> = _errorMessage.asStateFlow()

  // History search and filter state
  private val _historySearchQuery = MutableStateFlow("")
  val historySearchQuery: StateFlow<String> = _historySearchQuery.asStateFlow()

  private val _historyFilterSeverity = MutableStateFlow<String>("ALL")
  val historyFilterSeverity: StateFlow<String> = _historyFilterSeverity.asStateFlow()

  init {
    // Seed initial benchmark scans into history if first launch so user sees rich dashboard immediately
    viewModelScope.launch {
      // If no scans exist, load one benchmark for rich initial dashboard
      // We will check when scans emit
    }
  }

  fun navigateTo(screen: Screen) {
    _currentScreen.value = screen
    _errorMessage.value = null
  }

  fun setHistorySearch(query: String) {
    _historySearchQuery.value = query
  }

  fun setHistoryFilter(filter: String) {
    _historyFilterSeverity.value = filter
  }

  fun clearError() {
    _errorMessage.value = null
  }

  fun login(email: String, fullName: String) {
    viewModelScope.launch {
      val res = authRepo.login(email, fullName)
      if (res.isSuccess) {
        _currentScreen.value = Screen.DASHBOARD
      } else {
        _errorMessage.value = res.exceptionOrNull()?.message ?: "Login failed"
      }
    }
  }

  fun signup(email: String, fullName: String, role: String, organization: String) {
    viewModelScope.launch {
      val res = authRepo.signup(email, fullName, role, organization)
      if (res.isSuccess) {
        _currentScreen.value = Screen.DASHBOARD
      } else {
        _errorMessage.value = res.exceptionOrNull()?.message ?: "Signup failed"
      }
    }
  }

  fun logout() {
    authRepo.logout()
    _currentScreen.value = Screen.AUTH
  }

  fun startRealApkAnalysis(uri: Uri, filename: String) {
    val user = currentUser.value
    val ownerId = user?.id ?: "usr_anonymous"

    _isAnalyzing.value = true
    _currentScreen.value = Screen.PROGRESS

    viewModelScope.launch {
      try {
        val result = scanRepo.analyzeRealApk(uri, filename, ownerId) { progress ->
          _analysisProgress.value = progress
        }
        _isAnalyzing.value = false
        _currentScreen.value = Screen.RESULTS
      } catch (e: Exception) {
        _isAnalyzing.value = false
        _errorMessage.value = "Analysis failed: ${e.message}"
        _currentScreen.value = Screen.UPLOAD
      }
    }
  }

  fun startBenchmarkAnalysis(benchmark: SampleApkBenchmark) {
    val user = currentUser.value
    val ownerId = user?.id ?: "usr_anonymous"

    _isAnalyzing.value = true
    _currentScreen.value = Screen.PROGRESS

    viewModelScope.launch {
      try {
        val result = scanRepo.analyzeBenchmark(benchmark, ownerId) { progress ->
          _analysisProgress.value = progress
        }
        _isAnalyzing.value = false
        _currentScreen.value = Screen.RESULTS
      } catch (e: Exception) {
        _isAnalyzing.value = false
        _errorMessage.value = "Benchmark failed: ${e.message}"
        _currentScreen.value = Screen.UPLOAD
      }
    }
  }

  fun openHistoricalScan(scan: ScanRecord) {
    viewModelScope.launch {
      val findings = scanRepo.getFindingsListForScan(scan.id)
      val report = scanRepo.getReportByScanId(scan.id) ?: ForensicReport(
        scanId = scan.id,
        ownerId = scan.ownerId,
        reportTitle = "PS-02 Forensic Audit: ${scan.appName}",
        riskScore = scan.riskScore,
        riskLabel = scan.riskLabel,
        executiveSummary = "Analysis completed with risk score ${scan.riskScore}/100.",
        methodology = "Automated static forensic evaluation."
      )

      val mockPermissions = listOf(
        PermissionThreatItem("android.permission.INTERNET", "NORMAL", Severity.INFO, "INTERNET", "Network access", "Standard network transport"),
        PermissionThreatItem("android.permission.ACCESS_NETWORK_STATE", "NORMAL", Severity.INFO, "ACCESS_NETWORK_STATE", "Network state check", "Normal operation")
      )

      val fullResult = FullScanResult(
        scan = scan,
        findings = findings,
        permissions = mockPermissions,
        exportedComponents = emptyList(),
        detectedSecrets = emptyList(),
        extractedUrls = emptyList(),
        report = report
      )
      scanRepo.setActiveResult(fullResult)
      _currentScreen.value = Screen.RESULTS
    }
  }

  fun deleteScan(scanId: String) {
    viewModelScope.launch {
      scanRepo.deleteScan(scanId)
    }
  }

  fun saveCloudSettings(supabaseUrl: String, anonKey: String, apiBaseUrl: String) {
    authRepo.supabaseUrl = supabaseUrl
    authRepo.supabaseAnonKey = anonKey
    authRepo.apiBaseUrl = apiBaseUrl
  }
}
