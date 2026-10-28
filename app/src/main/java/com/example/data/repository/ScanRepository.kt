package com.example.data.repository

import android.content.Context
import android.net.Uri
import com.example.data.analyzer.AnalysisProgressState
import com.example.data.analyzer.ApkStaticAnalyzer
import com.example.data.analyzer.FullScanResult
import com.example.data.analyzer.SampleApkBenchmark
import com.example.data.analyzer.SampleApkCatalog
import com.example.data.local.AppDatabase
import com.example.data.model.ForensicReport
import com.example.data.model.ScanFinding
import com.example.data.model.ScanRecord
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

class ScanRepository(private val context: Context) {
  private val db = AppDatabase.getDatabase(context)
  private val scanDao = db.scanDao()
  private val findingDao = db.findingDao()
  private val reportDao = db.reportDao()
  private val analyzer = ApkStaticAnalyzer(context)

  val allScans: Flow<List<ScanRecord>> = scanDao.getAllScans()

  private val _currentActiveResult = MutableStateFlow<FullScanResult?>(null)
  val currentActiveResult: StateFlow<FullScanResult?> = _currentActiveResult.asStateFlow()

  suspend fun getScanById(scanId: String): ScanRecord? = scanDao.getScanById(scanId)

  fun getFindingsForScan(scanId: String): Flow<List<ScanFinding>> = findingDao.getFindingsForScan(scanId)

  suspend fun getFindingsListForScan(scanId: String): List<ScanFinding> = findingDao.getFindingsListForScan(scanId)

  suspend fun getReportByScanId(scanId: String): ForensicReport? = reportDao.getReportByScanId(scanId)

  suspend fun deleteScan(scanId: String) {
    scanDao.deleteScanById(scanId)
    findingDao.deleteFindingsForScan(scanId)
    if (_currentActiveResult.value?.scan?.id == scanId) {
      _currentActiveResult.value = null
    }
  }

  suspend fun analyzeRealApk(
    uri: Uri,
    filename: String,
    ownerId: String,
    onProgress: (AnalysisProgressState) -> Unit
  ): FullScanResult {
    val result = analyzer.analyzeApkUri(uri, filename, ownerId, onProgress)
    saveFullResult(result)
    _currentActiveResult.value = result
    return result
  }

  suspend fun analyzeBenchmark(
    benchmark: SampleApkBenchmark,
    ownerId: String,
    onProgress: (AnalysisProgressState) -> Unit
  ): FullScanResult {
    onProgress(AnalysisProgressState(0, "Stage 1/5: Loading Benchmark Artifact", 0.20f, "Simulating secure byte ingest for ${benchmark.name}..."))
    delay(400)
    onProgress(AnalysisProgressState(1, "Stage 2/5: Manifest & Package Analysis", 0.40f, "Parsing AndroidManifest.xml bytecode..."))
    delay(400)
    onProgress(AnalysisProgressState(2, "Stage 3/5: Permission Threat Profiling", 0.65f, "Evaluating dangerous permissions vs least-privilege baseline..."))
    delay(400)
    onProgress(AnalysisProgressState(3, "Stage 4/5: Component Exposure Audit", 0.85f, "Inspecting exported IPC endpoints, intents & services..."))
    delay(400)
    onProgress(AnalysisProgressState(4, "Stage 5/5: Risk Engine & Forensic Compilation", 1.0f, "Generating cryptographic hashes & forensic dossier..."))
    delay(300)

    val result = SampleApkCatalog.generateBenchmarkResult(benchmark, ownerId)
    saveFullResult(result)
    _currentActiveResult.value = result
    return result
  }

  fun setActiveResult(result: FullScanResult) {
    _currentActiveResult.value = result
  }

  private suspend fun saveFullResult(result: FullScanResult) {
    scanDao.insertScan(result.scan)
    findingDao.insertFindings(result.findings)
    reportDao.insertReport(result.report)
  }
}
