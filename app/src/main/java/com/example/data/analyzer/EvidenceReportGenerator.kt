package com.example.data.analyzer

import android.content.Context
import android.graphics.Canvas
import android.graphics.Color
import android.graphics.Paint
import android.graphics.Rect
import android.graphics.RectF
import android.graphics.Typeface
import android.graphics.pdf.PdfDocument
import android.net.Uri
import androidx.core.content.FileProvider
import com.example.data.local.AppDatabase
import com.example.data.model.ForensicReport
import com.example.data.model.RiskLabel
import com.example.data.model.ScanFinding
import com.example.data.model.ScanRecord
import com.example.data.model.Severity
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File
import java.io.FileOutputStream
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * Compiles Room database forensic analysis results into a structured, publication-grade
 * PDF document for cybersecurity and legal documentation.
 */
class EvidenceReportGenerator(
  private val context: Context,
  private val database: AppDatabase = AppDatabase.getDatabase(context)
) {

  companion object {
    // Standard A4 dimensions in points (72 points per inch)
    const val PAGE_WIDTH = 595
    const val PAGE_HEIGHT = 842

    const val MARGIN_LEFT = 40f
    const val MARGIN_RIGHT = 40f
    const val CONTENT_WIDTH = PAGE_WIDTH - MARGIN_LEFT - MARGIN_RIGHT
    const val MAX_CONTENT_Y = 790f
    const val HEADER_TOP_Y = 40f
    const val FOOTER_Y = 815f

    // Theme Colors
    val COLOR_NAVY = Color.rgb(10, 25, 47)         // #0A192F
    val COLOR_NAVY_LIGHT = Color.rgb(17, 34, 64)    // #112240
    val COLOR_CYAN = Color.rgb(2, 132, 199)        // #0284C7
    val COLOR_SLATE_DARK = Color.rgb(15, 23, 42)    // #0F172A
    val COLOR_SLATE_TEXT = Color.rgb(71, 85, 105)   // #475569
    val COLOR_LIGHT_BG = Color.rgb(248, 250, 252)   // #F8FAFC
    val COLOR_BORDER = Color.rgb(226, 232, 240)     // #E2E8F0
    val COLOR_WHITE = Color.WHITE

    val COLOR_CRITICAL = Color.rgb(220, 38, 38)     // #DC2626
    val COLOR_CRITICAL_BG = Color.rgb(254, 226, 226)// #FEE2E2
    val COLOR_HIGH = Color.rgb(234, 88, 12)         // #EA580C
    val COLOR_HIGH_BG = Color.rgb(255, 237, 213)    // #FFEDD5
    val COLOR_MEDIUM = Color.rgb(217, 119, 6)       // #D97706
    val COLOR_MEDIUM_BG = Color.rgb(254, 243, 199)  // #FEF3C7
    val COLOR_LOW = Color.rgb(5, 150, 105)          // #059669
    val COLOR_LOW_BG = Color.rgb(209, 250, 229)     // #D1FAE5
    val COLOR_SAFE = Color.rgb(16, 185, 129)        // #10B981
  }

  /**
   * Compiles the analysis result for [scanId] from the Room database into a PDF document.
   */
  suspend fun generatePdf(scanId: String, customOutputFile: File? = null): File = withContext(Dispatchers.IO) {
    val scan = database.scanDao().getScanById(scanId)
      ?: throw IllegalArgumentException("No scan record found in Room database for scanId: $scanId")
    val findings = database.findingDao().getFindingsListForScan(scanId)
    val report = database.reportDao().getReportByScanId(scanId)
      ?: ForensicReport(
        scanId = scan.id,
        ownerId = scan.ownerId,
        reportTitle = "PS-02 Security Audit: ${scan.appName}",
        riskScore = scan.riskScore,
        riskLabel = scan.riskLabel,
        executiveSummary = "Analysis completed with risk score ${scan.riskScore}/100.",
        methodology = "Automated static forensic evaluation."
      )

    compilePdf(scan, findings, report, customOutputFile)
  }

  /**
   * Generates a structured PDF document from in-memory or persisted security objects.
   * Leverages Android native graphics PDF renderer, with resilient fallback to ISO PDF 1.4 stream writer.
   */
  fun compilePdf(
    scan: ScanRecord,
    findings: List<ScanFinding>,
    report: ForensicReport,
    customOutputFile: File? = null
  ): File {
    val reportsDir = File(context.cacheDir, "reports").apply { mkdirs() }
    val sanitizedApp = scan.appName.replace(Regex("[^a-zA-Z0-9_-]"), "_")
    val outputFile = customOutputFile ?: File(reportsDir, "PS02_Forensic_Report_${sanitizedApp}_${scan.id.take(8)}.pdf")

    return try {
      compileWithAndroidPdfDocument(scan, findings, report, outputFile)
    } catch (_: Exception) {
      compileStructuredPdfStream(scan, findings, report, outputFile)
    }
  }

  private fun compileWithAndroidPdfDocument(
    scan: ScanRecord,
    findings: List<ScanFinding>,
    report: ForensicReport,
    outputFile: File
  ): File {
    val pdfDocument = PdfDocument()
    try {
      val dateFormat = SimpleDateFormat("yyyy-MM-dd HH:mm:ss 'UTC'", Locale.US)
      val formattedDate = dateFormat.format(Date(report.generatedAt))

      val renderer = PdfPageRenderer(pdfDocument, scan, report, formattedDate)

      renderer.startNewPage()
      renderer.drawExecutiveCover(scan, report, findings)

      renderer.startNewPage()
      renderer.drawTechnicalFindings(findings)

      renderer.drawMethodologyAndAttestation(report)
      renderer.finishCurrentPage()

      FileOutputStream(outputFile).use { out ->
        pdfDocument.writeTo(out)
      }
      return outputFile
    } finally {
      runCatching { pdfDocument.close() }
    }
  }

  private fun compileStructuredPdfStream(
    scan: ScanRecord,
    findings: List<ScanFinding>,
    report: ForensicReport,
    outputFile: File
  ): File {
    val dateFormat = SimpleDateFormat("yyyy-MM-dd HH:mm:ss 'UTC'", Locale.US)
    val formattedDate = dateFormat.format(Date(report.generatedAt))

    val pages = mutableListOf<List<String>>()

    // Page 1: Executive Dossier
    val page1 = mutableListOf<String>()
    page1.add("PS-02 ANDROID APPLICATION FORENSIC & SECURITY AUDIT REPORT")
    page1.add("Static Vulnerability, Permission Threat, and Evidence Audit")
    page1.add("================================================================================")
    page1.add("REPORT METADATA:")
    page1.add("  Report ID     : ${report.id}")
    page1.add("  Scan ID       : ${scan.id}")
    page1.add("  Auditor       : ${report.analystName}")
    page1.add("  Tool Version  : ${report.toolVersion}")
    page1.add("  Generated At  : $formattedDate")
    page1.add("  Audit Status  : ${scan.status.name}")
    page1.add("--------------------------------------------------------------------------------")
    page1.add("TARGET PROVENANCE & CRYPTOGRAPHIC INTEGRITY:")
    page1.add("  Application   : ${scan.appName}")
    page1.add("  Package Name  : ${scan.packageName}")
    page1.add("  Version       : ${scan.versionName} (Build ${scan.versionCode})")
    page1.add("  Target SDK    : API ${scan.targetSdk} (Min: ${scan.minSdk})")
    page1.add("  Original File : ${scan.originalFilename} (${scan.fileSizeBytes} bytes)")
    page1.add("  SHA-256 Digest: ${scan.sha256Hash}")
    page1.add("  MD5 Digest    : ${scan.md5Hash.ifEmpty { "N/A" }}")
    page1.add("--------------------------------------------------------------------------------")
    page1.add("COMPOSITE RISK EVALUATION:")
    page1.add("  OVERALL SCORE : ${scan.riskScore} / 100 [${scan.riskLabel.name}]")
    page1.add("  FINDINGS      : Critical: ${scan.criticalCount} | High: ${scan.highCount} | Medium: ${scan.mediumCount} | Low: ${scan.lowCount}")
    page1.add("--------------------------------------------------------------------------------")
    page1.add("EXECUTIVE SUMMARY:")
    page1.add(report.executiveSummary)
    pages.add(page1)

    // Page 2: Findings & Legal Disclaimer
    val page2 = mutableListOf<String>()
    page2.add("TECHNICAL SECURITY FINDINGS & EVIDENCE (${findings.size})")
    page2.add("================================================================================")
    findings.forEachIndexed { i, f ->
      page2.add("[#${i + 1}] [${f.severity.label}] ${f.ruleId} - ${f.title} (${f.cweId})")
      page2.add("    Description   : ${f.description}")
      if (f.evidence.isNotBlank()) {
        page2.add("    Evidence      : ${f.evidence}")
      }
      page2.add("    Remediation   : ${f.recommendation}")
      page2.add("")
    }
    page2.add("--------------------------------------------------------------------------------")
    page2.add("METHODOLOGY & STANDARDS:")
    page2.add(report.methodology)
    page2.add("--------------------------------------------------------------------------------")
    page2.add("LEGAL DISCLAIMER & ANALYSIS LIMITATIONS:")
    page2.add(report.limitationsDisclaimer)
    pages.add(page2)

    writeStandardPdf(pages, outputFile)
    return outputFile
  }

  private fun writeStandardPdf(pages: List<List<String>>, outputFile: File) {
    val bos = java.io.ByteArrayOutputStream()
    val offsets = mutableListOf<Long>()

    fun writeString(s: String) {
      bos.write(s.toByteArray(Charsets.ISO_8859_1))
    }

    writeString("%PDF-1.4\n%\u00E2\u00E3\u00CF\u00D3\n")

    val numPages = pages.size
    val fontObjIndex = 3 + (numPages * 2)

    // Catalog
    offsets.add(bos.size().toLong())
    writeString("1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n")

    // Pages collection
    offsets.add(bos.size().toLong())
    val kids = (0 until numPages).joinToString(" ") { "${3 + (it * 2)} 0 R" }
    writeString("2 0 obj\n<< /Type /Pages /Kids [$kids] /Count $numPages >>\nendobj\n")

    // Page and Content Stream objects
    for (i in 0 until numPages) {
      val pageObjNum = 3 + (i * 2)
      val contentObjNum = pageObjNum + 1

      offsets.add(bos.size().toLong())
      writeString("$pageObjNum 0 obj\n")
      writeString("<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Contents $contentObjNum 0 R ")
      writeString("/Resources << /Font << /F1 $fontObjIndex 0 R >> >> >>\nendobj\n")

      val contentStream = StringBuilder()
      contentStream.append("BT\n/F1 8.5 Tf\n12 TL\n40 800 Td\n")
      for (line in pages[i]) {
        val sanitized = line.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")
        contentStream.append("($sanitized) '\n")
      }
      contentStream.append("ET\n")
      val streamBytes = contentStream.toString().toByteArray(Charsets.ISO_8859_1)

      offsets.add(bos.size().toLong())
      writeString("$contentObjNum 0 obj\n<< /Length ${streamBytes.size} >>\nstream\n")
      bos.write(streamBytes)
      writeString("\nendstream\nendobj\n")
    }

    // Type1 Helvetica Font
    offsets.add(bos.size().toLong())
    writeString("$fontObjIndex 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>\nendobj\n")

    // Cross-Reference Table
    val startXref = bos.size().toLong()
    val totalObjs = offsets.size + 1
    writeString("xref\n0 $totalObjs\n0000000000 65535 f \n")
    for (offset in offsets) {
      writeString(String.format(Locale.US, "%010d 00000 n \n", offset))
    }

    // Trailer
    writeString("trailer\n<< /Size $totalObjs /Root 1 0 R >>\nstartxref\n$startXref\n%%EOF\n")

    outputFile.outputStream().use { fos ->
      bos.writeTo(fos)
    }
  }

  /**
   * Returns a secure content URI for sharing the generated PDF via FileProvider.
   */
  fun getShareableUri(pdfFile: File): Uri {
    return FileProvider.getUriForFile(
      context,
      "${context.packageName}.provider",
      pdfFile
    )
  }

  /**
   * Internal drawing manager maintaining layout flow, multi-page breaks, running headers, and footers.
   */
  private class PdfPageRenderer(
    private val doc: PdfDocument,
    private val scan: ScanRecord,
    private val report: ForensicReport,
    private val formattedDate: String
  ) {
    private var pageNumber = 0
    private var currentPage: PdfDocument.Page? = null
    var canvas: Canvas = Canvas()
    var currentY: Float = HEADER_TOP_Y

    private val textPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply { color = COLOR_SLATE_DARK }
    private val bgPaint = Paint(Paint.ANTI_ALIAS_FLAG)
    private val strokePaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
      style = Paint.Style.STROKE
      strokeWidth = 1f
    }

    fun startNewPage() {
      finishCurrentPage()
      pageNumber++
      val pageInfo = PdfDocument.PageInfo.Builder(PAGE_WIDTH, PAGE_HEIGHT, pageNumber).create()
      currentPage = doc.startPage(pageInfo)
      canvas = currentPage!!.canvas
      currentY = HEADER_TOP_Y

      // Draw running header on pages > 1
      if (pageNumber > 1) {
        drawRunningHeader()
      }
      drawRunningFooter()
    }

    fun finishCurrentPage() {
      currentPage?.let {
        doc.finishPage(it)
        currentPage = null
      }
    }

    fun ensureSpace(requiredHeight: Float) {
      if (currentY + requiredHeight > MAX_CONTENT_Y) {
        startNewPage()
      }
    }

    private fun drawRunningHeader() {
      textPaint.apply {
        typeface = Typeface.create(Typeface.DEFAULT, Typeface.BOLD)
        textSize = 8f
        color = COLOR_SLATE_TEXT
      }
      canvas.drawText("PS-02 FORENSIC EVIDENCE DOSSIER", MARGIN_LEFT, currentY, textPaint)

      val scanRef = "SCAN-ID: ${scan.id.take(12)}... | TARGET: ${scan.packageName}"
      val width = textPaint.measureText(scanRef)
      canvas.drawText(scanRef, PAGE_WIDTH - MARGIN_RIGHT - width, currentY, textPaint)

      currentY += 8f
      strokePaint.color = COLOR_BORDER
      canvas.drawLine(MARGIN_LEFT, currentY, PAGE_WIDTH - MARGIN_RIGHT, currentY, strokePaint)
      currentY += 16f
    }

    private fun drawRunningFooter() {
      strokePaint.color = COLOR_BORDER
      canvas.drawLine(MARGIN_LEFT, FOOTER_Y - 10f, PAGE_WIDTH - MARGIN_RIGHT, FOOTER_Y - 10f, strokePaint)

      textPaint.apply {
        typeface = Typeface.DEFAULT
        textSize = 8f
        color = COLOR_SLATE_TEXT
      }
      canvas.drawText("CONFIDENTIAL & PRIVILEGED • CYBER FORENSIC AUDIT RECORD", MARGIN_LEFT, FOOTER_Y, textPaint)

      val pageLabel = "Page $pageNumber"
      val pageLabelWidth = textPaint.measureText(pageLabel)
      canvas.drawText(pageLabel, PAGE_WIDTH - MARGIN_RIGHT - pageLabelWidth, FOOTER_Y, textPaint)
    }

    fun drawExecutiveCover(scan: ScanRecord, report: ForensicReport, findings: List<ScanFinding>) {
      // 1. Header Banner
      val bannerHeight = 72f
      bgPaint.color = COLOR_NAVY
      val bannerRect = RectF(MARGIN_LEFT, currentY, PAGE_WIDTH - MARGIN_RIGHT, currentY + bannerHeight)
      canvas.drawRoundRect(bannerRect, 8f, 8f, bgPaint)

      // Brand accent line
      bgPaint.color = COLOR_CYAN
      canvas.drawRect(MARGIN_LEFT, currentY + bannerHeight - 4f, PAGE_WIDTH - MARGIN_RIGHT, currentY + bannerHeight, bgPaint)

      textPaint.apply {
        color = COLOR_WHITE
        typeface = Typeface.create(Typeface.DEFAULT, Typeface.BOLD)
        textSize = 14f
      }
      canvas.drawText("PS-02 ANDROID APPLICATION FORENSIC & SECURITY REPORT", MARGIN_LEFT + 14f, currentY + 28f, textPaint)

      textPaint.apply {
        color = Color.rgb(186, 230, 253) // light cyan
        typeface = Typeface.DEFAULT
        textSize = 9f
      }
      canvas.drawText("Static Vulnerability, Permission Threat, and Cryptographic Evidence Audit", MARGIN_LEFT + 14f, currentY + 46f, textPaint)

      currentY += bannerHeight + 16f

      // 2. Metadata Grid (2-column layout)
      val metaBoxHeight = 60f
      bgPaint.color = COLOR_LIGHT_BG
      canvas.drawRoundRect(RectF(MARGIN_LEFT, currentY, PAGE_WIDTH - MARGIN_RIGHT, currentY + metaBoxHeight), 6f, 6f, bgPaint)
      strokePaint.color = COLOR_BORDER
      canvas.drawRoundRect(RectF(MARGIN_LEFT, currentY, PAGE_WIDTH - MARGIN_RIGHT, currentY + metaBoxHeight), 6f, 6f, strokePaint)

      val col1X = MARGIN_LEFT + 12f
      val col2X = MARGIN_LEFT + (CONTENT_WIDTH / 2f) + 12f
      var metaY = currentY + 16f

      drawMetaPair("REPORT ID", report.id.take(24) + "...", col1X, metaY)
      drawMetaPair("TOOL VERSION", report.toolVersion, col2X, metaY)
      metaY += 16f
      drawMetaPair("SCAN ID", scan.id.take(24) + "...", col1X, metaY)
      drawMetaPair("AUDITOR", report.analystName, col2X, metaY)
      metaY += 16f
      drawMetaPair("TIMESTAMP", formattedDate, col1X, metaY)
      drawMetaPair("STATUS", scan.status.name, col2X, metaY)

      currentY += metaBoxHeight + 14f

      // 3. Target Provenance & Cryptographic Verification Box
      val provHeight = 84f
      bgPaint.color = COLOR_WHITE
      canvas.drawRoundRect(RectF(MARGIN_LEFT, currentY, PAGE_WIDTH - MARGIN_RIGHT, currentY + provHeight), 6f, 6f, bgPaint)
      strokePaint.color = COLOR_BORDER
      canvas.drawRoundRect(RectF(MARGIN_LEFT, currentY, PAGE_WIDTH - MARGIN_RIGHT, currentY + provHeight), 6f, 6f, strokePaint)

      textPaint.apply {
        typeface = Typeface.create(Typeface.DEFAULT, Typeface.BOLD)
        textSize = 10f
        color = COLOR_NAVY
      }
      canvas.drawText("TARGET PROVENANCE & CRYPTOGRAPHIC INTEGRITY", MARGIN_LEFT + 12f, currentY + 16f, textPaint)

      var provY = currentY + 32f
      drawMetaPair("App Label", scan.appName, col1X, provY)
      drawMetaPair("Package", scan.packageName, col2X, provY)
      provY += 15f
      drawMetaPair("Version", "${scan.versionName} (Build ${scan.versionCode})", col1X, provY)
      drawMetaPair("Target SDK", "API ${scan.targetSdk} (Min: ${scan.minSdk})", col2X, provY)
      provY += 15f
      drawMetaPair("Original File", "${scan.originalFilename} (${formatBytes(scan.fileSizeBytes)})", col1X, provY)
      provY += 15f

      // Monospace SHA-256 Digest
      textPaint.apply {
        typeface = Typeface.create(Typeface.DEFAULT, Typeface.BOLD)
        textSize = 8.5f
        color = COLOR_SLATE_DARK
      }
      canvas.drawText("SHA-256:", col1X, provY, textPaint)
      textPaint.apply {
        typeface = Typeface.MONOSPACE
        textSize = 8f
        color = COLOR_CYAN
      }
      canvas.drawText(scan.sha256Hash, col1X + 54f, provY, textPaint)

      currentY += provHeight + 14f

      // 4. Composite Risk Score Card
      val scoreBoxHeight = 72f
      val riskColor = getRiskColor(scan.riskLabel)
      val riskBg = getRiskBgColor(scan.riskLabel)

      bgPaint.color = riskBg
      canvas.drawRoundRect(RectF(MARGIN_LEFT, currentY, PAGE_WIDTH - MARGIN_RIGHT, currentY + scoreBoxHeight), 6f, 6f, bgPaint)
      strokePaint.color = riskColor
      canvas.drawRoundRect(RectF(MARGIN_LEFT, currentY, PAGE_WIDTH - MARGIN_RIGHT, currentY + scoreBoxHeight), 6f, 6f, strokePaint)

      // Large Score display on left
      textPaint.apply {
        typeface = Typeface.create(Typeface.MONOSPACE, Typeface.BOLD)
        textSize = 32f
        color = riskColor
      }
      canvas.drawText("${scan.riskScore}", MARGIN_LEFT + 20f, currentY + 44f, textPaint)

      textPaint.apply {
        typeface = Typeface.DEFAULT
        textSize = 10f
        color = COLOR_SLATE_TEXT
      }
      canvas.drawText("/ 100", MARGIN_LEFT + 75f, currentY + 44f, textPaint)

      // Risk Label Pill
      val labelWidth = 80f
      val labelRect = RectF(MARGIN_LEFT + 120f, currentY + 24f, MARGIN_LEFT + 120f + labelWidth, currentY + 48f)
      bgPaint.color = riskColor
      canvas.drawRoundRect(labelRect, 4f, 4f, bgPaint)
      textPaint.apply {
        typeface = Typeface.create(Typeface.DEFAULT, Typeface.BOLD)
        textSize = 10f
        color = COLOR_WHITE
        textAlign = Paint.Align.CENTER
      }
      canvas.drawText(scan.riskLabel.name, labelRect.centerX(), labelRect.centerY() + 3.5f, textPaint)
      textPaint.textAlign = Paint.Align.LEFT

      // Severity count pills on right
      val countsX = MARGIN_LEFT + 225f
      drawCountBadge("CRITICAL", scan.criticalCount, COLOR_CRITICAL, countsX, currentY + 24f)
      drawCountBadge("HIGH", scan.highCount, COLOR_HIGH, countsX + 68f, currentY + 24f)
      drawCountBadge("MEDIUM", scan.mediumCount, COLOR_MEDIUM, countsX + 136f, currentY + 24f)
      drawCountBadge("LOW", scan.lowCount, COLOR_LOW, countsX + 204f, currentY + 24f)

      currentY += scoreBoxHeight + 14f

      // 5. Executive Summary
      textPaint.apply {
        typeface = Typeface.create(Typeface.DEFAULT, Typeface.BOLD)
        textSize = 11f
        color = COLOR_NAVY
      }
      canvas.drawText("EXECUTIVE FORENSIC SUMMARY", MARGIN_LEFT, currentY + 12f, textPaint)
      currentY += 20f

      textPaint.apply {
        typeface = Typeface.DEFAULT
        textSize = 9.5f
        color = COLOR_SLATE_DARK
      }
      val summaryLines = wrapText(report.executiveSummary, textPaint, CONTENT_WIDTH)
      for (line in summaryLines) {
        canvas.drawText(line, MARGIN_LEFT, currentY, textPaint)
        currentY += 13f
      }

      currentY += 10f

      // 6. Manifest Flags Assessment Strip
      val flagsBoxHeight = 44f
      bgPaint.color = COLOR_LIGHT_BG
      canvas.drawRoundRect(RectF(MARGIN_LEFT, currentY, PAGE_WIDTH - MARGIN_RIGHT, currentY + flagsBoxHeight), 6f, 6f, bgPaint)

      val flagY = currentY + 26f
      drawFlagIndicator("DEBUGGABLE", scan.isDebuggable, true, MARGIN_LEFT + 12f, flagY)
      drawFlagIndicator("CLEARTEXT HTTP", scan.usesCleartextTraffic, true, MARGIN_LEFT + 135f, flagY)
      drawFlagIndicator("ALLOW BACKUP", scan.allowsBackup, true, MARGIN_LEFT + 275f, flagY)
      drawFlagIndicator("PERMISSIONS", scan.permissionsCount > 0, false, MARGIN_LEFT + 400f, flagY, labelOverride = "${scan.permissionsCount} Declared")

      currentY += flagsBoxHeight + 18f
    }

    fun drawTechnicalFindings(findings: List<ScanFinding>) {
      textPaint.apply {
        typeface = Typeface.create(Typeface.DEFAULT, Typeface.BOLD)
        textSize = 12f
        color = COLOR_NAVY
      }
      canvas.drawText("TECHNICAL SECURITY FINDINGS & EVIDENCE (${findings.size})", MARGIN_LEFT, currentY, textPaint)
      currentY += 16f

      if (findings.isEmpty()) {
        textPaint.apply {
          typeface = Typeface.create(Typeface.DEFAULT, Typeface.ITALIC)
          textSize = 10f
          color = COLOR_SLATE_TEXT
        }
        canvas.drawText("No security findings or anomalous indicators detected during static analysis.", MARGIN_LEFT, currentY, textPaint)
        currentY += 20f
        return
      }

      findings.forEachIndexed { index, finding ->
        drawFindingItem(index + 1, finding)
      }
    }

    private fun drawFindingItem(index: Int, finding: ScanFinding) {
      val findingPadding = 10f
      val headerHeight = 22f

      // Pre-calculate wrapped line heights
      textPaint.apply {
        typeface = Typeface.DEFAULT
        textSize = 9f
      }
      val descLines = wrapText(finding.description, textPaint, CONTENT_WIDTH - (findingPadding * 2))
      val recLines = wrapText("Remediation: " + finding.recommendation, textPaint, CONTENT_WIDTH - (findingPadding * 2))

      textPaint.apply {
        typeface = Typeface.MONOSPACE
        textSize = 8f
      }
      val evidenceLines = if (finding.evidence.isNotBlank()) {
        wrapText(finding.evidence, textPaint, CONTENT_WIDTH - (findingPadding * 2) - 8f)
      } else emptyList()

      val evidenceBoxHeight = if (evidenceLines.isNotEmpty()) (evidenceLines.size * 11f) + 12f else 0f
      val totalItemHeight = headerHeight + (descLines.size * 12f) + evidenceBoxHeight + (recLines.size * 12f) + (findingPadding * 2) + 8f

      // Check if we need to advance to a new page
      ensureSpace(totalItemHeight)

      // Draw Item Container
      val itemRect = RectF(MARGIN_LEFT, currentY, PAGE_WIDTH - MARGIN_RIGHT, currentY + totalItemHeight)
      bgPaint.color = COLOR_WHITE
      canvas.drawRoundRect(itemRect, 6f, 6f, bgPaint)
      strokePaint.color = COLOR_BORDER
      canvas.drawRoundRect(itemRect, 6f, 6f, strokePaint)

      // Top colored accent border based on severity
      bgPaint.color = getSeverityColor(finding.severity)
      canvas.drawRoundRect(RectF(MARGIN_LEFT, currentY, MARGIN_LEFT + 4f, currentY + totalItemHeight), 6f, 6f, bgPaint)

      var itemY = currentY + 16f

      // Finding Header: [#Index] [RuleId] [CWE]
      textPaint.apply {
        typeface = Typeface.create(Typeface.MONOSPACE, Typeface.BOLD)
        textSize = 8.5f
        color = COLOR_NAVY
      }
      canvas.drawText("[#$index] ${finding.ruleId} • ${finding.cweId}", MARGIN_LEFT + findingPadding + 4f, itemY, textPaint)

      // Severity Badge on Right
      val badgeWidth = 60f
      val badgeRect = RectF(PAGE_WIDTH - MARGIN_RIGHT - badgeWidth - 8f, itemY - 10f, PAGE_WIDTH - MARGIN_RIGHT - 8f, itemY + 5f)
      bgPaint.color = getSeverityBgColor(finding.severity)
      canvas.drawRoundRect(badgeRect, 3f, 3f, bgPaint)
      textPaint.apply {
        typeface = Typeface.create(Typeface.DEFAULT, Typeface.BOLD)
        textSize = 8f
        color = getSeverityColor(finding.severity)
        textAlign = Paint.Align.CENTER
      }
      canvas.drawText(finding.severity.label, badgeRect.centerX(), badgeRect.centerY() + 3f, textPaint)
      textPaint.textAlign = Paint.Align.LEFT

      itemY += 14f

      // Finding Title
      textPaint.apply {
        typeface = Typeface.create(Typeface.DEFAULT, Typeface.BOLD)
        textSize = 10f
        color = COLOR_NAVY
      }
      canvas.drawText(finding.title, MARGIN_LEFT + findingPadding + 4f, itemY, textPaint)
      itemY += 14f

      // Description
      textPaint.apply {
        typeface = Typeface.DEFAULT
        textSize = 9f
        color = COLOR_SLATE_DARK
      }
      for (line in descLines) {
        canvas.drawText(line, MARGIN_LEFT + findingPadding + 4f, itemY, textPaint)
        itemY += 12f
      }

      // Evidence Box (Monospace Dark Background)
      if (evidenceLines.isNotEmpty()) {
        itemY += 4f
        val evRect = RectF(
          MARGIN_LEFT + findingPadding + 4f,
          itemY,
          PAGE_WIDTH - MARGIN_RIGHT - findingPadding,
          itemY + evidenceBoxHeight
        )
        bgPaint.color = COLOR_SLATE_DARK
        canvas.drawRoundRect(evRect, 4f, 4f, bgPaint)

        var evY = itemY + 11f
        textPaint.apply {
          typeface = Typeface.MONOSPACE
          textSize = 8f
          color = Color.rgb(56, 189, 248) // sky-400
        }
        for (evLine in evidenceLines) {
          canvas.drawText(evLine, evRect.left + 6f, evY, textPaint)
          evY += 11f
        }
        itemY += evidenceBoxHeight + 6f
      }

      // Remediation Recommendation
      textPaint.apply {
        typeface = Typeface.DEFAULT
        textSize = 8.5f
        color = COLOR_SLATE_TEXT
      }
      for (line in recLines) {
        canvas.drawText(line, MARGIN_LEFT + findingPadding + 4f, itemY, textPaint)
        itemY += 11f
      }

      currentY += totalItemHeight + 10f
    }

    fun drawMethodologyAndAttestation(report: ForensicReport) {
      ensureSpace(160f)

      // Methodology Section
      textPaint.apply {
        typeface = Typeface.create(Typeface.DEFAULT, Typeface.BOLD)
        textSize = 11f
        color = COLOR_NAVY
      }
      canvas.drawText("METHODOLOGY & STANDARDS COMPLIANCE", MARGIN_LEFT, currentY + 10f, textPaint)
      currentY += 20f

      textPaint.apply {
        typeface = Typeface.DEFAULT
        textSize = 9f
        color = COLOR_SLATE_DARK
      }
      val methodLines = wrapText(report.methodology, textPaint, CONTENT_WIDTH)
      for (line in methodLines) {
        canvas.drawText(line, MARGIN_LEFT, currentY, textPaint)
        currentY += 12f
      }

      currentY += 12f

      // Legal Disclaimer Box
      val discLines = wrapText(report.limitationsDisclaimer, textPaint, CONTENT_WIDTH - 20f)
      val discHeight = (discLines.size * 12f) + 24f

      ensureSpace(discHeight + 60f)

      bgPaint.color = Color.rgb(254, 242, 242) // light red
      val discRect = RectF(MARGIN_LEFT, currentY, PAGE_WIDTH - MARGIN_RIGHT, currentY + discHeight)
      canvas.drawRoundRect(discRect, 6f, 6f, bgPaint)
      strokePaint.color = COLOR_CRITICAL
      canvas.drawRoundRect(discRect, 6f, 6f, strokePaint)

      textPaint.apply {
        typeface = Typeface.create(Typeface.DEFAULT, Typeface.BOLD)
        textSize = 9f
        color = COLOR_CRITICAL
      }
      canvas.drawText("LEGAL NOTICE & STATIC ANALYSIS LIMITATIONS:", MARGIN_LEFT + 10f, currentY + 16f, textPaint)

      var discY = currentY + 28f
      textPaint.apply {
        typeface = Typeface.DEFAULT
        textSize = 8.5f
        color = Color.rgb(153, 27, 27) // dark red
      }
      for (line in discLines) {
        canvas.drawText(line, MARGIN_LEFT + 10f, discY, textPaint)
        discY += 12f
      }

      currentY += discHeight + 16f

      // Sign-off / Attestation Block
      val signBoxHeight = 44f
      strokePaint.color = COLOR_BORDER
      canvas.drawLine(MARGIN_LEFT, currentY + 30f, MARGIN_LEFT + 200f, currentY + 30f, strokePaint)
      canvas.drawLine(PAGE_WIDTH - MARGIN_RIGHT - 140f, currentY + 30f, PAGE_WIDTH - MARGIN_RIGHT, currentY + 30f, strokePaint)

      textPaint.apply {
        typeface = Typeface.DEFAULT
        textSize = 8f
        color = COLOR_SLATE_TEXT
      }
      canvas.drawText("LEAD FORENSIC AUDITOR SIGNATURE", MARGIN_LEFT, currentY + 42f, textPaint)
      canvas.drawText("DATE OF ISSUANCE", PAGE_WIDTH - MARGIN_RIGHT - 140f, currentY + 42f, textPaint)

      currentY += signBoxHeight + 10f
    }

    private fun drawMetaPair(label: String, value: String, x: Float, y: Float) {
      textPaint.apply {
        typeface = Typeface.create(Typeface.DEFAULT, Typeface.BOLD)
        textSize = 8f
        color = COLOR_SLATE_TEXT
      }
      canvas.drawText(label, x, y, textPaint)

      textPaint.apply {
        typeface = Typeface.DEFAULT
        textSize = 8.5f
        color = COLOR_SLATE_DARK
      }
      canvas.drawText(value, x + 65f, y, textPaint)
    }

    private fun drawCountBadge(label: String, count: Int, color: Int, x: Float, y: Float) {
      val badgeRect = RectF(x, y, x + 60f, y + 24f)
      bgPaint.color = COLOR_WHITE
      canvas.drawRoundRect(badgeRect, 4f, 4f, bgPaint)
      strokePaint.color = color
      canvas.drawRoundRect(badgeRect, 4f, 4f, strokePaint)

      textPaint.apply {
        typeface = Typeface.create(Typeface.MONOSPACE, Typeface.BOLD)
        textSize = 10f
        this.color = color
        textAlign = Paint.Align.CENTER
      }
      canvas.drawText("$count", badgeRect.centerX(), badgeRect.top + 11f, textPaint)

      textPaint.apply {
        typeface = Typeface.DEFAULT
        textSize = 7f
        this.color = COLOR_SLATE_TEXT
      }
      canvas.drawText(label, badgeRect.centerX(), badgeRect.top + 20f, textPaint)
      textPaint.textAlign = Paint.Align.LEFT
    }

    private fun drawFlagIndicator(name: String, isFlagged: Boolean, flagIsBad: Boolean, x: Float, y: Float, labelOverride: String? = null) {
      val statusColor = if (flagIsBad) {
        if (isFlagged) COLOR_CRITICAL else COLOR_SAFE
      } else {
        COLOR_CYAN
      }

      bgPaint.color = statusColor
      canvas.drawCircle(x + 4f, y - 3f, 3.5f, bgPaint)

      textPaint.apply {
        typeface = Typeface.create(Typeface.DEFAULT, Typeface.BOLD)
        textSize = 8f
        color = COLOR_SLATE_DARK
      }
      val text = labelOverride ?: "$name: ${if (isFlagged) "YES" else "NO"}"
      canvas.drawText(text, x + 12f, y, textPaint)
    }

    private fun wrapText(text: String, paint: Paint, maxWidth: Float): List<String> {
      val lines = mutableListOf<String>()
      val words = text.split(Regex("\\s+"))
      var currentLine = StringBuilder()

      for (word in words) {
        val testLine = if (currentLine.isEmpty()) word else "$currentLine $word"
        val measured = paint.measureText(testLine)
        if (measured <= maxWidth) {
          currentLine = StringBuilder(testLine)
        } else {
          if (currentLine.isNotEmpty()) {
            lines.add(currentLine.toString())
          }
          currentLine = StringBuilder(word)
        }
      }
      if (currentLine.isNotEmpty()) {
        lines.add(currentLine.toString())
      }
      return lines
    }

    private fun getRiskColor(riskLabel: RiskLabel): Int = when (riskLabel) {
      RiskLabel.CRITICAL -> COLOR_CRITICAL
      RiskLabel.HIGH -> COLOR_HIGH
      RiskLabel.MEDIUM -> COLOR_MEDIUM
      RiskLabel.LOW -> COLOR_LOW
      RiskLabel.SAFE -> COLOR_SAFE
    }

    private fun getRiskBgColor(riskLabel: RiskLabel): Int = when (riskLabel) {
      RiskLabel.CRITICAL -> COLOR_CRITICAL_BG
      RiskLabel.HIGH -> COLOR_HIGH_BG
      RiskLabel.MEDIUM -> COLOR_MEDIUM_BG
      RiskLabel.LOW -> COLOR_LOW_BG
      RiskLabel.SAFE -> Color.rgb(236, 253, 245)
    }

    private fun getSeverityColor(severity: Severity): Int = when (severity) {
      Severity.CRITICAL -> COLOR_CRITICAL
      Severity.HIGH -> COLOR_HIGH
      Severity.MEDIUM -> COLOR_MEDIUM
      Severity.LOW -> COLOR_LOW
      Severity.INFO -> COLOR_CYAN
    }

    private fun getSeverityBgColor(severity: Severity): Int = when (severity) {
      Severity.CRITICAL -> COLOR_CRITICAL_BG
      Severity.HIGH -> COLOR_HIGH_BG
      Severity.MEDIUM -> COLOR_MEDIUM_BG
      Severity.LOW -> COLOR_LOW_BG
      Severity.INFO -> Color.rgb(224, 242, 254)
    }

    private fun formatBytes(bytes: Long): String {
      if (bytes <= 0) return "0 B"
      val kb = bytes / 1024.0
      val mb = kb / 1024.0
      return when {
        mb >= 1.0 -> String.format(Locale.US, "%.1f MB", mb)
        kb >= 1.0 -> String.format(Locale.US, "%.1f KB", kb)
        else -> "$bytes B"
      }
    }
  }
}
