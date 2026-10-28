package com.example

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import com.example.data.analyzer.SampleApkCatalog
import com.example.data.model.RiskLabel
import com.example.data.model.Severity
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class ExampleRobolectricTest {

  @Test
  fun `read app name string from context`() {
    val context = ApplicationProvider.getApplicationContext<Context>()
    val appName = context.getString(R.string.app_name)
    assertEquals("PS-02 Security", appName)
  }

  @Test
  fun `verify sample benchmark risk evaluation`() {
    val insecureBank = SampleApkCatalog.benchmarks.first { it.id == "bench-insecure-bank" }
    val result = SampleApkCatalog.generateBenchmarkResult(insecureBank, "test_owner")

    assertNotNull(result.scan)
    assertEquals("InsecureBank Mobile v1.4", result.scan.appName)
    assertTrue("Risk score should be elevated for insecure bank target", result.scan.riskScore >= 75)
    assertEquals(RiskLabel.CRITICAL, result.scan.riskLabel)
    assertTrue("Should detect at least one critical finding", result.findings.any { it.severity == Severity.CRITICAL })
    assertTrue("Should include forensic report", result.report.executiveSummary.isNotBlank())
  }
}
