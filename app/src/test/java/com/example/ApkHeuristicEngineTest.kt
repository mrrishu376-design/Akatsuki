package com.example

import com.example.data.analyzer.ApkHeuristicEngine
import com.example.data.model.Confidence
import com.example.data.model.HeuristicCategory
import com.example.data.model.Severity
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import java.io.File
import java.io.FileOutputStream
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class ApkHeuristicEngineTest {

  private lateinit var heuristicEngine: ApkHeuristicEngine

  @Before
  fun setUp() {
    heuristicEngine = ApkHeuristicEngine()
  }

  @Test
  fun `scanDexContent detects Dynamic Code Loading with DexClassLoader`() {
    val maliciousBytecode = """
      Lcom/malware/dropper/PayloadManager;->loadRemoteDex(Ljava/lang/String;)V
      const-string v0, "dalvik.system.DexClassLoader"
      invoke-static {v0}, Ljava/lang/Class;->forName(Ljava/lang/String;)Ljava/lang/Class;
      new-instance v1, Ldalvik/system/DexClassLoader;
      invoke-direct {v1, p1, p2, p3, p4}, Ldalvik/system/DexClassLoader;-><init>()V
    """.trimIndent()

    val result = heuristicEngine.scanDexContent(dexContent = maliciousBytecode, scanId = "test-scan-dcl")

    assertTrue("Expected DCL finding", result.findings.any { it.category == HeuristicCategory.DYNAMIC_CODE_LOADING })
    val dclFinding = result.findings.first { it.ruleId == "HEUR-DCL-DEXCLASSLOADER" }
    assertEquals(Severity.CRITICAL, dclFinding.severity)
    assertEquals(Confidence.HIGH, dclFinding.confidence)
    assertEquals("T1407", dclFinding.mitreAttackId)
    assertTrue(result.summary.hasDynamicLoading)
    assertEquals(1, result.summary.dclCount)
  }

  @Test
  fun `scanDexContent detects InMemoryDexClassLoader execution`() {
    val inMemoryBytecode = """
      const-string v1, "dalvik.system.InMemoryDexClassLoader"
      invoke-virtual {p0, v1}, Ldalvik/system/InMemoryDexClassLoader;->loadClass()Ljava/lang/Class;
    """.trimIndent()

    val result = heuristicEngine.scanDexContent(dexContent = inMemoryBytecode)

    assertTrue("Should detect in-memory loader", result.findings.any { it.ruleId == "HEUR-DCL-INMEMORYDEX" })
    val finding = result.findings.first { it.ruleId == "HEUR-DCL-INMEMORYDEX" }
    assertEquals(Severity.CRITICAL, finding.severity)
    assertEquals("CWE-912", finding.cweId)
  }

  @Test
  fun `scanDexContent detects suspicious reflection calls for shell command execution`() {
    val reflectionBytecode = """
      Lcom/trojan/root/Escalation;->executeRoot()V
      const-string v0, "java.lang.Runtime"
      invoke-static {v0}, Ljava/lang/Class;->forName(Ljava/lang/String;)Ljava/lang/Class;
      const-string v1, "getRuntime"
      const-string v2, "exec"
      invoke-virtual {v3, v4, v5}, Ljava/lang/reflect/Method;->invoke(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;
      const-string v6, "/system/bin/sh"
      const-string v7, "su"
    """.trimIndent()

    val result = heuristicEngine.scanDexContent(dexContent = reflectionBytecode)

    assertTrue("Should detect shell reflection", result.findings.any { it.category == HeuristicCategory.SUSPICIOUS_REFLECTION })
    val shellFinding = result.findings.first { it.ruleId == "HEUR-REFL-SHELL-EXEC" }
    assertEquals(Severity.CRITICAL, shellFinding.severity)
    assertEquals("T1059 / T1629.001", shellFinding.mitreAttackId)
    assertTrue(result.summary.hasSuspiciousReflection)
  }

  @Test
  fun `scanDexContent detects hidden SystemProperties sandbox evasion query`() {
    val sandboxEvasionBytecode = """
      Lcom/stealth/anti_analysis/DetectEmulator;->isSandbox()Z
      const-string v0, "android.os.SystemProperties"
      const-string v1, "get"
      const-string v2, "ro.kernel.qemu"
      invoke-static {v2}, Landroid/os/SystemProperties;->get(Ljava/lang/String;)Ljava/lang/String;
    """.trimIndent()

    val result = heuristicEngine.scanDexContent(dexContent = sandboxEvasionBytecode)

    assertTrue("Should detect SystemProperties sandbox evasion", result.findings.any { it.ruleId == "HEUR-REFL-SYSTEM-PROPERTIES-EVASION" })
    val finding = result.findings.first { it.ruleId == "HEUR-REFL-SYSTEM-PROPERTIES-EVASION" }
    assertEquals(Severity.HIGH, finding.severity)
    assertEquals("T1497 / T1629.001", finding.mitreAttackId)
  }

  @Test
  fun `scanDexContent detects reflective telephony and IMEI harvesting`() {
    val telephonyBytecode = """
      Lcom/spyware/harvester/Fingerprint;->readDeviceIdentity()V
      invoke-virtual {v0, v1, v2}, Ljava/lang/reflect/Method;->invoke(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;
      const-string v3, "getDeviceId"
      const-string v4, "getImei"
    """.trimIndent()

    val result = heuristicEngine.scanDexContent(dexContent = telephonyBytecode)

    assertTrue("Should detect reflective telephony harvest", result.findings.any { it.ruleId == "HEUR-REFL-TELEPHONY-HARVEST" })
    val finding = result.findings.first { it.ruleId == "HEUR-REFL-TELEPHONY-HARVEST" }
    assertEquals(Severity.HIGH, finding.severity)
  }

  @Test
  fun `scanApkFile detects commercial packer and hidden asset payload in zip archive`() {
    val tempApk = File.createTempFile("test_sample_packed", ".apk").apply { deleteOnExit() }

    ZipOutputStream(FileOutputStream(tempApk)).use { zip ->
      // Add a known Qihoo Jiagu packer library
      zip.putNextEntry(ZipEntry("lib/arm64-v8a/libjiagu.so"))
      zip.write(byteArrayOf(0x7F, 0x45, 0x4C, 0x46)) // ELF magic
      zip.closeEntry()

      // Add a hidden secondary DEX inside assets/
      zip.putNextEntry(ZipEntry("assets/secondary_payload.dex"))
      zip.write("dex\n035\u0000".toByteArray())
      zip.closeEntry()

      // Add main classes.dex
      zip.putNextEntry(ZipEntry("classes.dex"))
      val dexCode = "SourceFile: \"\"\n" + (1..20).joinToString("\n") { "a/b/c" }
      zip.write(dexCode.toByteArray())
      zip.closeEntry()
    }

    val result = heuristicEngine.scanApkFile(tempApk, scanId = "scan-zip-test")

    // Check Packer detection
    val packerFinding = result.findings.firstOrNull { it.ruleId.startsWith("HEUR-OBF-PACKER") }
    assertNotNull("Expected Qihoo 360 Jiagu packer finding", packerFinding)
    assertEquals(Severity.CRITICAL, packerFinding?.severity)
    assertEquals("Qihoo 360 Jiagu Packer", result.summary.packerIdentified)

    // Check Hidden payload detection in assets
    val payloadFinding = result.findings.firstOrNull { it.ruleId == "HEUR-DCL-HIDDEN-PAYLOAD" }
    assertNotNull("Expected hidden payload finding", payloadFinding)
    assertEquals(Severity.HIGH, payloadFinding?.severity)

    // Check Short identifier mangling detection
    val manglingFinding = result.findings.firstOrNull { it.ruleId == "HEUR-OBF-SHORT-IDENTIFIERS" }
    assertNotNull("Expected identifier mangling finding", manglingFinding)

    assertTrue(result.summary.riskContributionScore > 30)
  }

  @Test
  fun `evaluateHeuristics evaluates predefined benchmark pattern matrix`() {
    val result = heuristicEngine.evaluateHeuristics(
      scanId = "bench-test",
      dclPatterns = listOf("DexClassLoader", "PayloadDrop"),
      obfuscationPatterns = listOf("Jiagu"),
      reflectionPatterns = listOf("Exec", "SystemProperties")
    )

    assertEquals(5, result.findings.size)
    assertEquals(2, result.summary.dclCount)
    assertEquals(1, result.summary.obfuscationCount)
    assertEquals(2, result.summary.reflectionCount)
    assertEquals("Qihoo 360 Jiagu Packer", result.summary.packerIdentified)
    assertEquals(Severity.CRITICAL, result.summary.highestSeverity)
    assertTrue(result.summary.hasDynamicLoading)
    assertTrue(result.summary.hasSuspiciousReflection)
  }

  @Test
  fun `clean benign code produces zero heuristic malicious alerts`() {
    val cleanBytecode = """
      package com.example.cleanapp;
      import android.os.Bundle;
      import androidx.appcompat.app.AppCompatActivity;
      public class MainActivity extends AppCompatActivity {
        @Override
        protected void onCreate(Bundle savedInstanceState) {
          super.onCreate(savedInstanceState);
        }
      }
    """.trimIndent()

    val result = heuristicEngine.scanDexContent(dexContent = cleanBytecode)

    assertTrue("Clean code should have no heuristic threats", result.findings.isEmpty())
    assertFalse(result.summary.hasDynamicLoading)
    assertFalse(result.summary.hasSuspiciousReflection)
    assertEquals(0, result.summary.totalHeuristicFindings)
    assertEquals(0, result.summary.riskContributionScore)
  }
}
