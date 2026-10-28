package com.example.data.analyzer

import com.example.data.model.Confidence
import com.example.data.model.HeuristicAnalysisSummary
import com.example.data.model.HeuristicCategory
import com.example.data.model.HeuristicFinding
import com.example.data.model.HeuristicScanResult
import com.example.data.model.Severity
import java.io.File
import java.util.UUID
import java.util.regex.Pattern
import java.util.zip.ZipEntry
import java.util.zip.ZipInputStream

/**
 * Heuristic Scanning Engine for Android APK static and forensic analysis.
 *
 * Scans APK binary streams, DEX byte structures, native libraries, and manifest tokens
 * to detect common malicious patterns:
 * 1. Dynamic Code Loading (DCL): DexClassLoader, InMemoryDexClassLoader, PathClassLoader, dynamic payload drops.
 * 2. Obfuscation & Packer Indicators: Known protector signatures (Jiagu, SecShell, Legu, Baidu, etc.),
 *    high identifier entropy/mangling, stripped debug tables, encrypted string stubs.
 * 3. Suspicious Reflection: Reflective execution of shell commands, hidden SystemProperties sandbox evasion,
 *    hidden API restriction bypasses, and reflective telephony harvesting.
 */
class ApkHeuristicEngine {

  companion object {
    // Known commercial and malware packer / protector signatures
    private val PACKER_SIGNATURES = mapOf(
      "libjiagu.so" to ("Qihoo 360 Jiagu Packer" to Severity.CRITICAL),
      "libjiagu_a64.so" to ("Qihoo 360 Jiagu Packer (arm64)" to Severity.CRITICAL),
      "libjiagu_x86.so" to ("Qihoo 360 Jiagu Packer (x86)" to Severity.CRITICAL),
      "com.qihoo.util.stub" to ("Qihoo 360 Jiagu Stub Class" to Severity.CRITICAL),
      "libsecmain.so" to ("Bangcle / SecShell Protector" to Severity.CRITICAL),
      "libsecexe.so" to ("Bangcle / SecShell Protector" to Severity.CRITICAL),
      "libbangcle.so" to ("Bangcle SecShell Native Engine" to Severity.CRITICAL),
      "com.secshell.secData" to ("SecShell Encrypted Container" to Severity.CRITICAL),
      "libtxo.so" to ("Tencent Legu Protector" to Severity.HIGH),
      "libshell.so" to ("Tencent Legu Native Shell" to Severity.HIGH),
      "com.tencent.StubShell" to ("Tencent Legu Stub" to Severity.HIGH),
      "libbaiduprotect.so" to ("Baidu Protect Native Shell" to Severity.HIGH),
      "libapkprotect.so" to ("APK Protect Engine" to Severity.HIGH),
      "libmobisec.so" to ("Alibaba AliProtect" to Severity.HIGH),
      "libkudelski.so" to ("Nagra / Kudelski Security Shell" to Severity.MEDIUM),
      "libdexguard.so" to ("DexGuard Native Security" to Severity.MEDIUM)
    )

    // Dynamic Code Loading patterns
    private val PATTERN_DEX_CLASS_LOADER = Pattern.compile("dalvik[./]system[./]DexClassLoader")
    private val PATTERN_IN_MEMORY_DEX = Pattern.compile("dalvik[./]system[./]InMemoryDexClassLoader")
    private val PATTERN_PATH_CLASS_LOADER = Pattern.compile("dalvik[./]system[./]PathClassLoader")
    private val PATTERN_DELEGATE_LAST = Pattern.compile("dalvik[./]system[./]DelegateLastClassLoader")
    private val PATTERN_SYSTEM_LOAD_DYNAMIC = Pattern.compile("System\\s*\\.\\s*load\\s*\\(\\s*[\"']?/(data|cache|sdcard)")
    private val PATTERN_DEX_FILE_API = Pattern.compile("dalvik[./]system[./]DexFile[;.]loadDex")

    // Reflection patterns
    private val PATTERN_METHOD_INVOKE = Pattern.compile("java[./]lang[./]reflect[./]Method[;.](?:->)?invoke|Method\\.invoke")
    private val PATTERN_CLASS_FOR_NAME = Pattern.compile("java[./]lang[./]Class[;.](?:->)?forName|Class\\.forName")
    private val PATTERN_FIELD_SET_ACCESSIBLE = Pattern.compile("setAccessible\\s*\\(\\s*true\\s*\\)")
    private val PATTERN_SYSTEM_PROPERTIES = Pattern.compile("android[./]os[./]SystemProperties[;.](?:->)?get")
    private val PATTERN_RUNTIME_EXEC = Pattern.compile("java[./]lang[./]Runtime[;.](?:->)?(?:getRuntime[;.](?:->)?)?exec|Runtime\\.getRuntime\\(\\)\\.exec|ProcessBuilder")
    private val PATTERN_SHELL_CMD = Pattern.compile("\\b(?:/system/bin/sh|/system/xbin/su)\\b|\"su\"|'su'")
    private val PATTERN_VM_RUNTIME_BYPASS = Pattern.compile("dalvik[./]system[./]VMRuntime|setHiddenApiExemptions")
    private val PATTERN_TELEPHONY_REFLECT = Pattern.compile("getDeviceId|getImei|getSubscriberId|getSimSerialNumber")

    // Obfuscation indicators
    private val PATTERN_SHORT_IDENTIFIERS = Pattern.compile("\\b[a-z]{1,2}/[a-z]{1,2}/[a-z]{1,2}\\b")
    private val PATTERN_STRIPPED_SOURCE = Pattern.compile("SourceFile\\s*:\\s*(\"\"|\"SourceFile\"|null)")
    private val PATTERN_XOR_DECRYPT_STUB = Pattern.compile("(?:\\^\\s*0x[0-9a-fA-F]{1,2}|byte\\[\\]\\s*[a-zA-Z0-9_]+\\s*=\\s*new\\s*byte)")
  }

  /**
   * Scans an APK file directly, inspecting ZIP entries and extracting strings from DEX/SO files.
   */
  fun scanApkFile(apkFile: File, scanId: String = ""): HeuristicScanResult {
    val findings = mutableListOf<HeuristicFinding>()
    val entryNames = mutableListOf<String>()
    val dexTexts = StringBuilder()

    var strippedSourceFileHits = 0
    var suspiciousSoFileFound: String? = null

    try {
      ZipInputStream(apkFile.inputStream()).use { zip ->
        var entry: ZipEntry?
        while (zip.nextEntry.also { entry = it } != null) {
          val name = entry?.name ?: continue
          entryNames.add(name)

          // 1. Check for Packer / Protector native libraries or stub signatures in entry names
          for ((sig, meta) in PACKER_SIGNATURES) {
            if (name.contains(sig, ignoreCase = true)) {
              suspiciousSoFileFound = meta.first
              findings.add(
                HeuristicFinding(
                  ruleId = "HEUR-OBF-PACKER-${sig.take(8).uppercase().replace(".", "")}",
                  category = HeuristicCategory.OBFUSCATION_PACKERS,
                  title = "Packer / Protector Signature Detected: ${meta.first}",
                  severity = meta.second,
                  confidence = Confidence.HIGH,
                  description = "APK contains native binary or stub component matching known packer or protector: '${meta.first}'. Packers obscure application logic and unpack bytecode into memory dynamically.",
                  matchedPattern = sig,
                  evidenceSnippet = "Archive Entry: $name",
                  location = name,
                  mitreAttackId = "T1406",
                  cweId = "CWE-656",
                  remediation = "Provide clear unpacked release artifacts for forensic auditing and Play Store compliance."
                )
              )
            }
          }

          // 2. Check for hidden executable payloads in assets/ or res/raw/
          if ((name.startsWith("assets/") || name.startsWith("res/raw/")) &&
            (name.endsWith(".dex") || name.endsWith(".jar") || name.endsWith(".apk") || name.endsWith(".payload"))
          ) {
            findings.add(
              HeuristicFinding(
                ruleId = "HEUR-DCL-HIDDEN-PAYLOAD",
                category = HeuristicCategory.DYNAMIC_CODE_LOADING,
                title = "Hidden Secondary Executable Payload in Assets",
                severity = Severity.HIGH,
                confidence = Confidence.HIGH,
                description = "Discovered compiled Dalvik bytecode or executable archive bundled inside assets/resources. Often used in dropper attacks for staged dynamic loading.",
                matchedPattern = name.substringAfterLast("."),
                evidenceSnippet = "Payload asset: $name",
                location = name,
                mitreAttackId = "T1407",
                cweId = "CWE-912",
                remediation = "Bundle all code statically in base application DEX structures or feature modules. Remove dropped bytecode archives."
              )
            )
          }

          // 3. Extract DEX text for bytecode pattern matching
          if (name.endsWith(".dex")) {
            val bytes = zip.readBytes()
            val text = String(bytes, Charsets.ISO_8859_1)
            dexTexts.append(text).append("\n")

            if (text.contains("SourceFile") && (text.contains("SourceFile: \"\"") || text.contains("SourceFile: SourceFile"))) {
              strippedSourceFileHits++
            }
          }
        }
      }
    } catch (_: Exception) {}

    // Evaluate extracted DEX bytecode / strings against heuristic rules
    val bytecodeFindings = scanDexContent(dexTexts.toString(), entryNames, scanId)
    findings.addAll(bytecodeFindings.findings)

    val summary = computeSummary(findings, suspiciousSoFileFound)
    return HeuristicScanResult(findings = findings.distinctBy { it.ruleId }, summary = summary)
  }

  /**
   * Scans text or extracted string representation from DEX bytecode and asset entries.
   */
  fun scanDexContent(
    dexContent: String,
    entryNames: List<String> = emptyList(),
    scanId: String = ""
  ): HeuristicScanResult {
    val findings = mutableListOf<HeuristicFinding>()
    var identifiedPacker: String? = null

    // ---------------------------------------------------------
    // CATEGORY 1: Dynamic Code Loading (DCL)
    // ---------------------------------------------------------

    // DexClassLoader
    if (PATTERN_DEX_CLASS_LOADER.matcher(dexContent).find()) {
      findings.add(
        HeuristicFinding(
          ruleId = "HEUR-DCL-DEXCLASSLOADER",
          category = HeuristicCategory.DYNAMIC_CODE_LOADING,
          title = "Dynamic Code Loading via DexClassLoader",
          severity = Severity.CRITICAL,
          confidence = Confidence.HIGH,
          description = "Application references 'dalvik.system.DexClassLoader' to dynamically load and execute external bytecode (DEX/JAR) at runtime. This allows bypassing store review and running unvetted secondary payloads.",
          matchedPattern = "dalvik.system.DexClassLoader",
          evidenceSnippet = "Reference in bytecode: dalvik/system/DexClassLoader",
          location = "classes.dex",
          mitreAttackId = "T1407",
          cweId = "CWE-912",
          remediation = "Package all application code statically in base APK or Android App Bundle. Avoid loading code from disk at runtime."
        )
      )
    }

    // InMemoryDexClassLoader
    if (PATTERN_IN_MEMORY_DEX.matcher(dexContent).find()) {
      findings.add(
        HeuristicFinding(
          ruleId = "HEUR-DCL-INMEMORYDEX",
          category = HeuristicCategory.DYNAMIC_CODE_LOADING,
          title = "In-Memory Dynamic Bytecode Execution",
          severity = Severity.CRITICAL,
          confidence = Confidence.HIGH,
          description = "Application utilizes 'dalvik.system.InMemoryDexClassLoader' to execute Dalvik bytecode directly from memory (ByteBuffer) without writing to disk, evading filesystem-based endpoint detection.",
          matchedPattern = "dalvik.system.InMemoryDexClassLoader",
          evidenceSnippet = "Reference in bytecode: dalvik/system/InMemoryDexClassLoader",
          location = "classes.dex",
          mitreAttackId = "T1407",
          cweId = "CWE-912",
          remediation = "Remove in-memory bytecode loader. Deploy standard compiled classes in release artifacts."
        )
      )
    }

    // PathClassLoader / DexFile
    if (PATTERN_PATH_CLASS_LOADER.matcher(dexContent).find() && (dexContent.contains("/data/data/") || dexContent.contains("/data/user/0/"))) {
      findings.add(
        HeuristicFinding(
          ruleId = "HEUR-DCL-PATHCLASSLOADER-WRITABLE",
          category = HeuristicCategory.DYNAMIC_CODE_LOADING,
          title = "PathClassLoader Targeting Writable Application Storage",
          severity = Severity.HIGH,
          confidence = Confidence.HIGH,
          description = "PathClassLoader instantiated targeting user-writable storage paths (/data/data), allowing runtime code injection or replacement of class definitions.",
          matchedPattern = "PathClassLoader -> /data/data/",
          evidenceSnippet = "dalvik.system.PathClassLoader targeting application private directory",
          location = "classes.dex",
          mitreAttackId = "T1407",
          cweId = "CWE-94",
          remediation = "Rely exclusively on system-managed class loader paths."
        )
      )
    }

    // Dynamic System.load
    if (PATTERN_SYSTEM_LOAD_DYNAMIC.matcher(dexContent).find() || dexContent.contains("System.load(/data/")) {
      findings.add(
        HeuristicFinding(
          ruleId = "HEUR-DCL-NATIVE-ABSOLUTE-LOAD",
          category = HeuristicCategory.DYNAMIC_CODE_LOADING,
          title = "Dynamic Native Library Loading from Writable Directory",
          severity = Severity.HIGH,
          confidence = Confidence.HIGH,
          description = "Discovered System.load() targeting absolute writable filesystem paths (/data/data or /cache) rather than System.loadLibrary(), enabling execution of dropped native ELF shared objects.",
          matchedPattern = "System.load(/data/...) / Runtime.load()",
          evidenceSnippet = "Invocation: System.load(writablePath)",
          location = "classes.dex",
          mitreAttackId = "T1407",
          cweId = "CWE-114",
          remediation = "Bundle native libraries in APK's lib/<abi>/ directory and invoke System.loadLibrary() exclusively."
        )
      )
    }

    // ---------------------------------------------------------
    // CATEGORY 2: Obfuscation Indicators & Packers
    // ---------------------------------------------------------

    // Check entry names or text for packer signatures
    for ((sig, meta) in PACKER_SIGNATURES) {
      if (dexContent.contains(sig, ignoreCase = true) || entryNames.any { it.contains(sig, ignoreCase = true) }) {
        identifiedPacker = meta.first
        findings.add(
          HeuristicFinding(
            ruleId = "HEUR-OBF-PACKER-${sig.take(8).uppercase().replace(".", "")}",
            category = HeuristicCategory.OBFUSCATION_PACKERS,
            title = "Packer / Protector Signature Detected: ${meta.first}",
            severity = meta.second,
            confidence = Confidence.HIGH,
            description = "Discovered known packer or shell protection signature: '${meta.first}'. Packers conceal real application logic from static inspection tools.",
            matchedPattern = sig,
            evidenceSnippet = "Matched indicator: $sig",
            location = "APK Binary",
            mitreAttackId = "T1406",
            cweId = "CWE-656",
            remediation = "Audit third-party packaging tools. Ensure build artifacts conform to transparent Play Store guidelines."
          )
        )
      }
    }

    // Short identifier density (mangling)
    val shortMatcher = PATTERN_SHORT_IDENTIFIERS.matcher(dexContent)
    var shortHits = 0
    while (shortMatcher.find() && shortHits < 100) {
      shortHits++
    }

    if (shortHits >= 15) {
      findings.add(
        HeuristicFinding(
          ruleId = "HEUR-OBF-SHORT-IDENTIFIERS",
          category = HeuristicCategory.OBFUSCATION_PACKERS,
          title = "Aggressive Class/Package Identifier Mangling",
          severity = Severity.LOW,
          confidence = Confidence.HIGH,
          description = "Detected widespread short single/two-letter class and package identifiers (e.g. a/b/c). Indicates symbol renaming through ProGuard, R8, or DexGuard.",
          matchedPattern = "[a-z]/[a-z]/[a-z] density ($shortHits instances)",
          evidenceSnippet = "Sample obfuscated package tokens: a.b.c, o.a.b",
          location = "classes.dex",
          mitreAttackId = "T1406",
          cweId = "CWE-656",
          remediation = "Retain mapping.txt files for authorized security verification and debugging."
        )
      )
    }

    // Stripped debug info
    if (PATTERN_STRIPPED_SOURCE.matcher(dexContent).find()) {
      findings.add(
        HeuristicFinding(
          ruleId = "HEUR-OBF-STRIPPED-DEBUG",
          category = HeuristicCategory.OBFUSCATION_PACKERS,
          title = "Stripped Debug Symbols and SourceFile Directives",
          severity = Severity.LOW,
          confidence = Confidence.MEDIUM,
          description = "Source code file attributes have been cleared or sanitized to generic dummy values, hindering reverse engineering and stack trace symbolication.",
          matchedPattern = "SourceFile: dummy / stripped",
          evidenceSnippet = "SourceFile directive sanitized",
          location = "classes.dex",
          mitreAttackId = "T1406",
          cweId = "CWE-656",
          remediation = "Ensure symbol files are submitted to internal crash reporting backends."
        )
      )
    }

    // ---------------------------------------------------------
    // CATEGORY 3: Suspicious Reflection & Dynamic Invocations
    // ---------------------------------------------------------

    val hasMethodInvoke = PATTERN_METHOD_INVOKE.matcher(dexContent).find()
    val hasClassForName = PATTERN_CLASS_FOR_NAME.matcher(dexContent).find()

    // OS Command Execution via Reflection / Runtime
    val hasShellCmd = PATTERN_SHELL_CMD.matcher(dexContent).find()
    if ((hasMethodInvoke || hasClassForName) && (PATTERN_RUNTIME_EXEC.matcher(dexContent).find() || hasShellCmd) ||
      dexContent.contains("Runtime.getRuntime().exec") || dexContent.contains("/system/bin/sh") || dexContent.contains("/system/xbin/su") ||
      (hasShellCmd && (dexContent.contains("Runtime") || dexContent.contains("ProcessBuilder")))
    ) {
      findings.add(
        HeuristicFinding(
          ruleId = "HEUR-REFL-SHELL-EXEC",
          category = HeuristicCategory.SUSPICIOUS_REFLECTION,
          title = "Reflective Shell / Root Command Execution",
          severity = Severity.CRITICAL,
          confidence = Confidence.HIGH,
          description = "Application performs reflective or direct invocation of Runtime.exec() / ProcessBuilder targeting shell commands (/system/bin/sh, su). Frequently used by malware for privilege escalation or remote command control.",
          matchedPattern = "Runtime.getRuntime().exec / su",
          evidenceSnippet = "Bytecode invocation: Runtime.exec(\"/system/bin/sh\" or \"su\")",
          location = "classes.dex",
          mitreAttackId = "T1059 / T1629.001",
          cweId = "CWE-78",
          remediation = "Cease execution of arbitrary device shell commands. Utilize Android framework APIs exclusively."
        )
      )
    }

    // SystemProperties Sandbox Evasion
    if (PATTERN_SYSTEM_PROPERTIES.matcher(dexContent).find() ||
      dexContent.contains("android.os.SystemProperties") && (dexContent.contains("ro.kernel.qemu") || dexContent.contains("ro.build.fingerprint") || dexContent.contains("qemu"))
    ) {
      findings.add(
        HeuristicFinding(
          ruleId = "HEUR-REFL-SYSTEM-PROPERTIES-EVASION",
          category = HeuristicCategory.SUSPICIOUS_REFLECTION,
          title = "SystemProperties Access for Sandbox / Emulator Evasion",
          severity = Severity.HIGH,
          confidence = Confidence.HIGH,
          description = "Reflectively queries hidden android.os.SystemProperties for emulator indicators (ro.kernel.qemu, ro.build.flavor). Used by sophisticated trojans to halt malicious activity inside automated analysis sandboxes.",
          matchedPattern = "android.os.SystemProperties.get -> ro.kernel.qemu",
          evidenceSnippet = "android.os.SystemProperties.get(\"ro.kernel.qemu\")",
          location = "classes.dex",
          mitreAttackId = "T1497 / T1629.001",
          cweId = "CWE-470",
          remediation = "Use official public android.os.Build APIs. Avoid hidden framework reflection."
        )
      )
    }

    // Hidden API restriction bypass
    if (PATTERN_VM_RUNTIME_BYPASS.matcher(dexContent).find() || dexContent.contains("setHiddenApiExemptions")) {
      findings.add(
        HeuristicFinding(
          ruleId = "HEUR-REFL-HIDDEN-API-BYPASS",
          category = HeuristicCategory.SUSPICIOUS_REFLECTION,
          title = "Android Hidden API Restriction Bypass Vector",
          severity = Severity.HIGH,
          confidence = Confidence.HIGH,
          description = "Detected reflection stubs designed to subvert Android's non-SDK interface enforcement policy (e.g. setHiddenApiExemptions or unsealed reflection chains).",
          matchedPattern = "VMRuntime / setHiddenApiExemptions",
          evidenceSnippet = "Reflection call to dalvik.system.VMRuntime",
          location = "classes.dex",
          mitreAttackId = "T1629.001",
          cweId = "CWE-470",
          remediation = "Migrate to supported public Android SDK and Jetpack APIs."
        )
      )
    }

    // Telephony Identifier Reflection
    if (hasMethodInvoke && PATTERN_TELEPHONY_REFLECT.matcher(dexContent).find()) {
      findings.add(
        HeuristicFinding(
          ruleId = "HEUR-REFL-TELEPHONY-HARVEST",
          category = HeuristicCategory.SUSPICIOUS_REFLECTION,
          title = "Reflective Telephony & Device Identifier Extraction",
          severity = Severity.HIGH,
          confidence = Confidence.HIGH,
          description = "Application utilizes reflection to invoke TelephonyManager hardware methods (getDeviceId, getImei, getSubscriberId) to covertly harvest persistent hardware serials without triggering static lint warnings.",
          matchedPattern = "Method.invoke -> getDeviceId / getImei",
          evidenceSnippet = "Reflective resolution of TelephonyManager.getDeviceId()",
          location = "classes.dex",
          mitreAttackId = "T1412 / T1629.001",
          cweId = "CWE-200",
          remediation = "Use resettable Advertising IDs or App Set IDs instead of immutable hardware serials."
        )
      )
    }

    // General Dynamic Reflection
    if (hasMethodInvoke && hasClassForName && findings.none { it.category == HeuristicCategory.SUSPICIOUS_REFLECTION }) {
      findings.add(
        HeuristicFinding(
          ruleId = "HEUR-REFL-DYNAMIC-INVOCATION",
          category = HeuristicCategory.SUSPICIOUS_REFLECTION,
          title = "Unconstrained Dynamic Reflection Resolution",
          severity = Severity.MEDIUM,
          confidence = Confidence.MEDIUM,
          description = "Discovered dynamic resolution via Class.forName and Method.invoke with dynamic parameters. Obscures true runtime call graphs from static analysis tools.",
          matchedPattern = "Class.forName + Method.invoke",
          evidenceSnippet = "Dynamic reflection resolution stubs in bytecode",
          location = "classes.dex",
          mitreAttackId = "T1629.001",
          cweId = "CWE-470",
          remediation = "Adopt explicit typed interfaces and dependency injection."
        )
      )
    }

    val summary = computeSummary(findings, identifiedPacker)
    return HeuristicScanResult(findings = findings.distinctBy { it.ruleId }, summary = summary)
  }

  /**
   * Evaluates heuristics directly from predefined pattern lists (useful for benchmarks & unit testing).
   */
  fun evaluateHeuristics(
    scanId: String = "",
    dclPatterns: List<String> = emptyList(),
    obfuscationPatterns: List<String> = emptyList(),
    reflectionPatterns: List<String> = emptyList()
  ): HeuristicScanResult {
    val findings = mutableListOf<HeuristicFinding>()

    for (pattern in dclPatterns) {
      when {
        pattern.contains("DexClassLoader", ignoreCase = true) -> findings.add(
          HeuristicFinding(
            ruleId = "HEUR-DCL-DEXCLASSLOADER",
            category = HeuristicCategory.DYNAMIC_CODE_LOADING,
            title = "Dynamic Code Loading via DexClassLoader",
            severity = Severity.CRITICAL,
            confidence = Confidence.HIGH,
            description = "Application references DexClassLoader to dynamically load and execute external bytecode at runtime.",
            matchedPattern = "dalvik.system.DexClassLoader",
            evidenceSnippet = "Usage of DexClassLoader detected",
            location = "classes.dex",
            mitreAttackId = "T1407",
            cweId = "CWE-912",
            remediation = "Bundle all code statically in base APK."
          )
        )
        pattern.contains("InMemoryDex", ignoreCase = true) -> findings.add(
          HeuristicFinding(
            ruleId = "HEUR-DCL-INMEMORYDEX",
            category = HeuristicCategory.DYNAMIC_CODE_LOADING,
            title = "In-Memory Dynamic Bytecode Execution",
            severity = Severity.CRITICAL,
            confidence = Confidence.HIGH,
            description = "Application utilizes InMemoryDexClassLoader to execute Dalvik bytecode directly from memory buffers.",
            matchedPattern = "dalvik.system.InMemoryDexClassLoader",
            evidenceSnippet = "In-memory bytecode buffer execution",
            location = "classes.dex",
            mitreAttackId = "T1407",
            cweId = "CWE-912",
            remediation = "Remove in-memory bytecode loader."
          )
        )
        pattern.contains("PayloadDrop", ignoreCase = true) || pattern.contains(".dex in assets", ignoreCase = true) -> findings.add(
          HeuristicFinding(
            ruleId = "HEUR-DCL-PAYLOAD-DROP",
            category = HeuristicCategory.DYNAMIC_CODE_LOADING,
            title = "Executable Payload Dropper Vector",
            severity = Severity.HIGH,
            confidence = Confidence.HIGH,
            description = "Application drops or unpacks secondary DEX/JAR payload files into local private storage.",
            matchedPattern = "Secondary payload drop",
            evidenceSnippet = "Encrypted bytecode dropper in assets/",
            location = "assets/payload.dat",
            mitreAttackId = "T1407",
            cweId = "CWE-912",
            remediation = "Bundle all application logic in standard base APK."
          )
        )
      }
    }

    var identifiedPacker: String? = null
    for (pattern in obfuscationPatterns) {
      when {
        pattern.contains("Jiagu", ignoreCase = true) -> {
          identifiedPacker = "Qihoo 360 Jiagu Packer"
          findings.add(
            HeuristicFinding(
              ruleId = "HEUR-OBF-PACKER-JIAGU",
              category = HeuristicCategory.OBFUSCATION_PACKERS,
              title = "Packer Signature Detected: Qihoo 360 Jiagu",
              severity = Severity.CRITICAL,
              confidence = Confidence.HIGH,
              description = "Application is protected with Qihoo 360 Jiagu packer shell. Core DEX is encrypted and decrypted dynamically in memory.",
              matchedPattern = "libjiagu.so / com.qihoo.util",
              evidenceSnippet = "lib/arm64-v8a/libjiagu.so",
              location = "lib/arm64-v8a/libjiagu.so",
              mitreAttackId = "T1406",
              cweId = "CWE-656",
              remediation = "Provide transparent unpacked build for security compliance."
            )
          )
        }
        pattern.contains("SecShell", ignoreCase = true) || pattern.contains("Bangcle", ignoreCase = true) -> {
          identifiedPacker = "Bangcle / SecShell Protector"
          findings.add(
            HeuristicFinding(
              ruleId = "HEUR-OBF-PACKER-SECSHELL",
              category = HeuristicCategory.OBFUSCATION_PACKERS,
              title = "Packer Signature Detected: Bangcle SecShell",
              severity = Severity.CRITICAL,
              confidence = Confidence.HIGH,
              description = "Application is encased in Bangcle SecShell protection, encrypting classes.dex.",
              matchedPattern = "libsecmain.so",
              evidenceSnippet = "lib/armeabi-v7a/libsecmain.so",
              location = "lib/armeabi-v7a/libsecmain.so",
              mitreAttackId = "T1406",
              cweId = "CWE-656",
              remediation = "Provide unpacked build for security audit."
            )
          )
        }
        pattern.contains("ShortIdentifiers", ignoreCase = true) || pattern.contains("Mangling", ignoreCase = true) -> {
          findings.add(
            HeuristicFinding(
              ruleId = "HEUR-OBF-SHORT-IDENTIFIERS",
              category = HeuristicCategory.OBFUSCATION_PACKERS,
              title = "Aggressive Class/Package Identifier Mangling",
              severity = Severity.LOW,
              confidence = Confidence.HIGH,
              description = "High proportion of single/two-character class and package names indicating symbol obfuscation.",
              matchedPattern = "Short identifier mangling (a.a, b.c)",
              evidenceSnippet = "Flattened class hierarchy: a.b.c",
              location = "classes.dex",
              mitreAttackId = "T1406",
              cweId = "CWE-656",
              remediation = "Retain mapping files for authorized auditing."
            )
          )
        }
        pattern.contains("StrippedDebug", ignoreCase = true) -> {
          findings.add(
            HeuristicFinding(
              ruleId = "HEUR-OBF-STRIPPED-DEBUG",
              category = HeuristicCategory.OBFUSCATION_PACKERS,
              title = "Stripped Debug Symbols and SourceFile Directives",
              severity = Severity.LOW,
              confidence = Confidence.MEDIUM,
              description = "Source code file attributes sanitized to generic dummy values.",
              matchedPattern = "SourceFile sanitized",
              evidenceSnippet = "Omitted SourceFile and line numbers",
              location = "classes.dex",
              mitreAttackId = "T1406",
              cweId = "CWE-656",
              remediation = "Submit symbol files to authorized symbol server."
            )
          )
        }
      }
    }

    for (pattern in reflectionPatterns) {
      when {
        pattern.contains("Exec", ignoreCase = true) || pattern.contains("Root", ignoreCase = true) -> findings.add(
          HeuristicFinding(
            ruleId = "HEUR-REFL-SHELL-EXEC",
            category = HeuristicCategory.SUSPICIOUS_REFLECTION,
            title = "Reflective Shell / Root Command Execution",
            severity = Severity.CRITICAL,
            confidence = Confidence.HIGH,
            description = "Application performs reflective invocation of Runtime.exec() targeting root or shell execution (/system/bin/sh, su).",
            matchedPattern = "Runtime.getRuntime().exec(\"su\")",
            evidenceSnippet = "Reflective call to Runtime.exec(\"su\")",
            location = "classes.dex",
            mitreAttackId = "T1059 / T1629.001",
            cweId = "CWE-78",
            remediation = "Cease execution of arbitrary device shell commands."
          )
        )
        pattern.contains("SystemProperties", ignoreCase = true) || pattern.contains("Sandbox", ignoreCase = true) -> findings.add(
          HeuristicFinding(
            ruleId = "HEUR-REFL-SYSTEM-PROPERTIES-EVASION",
            category = HeuristicCategory.SUSPICIOUS_REFLECTION,
            title = "SystemProperties Access for Sandbox / Emulator Evasion",
            severity = Severity.HIGH,
            confidence = Confidence.HIGH,
            description = "Reflectively queries hidden android.os.SystemProperties to detect analysis sandboxes and emulators.",
            matchedPattern = "android.os.SystemProperties.get",
            evidenceSnippet = "SystemProperties.get(\"ro.kernel.qemu\")",
            location = "classes.dex",
            mitreAttackId = "T1497 / T1629.001",
            cweId = "CWE-470",
            remediation = "Use official public android.os.Build APIs."
          )
        )
        pattern.contains("Telephony", ignoreCase = true) || pattern.contains("Imei", ignoreCase = true) -> findings.add(
          HeuristicFinding(
            ruleId = "HEUR-REFL-TELEPHONY-HARVEST",
            category = HeuristicCategory.SUSPICIOUS_REFLECTION,
            title = "Reflective Telephony & Device Identifier Extraction",
            severity = Severity.HIGH,
            confidence = Confidence.HIGH,
            description = "Reflectively queries TelephonyManager to extract device serial numbers (IMEI, IMSI).",
            matchedPattern = "Method.invoke -> getDeviceId",
            evidenceSnippet = "Reflective access to TelephonyManager.getDeviceId()",
            location = "classes.dex",
            mitreAttackId = "T1412 / T1629.001",
            cweId = "CWE-200",
            remediation = "Use resettable Advertising IDs instead."
          )
        )
      }
    }

    val summary = computeSummary(findings, identifiedPacker)
    return HeuristicScanResult(findings = findings.distinctBy { it.ruleId }, summary = summary)
  }

  private fun computeSummary(
    findings: List<HeuristicFinding>,
    identifiedPacker: String?
  ): HeuristicAnalysisSummary {
    val dclCount = findings.count { it.category == HeuristicCategory.DYNAMIC_CODE_LOADING }
    val obfCount = findings.count { it.category == HeuristicCategory.OBFUSCATION_PACKERS }
    val reflCount = findings.count { it.category == HeuristicCategory.SUSPICIOUS_REFLECTION }

    val highestSeverity = when {
      findings.any { it.severity == Severity.CRITICAL } -> Severity.CRITICAL
      findings.any { it.severity == Severity.HIGH } -> Severity.HIGH
      findings.any { it.severity == Severity.MEDIUM } -> Severity.MEDIUM
      findings.any { it.severity == Severity.LOW } -> Severity.LOW
      else -> Severity.INFO
    }

    val riskContribution = (dclCount * 25) + (if (identifiedPacker != null) 20 else obfCount * 5) + (reflCount * 15)

    return HeuristicAnalysisSummary(
      totalHeuristicFindings = findings.size,
      dclCount = dclCount,
      obfuscationCount = obfCount,
      reflectionCount = reflCount,
      highestSeverity = highestSeverity,
      packerIdentified = identifiedPacker,
      hasDynamicLoading = dclCount > 0,
      hasSuspiciousReflection = reflCount > 0,
      riskContributionScore = riskContribution.coerceIn(0, 50)
    )
  }
}
