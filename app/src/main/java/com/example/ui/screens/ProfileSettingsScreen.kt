package com.example.ui.screens

import androidx.compose.foundation.background
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
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.AccountCircle
import androidx.compose.material.icons.filled.Cloud
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.ExitToApp
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.Save
import androidx.compose.material.icons.filled.Security
import androidx.compose.material.icons.filled.Storage
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.example.ui.MainViewModel
import com.example.ui.components.CyberTopAppBar
import com.example.ui.navigation.Screen
import com.example.ui.theme.CyberAccentCyan
import com.example.ui.theme.CyberBlueDark
import com.example.ui.theme.CyberBluePrimary
import com.example.ui.theme.RiskSafeGreen
import com.example.ui.theme.SeverityCritical
import com.example.ui.theme.Slate200
import com.example.ui.theme.Slate600
import com.example.ui.theme.Slate800

@Composable
fun ProfileSettingsScreen(viewModel: MainViewModel) {
  val clipboardManager = LocalClipboardManager.current
  val user by viewModel.currentUser.collectAsState()

  var supabaseUrl by remember { mutableStateOf(viewModel.authRepo.supabaseUrl) }
  var supabaseKey by remember { mutableStateOf(viewModel.authRepo.supabaseAnonKey) }
  var apiBaseUrl by remember { mutableStateOf(viewModel.authRepo.apiBaseUrl) }
  var showSqlSchema by remember { mutableStateOf(false) }
  var saveSuccessMessage by remember { mutableStateOf(false) }

  val sqlSchemaDefinition = """
-- PS-02 POSTGRESQL & ROW LEVEL SECURITY (RLS) SCHEMA

-- 1. Profiles Table
CREATE TABLE IF NOT EXISTS public.profiles (
    id UUID PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
    email TEXT NOT NULL,
    full_name TEXT NOT NULL,
    role TEXT DEFAULT 'Forensic Analyst',
    organization TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW()
);
ALTER TABLE public.profiles ENABLE ROW LEVEL SECURITY;
CREATE POLICY "Users read own profile" ON public.profiles FOR SELECT USING (auth.uid() = id);
CREATE POLICY "Users update own profile" ON public.profiles FOR UPDATE USING (auth.uid() = id);

-- 2. Scans Table
CREATE TABLE IF NOT EXISTS public.scans (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    owner_id UUID NOT NULL REFERENCES public.profiles(id) ON DELETE CASCADE,
    app_name TEXT NOT NULL,
    package_name TEXT NOT NULL,
    version_name TEXT,
    version_code BIGINT,
    original_filename TEXT NOT NULL,
    file_size_bytes BIGINT NOT NULL,
    sha256_hash TEXT NOT NULL,
    md5_hash TEXT,
    status TEXT NOT NULL DEFAULT 'COMPLETED',
    risk_score INT CHECK (risk_score >= 0 AND risk_score <= 100),
    risk_label TEXT NOT NULL,
    critical_count INT DEFAULT 0,
    high_count INT DEFAULT 0,
    medium_count INT DEFAULT 0,
    low_count INT DEFAULT 0,
    permissions_count INT DEFAULT 0,
    exported_components_count INT DEFAULT 0,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    completed_at TIMESTAMPTZ DEFAULT NOW()
);
ALTER TABLE public.scans ENABLE ROW LEVEL SECURITY;
CREATE POLICY "Users read own scans" ON public.scans FOR SELECT USING (auth.uid() = owner_id);

-- 3. Scan Findings Table
CREATE TABLE IF NOT EXISTS public.scan_findings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id UUID NOT NULL REFERENCES public.scans(id) ON DELETE CASCADE,
    rule_id TEXT NOT NULL,
    category TEXT NOT NULL,
    title TEXT NOT NULL,
    severity TEXT NOT NULL,
    description TEXT NOT NULL,
    evidence TEXT,
    recommendation TEXT,
    cwe_id TEXT
);
ALTER TABLE public.scan_findings ENABLE ROW LEVEL SECURITY;
CREATE POLICY "Users read findings of own scans" ON public.scan_findings FOR SELECT
USING (EXISTS (SELECT 1 FROM public.scans WHERE public.scans.id = scan_findings.scan_id AND public.scans.owner_id = auth.uid()));

-- 4. Forensic Reports Table
CREATE TABLE IF NOT EXISTS public.forensic_reports (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id UUID NOT NULL REFERENCES public.scans(id) ON DELETE CASCADE,
    owner_id UUID NOT NULL REFERENCES public.profiles(id) ON DELETE CASCADE,
    report_title TEXT NOT NULL,
    generated_at TIMESTAMPTZ DEFAULT NOW(),
    analyst_name TEXT NOT NULL,
    tool_version TEXT NOT NULL,
    risk_score INT NOT NULL,
    risk_label TEXT NOT NULL,
    executive_summary TEXT NOT NULL,
    methodology TEXT NOT NULL,
    limitations_disclaimer TEXT NOT NULL
);
ALTER TABLE public.forensic_reports ENABLE ROW LEVEL SECURITY;
CREATE POLICY "Users read own forensic reports" ON public.forensic_reports FOR SELECT USING (auth.uid() = owner_id);
""".trimIndent()

  Scaffold(
    topBar = {
      CyberTopAppBar(
        title = "Auditor & System Settings",
        subtitle = "Profiles, Keys & Cloud Database",
        showBack = true,
        onBackClick = { viewModel.navigateTo(Screen.DASHBOARD) }
      )
    }
  ) { innerPadding ->
    Column(
      modifier = Modifier
        .fillMaxSize()
        .padding(innerPadding)
        .padding(16.dp)
        .verticalScroll(rememberScrollState()),
      verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
      // AUDITOR PROFILE CARD
      Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
        shape = RoundedCornerShape(14.dp),
        elevation = CardDefaults.cardElevation(defaultElevation = 2.dp)
      ) {
        Column(modifier = Modifier.padding(18.dp)) {
          Row(verticalAlignment = Alignment.CenterVertically) {
            Box(
              modifier = Modifier
                .size(52.dp)
                .clip(CircleShape)
                .background(CyberBluePrimary.copy(alpha = 0.12f)),
              contentAlignment = Alignment.Center
            ) {
              Icon(Icons.Default.AccountCircle, contentDescription = null, tint = CyberBluePrimary, modifier = Modifier.size(36.dp))
            }
            Spacer(modifier = Modifier.width(14.dp))
            Column {
              Text(
                text = user?.fullName ?: "SecOps Auditor",
                style = MaterialTheme.typography.titleMedium.copy(fontWeight = FontWeight.Bold),
                color = MaterialTheme.colorScheme.onSurface
              )
              Text(
                text = "${user?.role ?: "Forensic Analyst"} • ${user?.organization ?: "Cyber Defense Lab"}",
                style = MaterialTheme.typography.bodySmall,
                color = Slate600
              )
              Text(
                text = user?.email ?: "analyst@cyberdefense.org",
                style = MaterialTheme.typography.labelSmall.copy(fontFamily = FontFamily.Monospace),
                color = CyberBlueDark
              )
            }
          }

          Spacer(modifier = Modifier.height(14.dp))
          HorizontalDivider(color = Color(0xFFE2E8F0))
          Spacer(modifier = Modifier.height(10.dp))

          OutlinedButton(
            onClick = { viewModel.logout() },
            modifier = Modifier
              .fillMaxWidth()
              .testTag("btn_logout_auditor"),
            shape = RoundedCornerShape(8.dp)
          ) {
            Icon(Icons.Default.ExitToApp, contentDescription = null, tint = SeverityCritical)
            Spacer(modifier = Modifier.width(8.dp))
            Text("Switch Auditor Account / Sign Out", color = SeverityCritical, fontWeight = FontWeight.Bold)
          }
        }
      }

      // CLOUD BACKEND INTEGRATION SETTINGS (SUPABASE & FASTAPI)
      Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
        shape = RoundedCornerShape(14.dp),
        elevation = CardDefaults.cardElevation(defaultElevation = 2.dp)
      ) {
        Column(modifier = Modifier.padding(18.dp)) {
          Row(verticalAlignment = Alignment.CenterVertically) {
            Icon(Icons.Default.Cloud, contentDescription = null, tint = CyberBluePrimary)
            Spacer(modifier = Modifier.width(10.dp))
            Text(
              text = "Cloud Backend & API Configuration",
              style = MaterialTheme.typography.titleSmall.copy(fontWeight = FontWeight.Bold),
              color = MaterialTheme.colorScheme.onSurface
            )
          }

          Spacer(modifier = Modifier.height(6.dp))
          Text(
            text = "Configure your Supabase PostgreSQL and FastAPI service endpoints for remote synchronization:",
            style = MaterialTheme.typography.bodySmall,
            color = Slate600
          )

          Spacer(modifier = Modifier.height(14.dp))

          OutlinedTextField(
            value = supabaseUrl,
            onValueChange = { supabaseUrl = it },
            label = { Text("NEXT_PUBLIC_SUPABASE_URL") },
            modifier = Modifier
              .fillMaxWidth()
              .testTag("input_supabase_url"),
            singleLine = true
          )

          Spacer(modifier = Modifier.height(10.dp))

          OutlinedTextField(
            value = supabaseKey,
            onValueChange = { supabaseKey = it },
            label = { Text("NEXT_PUBLIC_SUPABASE_ANON_KEY") },
            modifier = Modifier
              .fillMaxWidth()
              .testTag("input_supabase_anon_key"),
            singleLine = true
          )

          Spacer(modifier = Modifier.height(10.dp))

          OutlinedTextField(
            value = apiBaseUrl,
            onValueChange = { apiBaseUrl = it },
            label = { Text("FASTAPI_API_BASE_URL (Render/Local)") },
            modifier = Modifier
              .fillMaxWidth()
              .testTag("input_api_base_url"),
            singleLine = true
          )

          Spacer(modifier = Modifier.height(16.dp))

          Button(
            onClick = {
              viewModel.saveCloudSettings(supabaseUrl, supabaseKey, apiBaseUrl)
              saveSuccessMessage = true
            },
            modifier = Modifier
              .fillMaxWidth()
              .testTag("btn_save_cloud_settings"),
            colors = ButtonDefaults.buttonColors(containerColor = CyberBluePrimary),
            shape = RoundedCornerShape(8.dp)
          ) {
            Icon(Icons.Default.Save, contentDescription = null, modifier = Modifier.size(16.dp))
            Spacer(modifier = Modifier.width(6.dp))
            Text("Save API & Cloud Configuration", fontWeight = FontWeight.Bold)
          }

          if (saveSuccessMessage) {
            Spacer(modifier = Modifier.height(8.dp))
            Text(
              text = "Configuration updated successfully.",
              style = MaterialTheme.typography.labelSmall.copy(fontWeight = FontWeight.Bold),
              color = RiskSafeGreen
            )
          }
        }
      }

      // POSTGRESQL & ROW LEVEL SECURITY SCHEMA VIEWER
      Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
        shape = RoundedCornerShape(14.dp)
      ) {
        Column(modifier = Modifier.padding(18.dp)) {
          Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
          ) {
            Row(verticalAlignment = Alignment.CenterVertically) {
              Icon(Icons.Default.Storage, contentDescription = null, tint = CyberBluePrimary)
              Spacer(modifier = Modifier.width(10.dp))
              Text(
                text = "PostgreSQL & RLS Blueprint",
                style = MaterialTheme.typography.titleSmall.copy(fontWeight = FontWeight.Bold),
                color = MaterialTheme.colorScheme.onSurface
              )
            }

            TextButton(onClick = { showSqlSchema = !showSqlSchema }) {
              Text(if (showSqlSchema) "Hide SQL" else "View SQL", fontWeight = FontWeight.Bold)
            }
          }

          Text(
            text = "Production schema with foreign keys, constraints, and Row Level Security isolation policies for multi-tenant security.",
            style = MaterialTheme.typography.bodySmall,
            color = Slate600
          )

          if (showSqlSchema) {
            Spacer(modifier = Modifier.height(10.dp))
            Surface(
              modifier = Modifier.fillMaxWidth(),
              color = Color(0xFF0F172A),
              shape = RoundedCornerShape(8.dp)
            ) {
              Column(modifier = Modifier.padding(12.dp)) {
                Row(
                  modifier = Modifier.fillMaxWidth(),
                  horizontalArrangement = Arrangement.End
                ) {
                  Button(
                    onClick = { clipboardManager.setText(AnnotatedString(sqlSchemaDefinition)) },
                    colors = ButtonDefaults.buttonColors(containerColor = CyberBluePrimary),
                    shape = RoundedCornerShape(6.dp)
                  ) {
                    Icon(Icons.Default.ContentCopy, contentDescription = null, modifier = Modifier.size(14.dp))
                    Spacer(modifier = Modifier.width(4.dp))
                    Text("Copy SQL", fontSize = 11.sp)
                  }
                }
                Spacer(modifier = Modifier.height(6.dp))
                Text(
                  text = sqlSchemaDefinition,
                  style = MaterialTheme.typography.bodySmall.copy(
                    fontFamily = FontFamily.Monospace,
                    fontSize = 10.sp,
                    lineHeight = 15.sp
                  ),
                  color = Color(0xFF38BDF8)
                )
              }
            }
          }
        }
      }

      Spacer(modifier = Modifier.height(20.dp))
    }
  }
}
