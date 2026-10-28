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
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Business
import androidx.compose.material.icons.filled.Email
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.Person
import androidx.compose.material.icons.filled.Security
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Tab
import androidx.compose.material3.TabRow
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.example.ui.MainViewModel
import com.example.ui.theme.CyberAccentCyan
import com.example.ui.theme.CyberBlueDark
import com.example.ui.theme.CyberBluePrimary
import com.example.ui.theme.CyberNavy
import com.example.ui.theme.Slate200
import com.example.ui.theme.Slate600
import com.example.ui.theme.Slate800

import androidx.compose.runtime.collectAsState

@Composable
fun AuthScreen(viewModel: MainViewModel) {
  var selectedTab by remember { mutableIntStateOf(0) } // 0 = Login, 1 = Signup

  var email by remember { mutableStateOf("analyst@cyberdefense.org") }
  var password by remember { mutableStateOf("••••••••••••") }
  var fullName by remember { mutableStateOf("Alex Mercer") }
  var role by remember { mutableStateOf("Senior Forensic Auditor") }
  var organization by remember { mutableStateOf("Cyber Defense & Threat Intelligence") }

  val errorMessage by viewModel.errorMessage.collectAsState()

  Box(
    modifier = Modifier
      .fillMaxSize()
      .background(MaterialTheme.colorScheme.background)
  ) {
    Column(
      modifier = Modifier
        .fillMaxSize()
        .verticalScroll(rememberScrollState())
        .padding(24.dp),
      horizontalAlignment = Alignment.CenterHorizontally,
      verticalArrangement = Arrangement.Center
    ) {
      Spacer(modifier = Modifier.height(24.dp))

      // Shield Logo & Platform Title
      Box(
        modifier = Modifier
          .size(64.dp)
          .clip(RoundedCornerShape(16.dp))
          .background(
            Brush.linearGradient(
              colors = listOf(CyberBluePrimary, CyberBlueDark)
            )
          ),
        contentAlignment = Alignment.Center
      ) {
        Icon(
          imageVector = Icons.Default.Shield,
          contentDescription = "PS-02 Security Platform",
          tint = Color.White,
          modifier = Modifier.size(36.dp)
        )
      }

      Spacer(modifier = Modifier.height(16.dp))

      Text(
        text = "PS-02 Android Forensic Platform",
        style = MaterialTheme.typography.titleLarge.copy(
          fontWeight = FontWeight.Bold,
          letterSpacing = 0.5.sp
        ),
        color = MaterialTheme.colorScheme.onBackground
      )

      Text(
        text = "Static Vulnerability & Evidence Analysis",
        style = MaterialTheme.typography.bodyMedium,
        color = Slate600
      )

      Spacer(modifier = Modifier.height(28.dp))

      Card(
        modifier = Modifier
          .fillMaxWidth()
          .clip(RoundedCornerShape(16.dp)),
        colors = CardDefaults.cardColors(
          containerColor = MaterialTheme.colorScheme.surface
        ),
        elevation = CardDefaults.cardElevation(defaultElevation = 2.dp)
      ) {
        Column(modifier = Modifier.padding(20.dp)) {
          TabRow(
            selectedTabIndex = selectedTab,
            containerColor = Color.Transparent,
            contentColor = CyberBluePrimary
          ) {
            Tab(
              selected = selectedTab == 0,
              onClick = { selectedTab = 0 },
              modifier = Modifier.testTag("tab_login"),
              text = { Text("Auditor Login", fontWeight = FontWeight.Bold) }
            )
            Tab(
              selected = selectedTab == 1,
              onClick = { selectedTab = 1 },
              modifier = Modifier.testTag("tab_signup"),
              text = { Text("Register", fontWeight = FontWeight.Bold) }
            )
          }

          Spacer(modifier = Modifier.height(20.dp))

          val currentError = errorMessage
          if (currentError != null) {
            Card(
              modifier = Modifier
                .fillMaxWidth()
                .padding(bottom = 16.dp),
              colors = CardDefaults.cardColors(containerColor = Color(0xFFFEE2E2))
            ) {
              Text(
                text = currentError,
                color = Color(0xFFDC2626),
                style = MaterialTheme.typography.bodySmall,
                modifier = Modifier.padding(12.dp)
              )
            }
          }

          if (selectedTab == 0) {
            // LOGIN FORM
            OutlinedTextField(
              value = email,
              onValueChange = { email = it },
              label = { Text("SecOps Email") },
              leadingIcon = { Icon(Icons.Default.Email, contentDescription = null, tint = CyberBluePrimary) },
              modifier = Modifier
                .fillMaxWidth()
                .testTag("input_login_email"),
              singleLine = true
            )

            Spacer(modifier = Modifier.height(14.dp))

            OutlinedTextField(
              value = password,
              onValueChange = { password = it },
              label = { Text("Password") },
              leadingIcon = { Icon(Icons.Default.Lock, contentDescription = null, tint = CyberBluePrimary) },
              visualTransformation = PasswordVisualTransformation(),
              modifier = Modifier
                .fillMaxWidth()
                .testTag("input_login_password"),
              singleLine = true
            )

            Spacer(modifier = Modifier.height(20.dp))

            Button(
              onClick = { viewModel.login(email, fullName) },
              modifier = Modifier
                .fillMaxWidth()
                .height(48.dp)
                .testTag("btn_submit_login"),
              colors = ButtonDefaults.buttonColors(containerColor = CyberBluePrimary),
              shape = RoundedCornerShape(10.dp)
            ) {
              Icon(Icons.Default.Security, contentDescription = null, modifier = Modifier.size(18.dp))
              Spacer(modifier = Modifier.width(8.dp))
              Text("Authenticate Session", fontWeight = FontWeight.Bold)
            }
          } else {
            // SIGNUP FORM
            OutlinedTextField(
              value = fullName,
              onValueChange = { fullName = it },
              label = { Text("Auditor Full Name") },
              leadingIcon = { Icon(Icons.Default.Person, contentDescription = null, tint = CyberBluePrimary) },
              modifier = Modifier
                .fillMaxWidth()
                .testTag("input_signup_name"),
              singleLine = true
            )

            Spacer(modifier = Modifier.height(12.dp))

            OutlinedTextField(
              value = email,
              onValueChange = { email = it },
              label = { Text("Work Email") },
              leadingIcon = { Icon(Icons.Default.Email, contentDescription = null, tint = CyberBluePrimary) },
              modifier = Modifier
                .fillMaxWidth()
                .testTag("input_signup_email"),
              singleLine = true
            )

            Spacer(modifier = Modifier.height(12.dp))

            OutlinedTextField(
              value = organization,
              onValueChange = { organization = it },
              label = { Text("Security Agency / Organization") },
              leadingIcon = { Icon(Icons.Default.Business, contentDescription = null, tint = CyberBluePrimary) },
              modifier = Modifier
                .fillMaxWidth()
                .testTag("input_signup_org"),
              singleLine = true
            )

            Spacer(modifier = Modifier.height(20.dp))

            Button(
              onClick = { viewModel.signup(email, fullName, role, organization) },
              modifier = Modifier
                .fillMaxWidth()
                .height(48.dp)
                .testTag("btn_submit_signup"),
              colors = ButtonDefaults.buttonColors(containerColor = CyberBluePrimary),
              shape = RoundedCornerShape(10.dp)
            ) {
              Text("Create Auditor Account", fontWeight = FontWeight.Bold)
            }
          }

          Spacer(modifier = Modifier.height(12.dp))

          Text(
            text = "Supabase Auth & Row Level Security (RLS) protected profile layer.",
            style = MaterialTheme.typography.bodySmall,
            color = Slate600,
            modifier = Modifier.align(Alignment.CenterHorizontally)
          )
        }
      }

      Spacer(modifier = Modifier.height(24.dp))
    }
  }
}
