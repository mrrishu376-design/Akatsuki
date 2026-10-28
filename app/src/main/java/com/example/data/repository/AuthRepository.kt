package com.example.data.repository

import android.content.Context
import com.example.data.local.AppDatabase
import com.example.data.model.AuthUser
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import java.util.UUID

class AuthRepository(context: Context) {
  private val userDao = AppDatabase.getDatabase(context).userDao()

  private val _currentUser = MutableStateFlow<AuthUser?>(null)
  val currentUser: StateFlow<AuthUser?> = _currentUser.asStateFlow()

  // Cloud backend settings
  var supabaseUrl: String = "https://your-project.supabase.co"
  var supabaseAnonKey: String = "sb_publishable_anon_key_placeholder"
  var apiBaseUrl: String = "https://ps02-forensics-api.onrender.com"

  init {
    // Default SecOps profile for seamless evaluation
    val defaultUser = AuthUser(
      id = "usr_secops_lead_01",
      email = "analyst@cyberdefense.org",
      fullName = "Alex Mercer",
      role = "Senior Forensic Auditor",
      organization = "Cyber Defense & Threat Intelligence"
    )
    _currentUser.value = defaultUser
  }

  suspend fun login(email: String, fullName: String = ""): Result<AuthUser> {
    if (email.isBlank() || !email.contains("@")) {
      return Result.failure(IllegalArgumentException("Please enter a valid cybersecurity auditor email address."))
    }

    val existing = userDao.getUserByEmail(email)
    val user = if (existing != null) {
      existing
    } else {
      val newUser = AuthUser(
        id = UUID.randomUUID().toString(),
        email = email.trim(),
        fullName = if (fullName.isNotBlank()) fullName.trim() else email.substringBefore("@").replace(".", " ").capitalize(),
        role = "Forensic Analyst",
        organization = "Security Operations Center"
      )
      userDao.insertUser(newUser)
      newUser
    }
    _currentUser.value = user
    return Result.success(user)
  }

  suspend fun signup(email: String, fullName: String, role: String, organization: String): Result<AuthUser> {
    if (email.isBlank() || !email.contains("@")) {
      return Result.failure(IllegalArgumentException("Please enter a valid email address."))
    }
    if (fullName.isBlank()) {
      return Result.failure(IllegalArgumentException("Full name cannot be empty."))
    }

    val newUser = AuthUser(
      id = UUID.randomUUID().toString(),
      email = email.trim(),
      fullName = fullName.trim(),
      role = if (role.isNotBlank()) role.trim() else "Forensic Analyst",
      organization = if (organization.isNotBlank()) organization.trim() else "SecOps Lab"
    )
    userDao.insertUser(newUser)
    _currentUser.value = newUser
    return Result.success(newUser)
  }

  fun logout() {
    _currentUser.value = null
  }
}
