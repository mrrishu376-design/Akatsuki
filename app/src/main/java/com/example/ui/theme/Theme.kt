package com.example.ui.theme

import android.os.Build
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color

private val EnterpriseLightColorScheme = lightColorScheme(
  primary = ConsoleBluePrimary,
  onPrimary = Color.White,
  primaryContainer = ConsoleBlueBg,
  onPrimaryContainer = ConsoleBlueHover,
  secondary = ConsoleNavy,
  onSecondary = Color.White,
  secondaryContainer = Color(0xFFF1F5F9),
  onSecondaryContainer = ConsoleNavy,
  tertiary = SeverityHigh,
  background = Color.White,
  onBackground = Slate900,
  surface = Color.White,
  onSurface = Slate900,
  surfaceVariant = ConsoleCanvas,
  onSurfaceVariant = Slate700,
  outline = ConsoleBorder,
  outlineVariant = ConsoleBorderStrong,
  error = SeverityCritical,
  onError = Color.White
)

private val EnterpriseDarkColorScheme = darkColorScheme(
  primary = Color(0xFF60A5FA),
  onPrimary = ConsoleNavy,
  primaryContainer = ConsoleNavySurface,
  onPrimaryContainer = Color(0xFFDBEAFE),
  secondary = Color(0xFF93C5FD),
  onSecondary = ConsoleNavy,
  secondaryContainer = Color(0xFF1E293B),
  onSecondaryContainer = Color.White,
  tertiary = SeverityHigh,
  background = ConsoleNavy,
  onBackground = Color(0xFFF8FAFC),
  surface = ConsoleNavySurface,
  onSurface = Color(0xFFF1F5F9),
  surfaceVariant = Color(0xFF1E293B),
  onSurfaceVariant = Color(0xFFCBD5E1),
  outline = Color(0xFF334155),
  error = SeverityCritical,
  onError = Color.White
)

@Composable
fun MyApplicationTheme(
  darkTheme: Boolean = isSystemInDarkTheme(),
  dynamicColor: Boolean = false,
  content: @Composable () -> Unit,
) {
  // Use clean Enterprise Security Console light palette by default
  val colorScheme = if (darkTheme) EnterpriseDarkColorScheme else EnterpriseLightColorScheme

  MaterialTheme(
    colorScheme = colorScheme,
    typography = Typography,
    content = content
  )
}
