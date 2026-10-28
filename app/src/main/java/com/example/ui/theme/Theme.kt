package com.example.ui.theme

import android.os.Build
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color

private val DarkColorScheme = darkColorScheme(
  primary = CyberBlueLight,
  onPrimary = CyberNavy,
  primaryContainer = CyberBlueDark,
  onPrimaryContainer = Color.White,
  secondary = CyberAccentCyan,
  onSecondary = CyberNavy,
  secondaryContainer = Color(0xFF0F3254),
  onSecondaryContainer = Color(0xFFBAE6FD),
  tertiary = Color(0xFF38BDF8),
  background = CyberNavy,
  onBackground = Color(0xFFE2E8F0),
  surface = CyberNavySurface,
  onSurface = Color(0xFFF1F5F9),
  surfaceVariant = Slate800,
  onSurfaceVariant = Slate300,
  outline = Color(0xFF334E68),
  error = SeverityCritical,
  onError = Color.White
)

private val LightColorScheme = lightColorScheme(
  primary = CyberBluePrimary,
  onPrimary = Color.White,
  primaryContainer = Color(0xFFE0F2FE),
  onPrimaryContainer = CyberBlueDark,
  secondary = Color(0xFF0369A1),
  onSecondary = Color.White,
  secondaryContainer = Color(0xFFBAE6FD),
  onSecondaryContainer = Color(0xFF0C4A6E),
  tertiary = Color(0xFF0284C7),
  background = Slate50,
  onBackground = Slate900,
  surface = Color.White,
  onSurface = Slate900,
  surfaceVariant = Color(0xFFF0F9FF),
  onSurfaceVariant = Slate700,
  outline = Slate300,
  error = SeverityCritical,
  onError = Color.White
)

@Composable
fun MyApplicationTheme(
  darkTheme: Boolean = isSystemInDarkTheme(),
  dynamicColor: Boolean = false, // Use our cybersecurity palette
  content: @Composable () -> Unit,
) {
  val colorScheme = if (darkTheme) DarkColorScheme else LightColorScheme

  MaterialTheme(
    colorScheme = colorScheme,
    typography = Typography,
    content = content
  )
}
