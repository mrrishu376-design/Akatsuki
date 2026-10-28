package com.example.data.local

import androidx.room.TypeConverter
import com.example.data.model.RiskLabel
import com.example.data.model.ScanStatus
import com.example.data.model.Severity

class Converters {
  @TypeConverter
  fun fromSeverity(value: Severity): String = value.name

  @TypeConverter
  fun toSeverity(value: String): Severity = runCatching { Severity.valueOf(value) }.getOrDefault(Severity.INFO)

  @TypeConverter
  fun fromScanStatus(value: ScanStatus): String = value.name

  @TypeConverter
  fun toScanStatus(value: String): ScanStatus = runCatching { ScanStatus.valueOf(value) }.getOrDefault(ScanStatus.COMPLETED)

  @TypeConverter
  fun fromRiskLabel(value: RiskLabel): String = value.name

  @TypeConverter
  fun toRiskLabel(value: String): RiskLabel = runCatching { RiskLabel.valueOf(value) }.getOrDefault(RiskLabel.SAFE)
}
