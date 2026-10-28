package com.example.data.local

import android.content.Context
import androidx.room.Database
import androidx.room.Room
import androidx.room.RoomDatabase
import androidx.room.TypeConverters
import com.example.data.model.AuthUser
import com.example.data.model.ForensicReport
import com.example.data.model.ScanFinding
import com.example.data.model.ScanRecord

@Database(
  entities = [AuthUser::class, ScanRecord::class, ScanFinding::class, ForensicReport::class],
  version = 1,
  exportSchema = false
)
@TypeConverters(Converters::class)
abstract class AppDatabase : RoomDatabase() {
  abstract fun userDao(): UserDao
  abstract fun scanDao(): ScanDao
  abstract fun findingDao(): FindingDao
  abstract fun reportDao(): ReportDao

  companion object {
    @Volatile
    private var INSTANCE: AppDatabase? = null

    fun getDatabase(context: Context): AppDatabase {
      return INSTANCE ?: synchronized(this) {
        val instance = Room.databaseBuilder(
          context.applicationContext,
          AppDatabase::class.java,
          "ps02_forensics_db"
        ).fallbackToDestructiveMigration().build()
        INSTANCE = instance
        instance
      }
    }
  }
}
