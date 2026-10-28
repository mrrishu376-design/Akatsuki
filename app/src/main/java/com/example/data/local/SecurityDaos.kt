package com.example.data.local

import androidx.room.Dao
import androidx.room.Delete
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query
import androidx.room.Update
import com.example.data.model.AuthUser
import com.example.data.model.ForensicReport
import com.example.data.model.ScanFinding
import com.example.data.model.ScanRecord
import kotlinx.coroutines.flow.Flow

@Dao
interface UserDao {
  @Query("SELECT * FROM users WHERE email = :email LIMIT 1")
  suspend fun getUserByEmail(email: String): AuthUser?

  @Query("SELECT * FROM users WHERE id = :id LIMIT 1")
  suspend fun getUserById(id: String): AuthUser?

  @Insert(onConflict = OnConflictStrategy.REPLACE)
  suspend fun insertUser(user: AuthUser)
}

@Dao
interface ScanDao {
  @Query("SELECT * FROM scans ORDER BY createdAt DESC")
  fun getAllScans(): Flow<List<ScanRecord>>

  @Query("SELECT * FROM scans WHERE ownerId = :ownerId ORDER BY createdAt DESC")
  fun getScansByOwner(ownerId: String): Flow<List<ScanRecord>>

  @Query("SELECT * FROM scans WHERE id = :scanId LIMIT 1")
  suspend fun getScanById(scanId: String): ScanRecord?

  @Insert(onConflict = OnConflictStrategy.REPLACE)
  suspend fun insertScan(scan: ScanRecord)

  @Update
  suspend fun updateScan(scan: ScanRecord)

  @Query("DELETE FROM scans WHERE id = :scanId")
  suspend fun deleteScanById(scanId: String)
}

@Dao
interface FindingDao {
  @Query("SELECT * FROM scan_findings WHERE scanId = :scanId")
  fun getFindingsForScan(scanId: String): Flow<List<ScanFinding>>

  @Query("SELECT * FROM scan_findings WHERE scanId = :scanId")
  suspend fun getFindingsListForScan(scanId: String): List<ScanFinding>

  @Insert(onConflict = OnConflictStrategy.REPLACE)
  suspend fun insertFindings(findings: List<ScanFinding>)

  @Query("DELETE FROM scan_findings WHERE scanId = :scanId")
  suspend fun deleteFindingsForScan(scanId: String)
}

@Dao
interface ReportDao {
  @Query("SELECT * FROM forensic_reports WHERE scanId = :scanId LIMIT 1")
  suspend fun getReportByScanId(scanId: String): ForensicReport?

  @Query("SELECT * FROM forensic_reports WHERE id = :reportId LIMIT 1")
  suspend fun getReportById(reportId: String): ForensicReport?

  @Insert(onConflict = OnConflictStrategy.REPLACE)
  suspend fun insertReport(report: ForensicReport)
}
