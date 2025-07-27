#include "BanRequest.h"
#include "../Imports/Imports.h"

bool banHWID(const std::string& hwid) {
    sqlite3* db;
    int rc = sqlite3_open("auth_panel.db", &db);
    if (rc != SQLITE_OK) {
        return false;
    }

    // Enable Write-Ahead Logging (WAL) mode
    rc = sqlite3_exec(db, "PRAGMA journal_mode=WAL;", nullptr, nullptr, nullptr);
    if (rc != SQLITE_OK) {
        sqlite3_close(db);
        return false;
    }

    // Set busy timeout
    rc = sqlite3_busy_timeout(db, 5000); // Wait up to 5000 milliseconds
    if (rc != SQLITE_OK) {
        sqlite3_close(db);
        return false;
    }

    // Begin transaction
    rc = sqlite3_exec(db, "BEGIN TRANSACTION;", nullptr, nullptr, nullptr);
    if (rc != SQLITE_OK) {
        sqlite3_close(db);
        return false;
    }

    bool success = true;

    // Insert into banned_hwids (simplified as ban_date is automatic)
    std::string banSql = "INSERT INTO banned_hwids (hwid) VALUES (?);";
    sqlite3_stmt* banStmt = nullptr;

    rc = sqlite3_prepare_v2(db, banSql.c_str(), -1, &banStmt, nullptr);
    if (rc != SQLITE_OK) {
        sqlite3_exec(db, "ROLLBACK;", nullptr, nullptr, nullptr);
        sqlite3_close(db);
        return false;
    }

    rc = sqlite3_bind_text(banStmt, 1, hwid.c_str(), -1, SQLITE_STATIC);
    if (rc != SQLITE_OK) {
        sqlite3_finalize(banStmt);
        sqlite3_exec(db, "ROLLBACK;", nullptr, nullptr, nullptr);
        sqlite3_close(db);
        return false;
    }

    rc = sqlite3_step(banStmt);
    if (rc != SQLITE_DONE) {
        sqlite3_finalize(banStmt);
        sqlite3_exec(db, "ROLLBACK;", nullptr, nullptr, nullptr);
        sqlite3_close(db);
        return false;
    }

    sqlite3_finalize(banStmt);

    // Invalidate all keys associated with the HWID
    std::string invalidateSql = "UPDATE application_keys SET is_valid = 0 WHERE hwid = ?";
    sqlite3_stmt* invalidateStmt = nullptr;

    rc = sqlite3_prepare_v2(db, invalidateSql.c_str(), -1, &invalidateStmt, nullptr);
    if (rc != SQLITE_OK) {
        sqlite3_exec(db, "ROLLBACK;", nullptr, nullptr, nullptr);
        sqlite3_close(db);
        return false;
    }

    rc = sqlite3_bind_text(invalidateStmt, 1, hwid.c_str(), -1, SQLITE_STATIC);
    if (rc != SQLITE_OK) {
        sqlite3_finalize(invalidateStmt);
        sqlite3_exec(db, "ROLLBACK;", nullptr, nullptr, nullptr);
        sqlite3_close(db);
        return false;
    }

    rc = sqlite3_step(invalidateStmt);
    if (rc != SQLITE_DONE) {
        sqlite3_finalize(invalidateStmt);
        sqlite3_exec(db, "ROLLBACK;", nullptr, nullptr, nullptr);
        sqlite3_close(db);
        return false;
    }

    sqlite3_finalize(invalidateStmt);

    // Commit transaction
    rc = sqlite3_exec(db, "COMMIT;", nullptr, nullptr, nullptr);
    if (rc != SQLITE_OK) {
        sqlite3_exec(db, "ROLLBACK;", nullptr, nullptr, nullptr);
        sqlite3_close(db);
        return false;
    }

    sqlite3_close(db);
    return true;
}