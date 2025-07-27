#include "CheckKey.h"

int applicationId = -1;   // Define with default value

std::string checkKeyInAllTables(const std::string& key, const std::string& hashedHwid) {
    // Reset values at start
    ValidKey = false;
    applicationId = -1;

    sqlite3* db;
    int rc = sqlite3_open("auth_panel.db", &db);
    if (rc != SQLITE_OK) {
        return "Database error";
    }

    // Begin transaction
    rc = sqlite3_exec(db, "BEGIN TRANSACTION;", nullptr, nullptr, nullptr);
    if (rc != SQLITE_OK) {
        sqlite3_close(db);
        return "Database error";
    }

    // First check if the HWID is banned
    std::string banCheckSql = "SELECT 1 FROM banned_hwids WHERE hwid = ?";
    sqlite3_stmt* banStmt = nullptr;

    rc = sqlite3_prepare_v2(db, banCheckSql.c_str(), -1, &banStmt, nullptr);
    if (rc == SQLITE_OK) {
        sqlite3_bind_text(banStmt, 1, hashedHwid.c_str(), -1, SQLITE_STATIC);
        if (sqlite3_step(banStmt) == SQLITE_ROW) {
            sqlite3_finalize(banStmt);

            std::string invalidateKeysSql = "UPDATE application_keys SET is_valid = 0 WHERE hwid = ?";
            sqlite3_stmt* invalidateStmt = nullptr;

            rc = sqlite3_prepare_v2(db, invalidateKeysSql.c_str(), -1, &invalidateStmt, nullptr);
            if (rc == SQLITE_OK) {
                sqlite3_bind_text(invalidateStmt, 1, hashedHwid.c_str(), -1, SQLITE_STATIC);
                sqlite3_step(invalidateStmt);
                sqlite3_finalize(invalidateStmt);
            }

            sqlite3_exec(db, "COMMIT;", nullptr, nullptr, nullptr);
            sqlite3_close(db);
            return "user is banned";
        }
        sqlite3_finalize(banStmt);
    }

    // Check if the key exists and is valid - NOW INCLUDING application_id
    std::string sql = "SELECT ak.is_valid, ak.first_use_date, ak.duration, ak.hwid, a.name, ak.application_id "
        "FROM application_keys ak "
        "JOIN applications a ON ak.application_id = a.id "
        "WHERE ak.key = ?";

    sqlite3_stmt* stmt = nullptr;
    rc = sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
        sqlite3_exec(db, "ROLLBACK;", nullptr, nullptr, nullptr);
        sqlite3_close(db);
        return "Database error";
    }

    rc = sqlite3_bind_text(stmt, 1, key.c_str(), -1, SQLITE_STATIC);
    if (rc != SQLITE_OK) {
        sqlite3_finalize(stmt);
        sqlite3_exec(db, "ROLLBACK;", nullptr, nullptr, nullptr);
        sqlite3_close(db);
        return "Database error";
    }

    if (sqlite3_step(stmt) != SQLITE_ROW) {
        sqlite3_finalize(stmt);
        sqlite3_exec(db, "COMMIT;", nullptr, nullptr, nullptr);
        sqlite3_close(db);
        return "key_invalid";
    }

    int isValid = sqlite3_column_int(stmt, 0);
    if (!isValid) {
        sqlite3_finalize(stmt);
        sqlite3_exec(db, "COMMIT;", nullptr, nullptr, nullptr);
        sqlite3_close(db);
        return "key_invalid";
    }

    const unsigned char* firstUseDate = sqlite3_column_text(stmt, 1);
    int duration = sqlite3_column_int(stmt, 2);
    const unsigned char* dbHwid = sqlite3_column_text(stmt, 3);
    const unsigned char* appName = sqlite3_column_text(stmt, 4);
    int applicationId = sqlite3_column_int(stmt, 5);  // GET APPLICATION_ID

    std::string appNameStr = (appName != nullptr) ? std::string(reinterpret_cast<const char*>(appName)) : "unknown";

    // Check if this is first use (no HWID or first use date)
    if (dbHwid == nullptr || firstUseDate == nullptr) {
        sqlite3_finalize(stmt);

        std::string updateSql = "UPDATE application_keys SET first_use_date = datetime('now'), hwid = ? WHERE key = ?";
        sqlite3_stmt* updateStmt = nullptr;

        rc = sqlite3_prepare_v2(db, updateSql.c_str(), -1, &updateStmt, nullptr);
        if (rc == SQLITE_OK) {
            sqlite3_bind_text(updateStmt, 1, hashedHwid.c_str(), -1, SQLITE_STATIC);
            sqlite3_bind_text(updateStmt, 2, key.c_str(), -1, SQLITE_STATIC);

            rc = sqlite3_step(updateStmt);
            sqlite3_finalize(updateStmt);

            if (rc == SQLITE_DONE) {
                sqlite3_exec(db, "COMMIT;", nullptr, nullptr, nullptr);
                sqlite3_close(db);
                ValidKey = true;                    // SET VALIDKEY
                ::applicationId = applicationId; // SET APPLICATION_ID
                return "valid_key for " + appNameStr;
            }
        }

        sqlite3_exec(db, "ROLLBACK;", nullptr, nullptr, nullptr);
        sqlite3_close(db);
        return "Database error";
    }

    // If HWID exists, check if it matches
    if (strcmp(reinterpret_cast<const char*>(dbHwid), hashedHwid.c_str()) != 0) {
        sqlite3_finalize(stmt);
        sqlite3_exec(db, "COMMIT;", nullptr, nullptr, nullptr);
        sqlite3_close(db);
        return "invalid HWID";
    }

    // Check if the key has expired
    std::string checkExpirySql = "SELECT datetime(?, '+' || ? || ' seconds') > datetime('now')";
    sqlite3_stmt* expiryStmt = nullptr;
    bool isExpired = true;

    rc = sqlite3_prepare_v2(db, checkExpirySql.c_str(), -1, &expiryStmt, nullptr);
    if (rc == SQLITE_OK) {
        sqlite3_bind_text(expiryStmt, 1, reinterpret_cast<const char*>(firstUseDate), -1, SQLITE_STATIC);
        sqlite3_bind_int(expiryStmt, 2, duration);

        if (sqlite3_step(expiryStmt) == SQLITE_ROW) {
            isExpired = (sqlite3_column_int(expiryStmt, 0) == 0);
        }
        sqlite3_finalize(expiryStmt);
    }

    sqlite3_finalize(stmt);

    if (!isExpired) {
        sqlite3_exec(db, "COMMIT;", nullptr, nullptr, nullptr);
        sqlite3_close(db);
        ValidKey = true;                    // SET VALIDKEY
        ::applicationId = applicationId; // SET APPLICATION_ID
        return "valid_key for " + appNameStr;
    }

    // Key has expired, invalidate it
    std::string invalidateSql = "UPDATE application_keys SET is_valid = 0 WHERE key = ?";
    sqlite3_stmt* invalidateStmt = nullptr;

    rc = sqlite3_prepare_v2(db, invalidateSql.c_str(), -1, &invalidateStmt, nullptr);
    if (rc == SQLITE_OK) {
        sqlite3_bind_text(invalidateStmt, 1, key.c_str(), -1, SQLITE_STATIC);
        sqlite3_step(invalidateStmt);
        sqlite3_finalize(invalidateStmt);
    }

    sqlite3_exec(db, "COMMIT;", nullptr, nullptr, nullptr);
    sqlite3_close(db);
    return "key_expired";
}