// database.cpp
#include "database.hpp"
#include <sqlite3.h>
#include <iostream>

Database::Database(const std::string& db_path) {
    openDatabase(db_path);
}

Database::~Database() {
    closeDatabase();
}

void Database::openDatabase(const std::string& db_path) {
    if (sqlite3_open(db_path.c_str(), &db)) {
        std::cerr << "Can't open database: " << sqlite3_errmsg(db) << std::endl;
    }
    else {
        std::cout << "Database opened successfully!" << std::endl;
    }
}

void Database::closeDatabase() {
    sqlite3_close(db);
}

bool Database::isKeyValid(const std::string& key) {
    const char* sql = "SELECT ak.is_valid "
                     "FROM application_keys ak "
                     "WHERE ak.key = ? AND ak.is_valid = 1 "
                     "AND (ak.first_use_date IS NULL OR "
                     "datetime(ak.first_use_date, '+' || ak.duration || ' seconds') > datetime('now'));";
    
    sqlite3_stmt* stmt;
    bool is_valid = false;

    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, key.c_str(), -1, SQLITE_STATIC);

        if (sqlite3_step(stmt) == SQLITE_ROW) {
            is_valid = sqlite3_column_int(stmt, 0) == 1;
        }
    }
    sqlite3_finalize(stmt);
    return is_valid;
}