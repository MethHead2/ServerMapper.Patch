// database.hpp
#pragma once
#include <string>

class Database {
public:
    Database(const std::string& db_path);
    ~Database();

    bool isKeyValid(const std::string& key);

private:
    void openDatabase(const std::string& db_path);
    void closeDatabase();
    struct sqlite3* db;
};