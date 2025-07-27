#ifndef CHECKKEY_H
#define CHECKKEY_H

#include <string>
#include <iostream>
#include <winsock2.h>
#include <sqlite3.h>
#include <ctime>
#include <sstream>
#pragma comment(lib, "ws2_32.lib")

std::string checkKeyInAllTables(const std::string& key, const std::string& hashedHwid);

inline bool ValidKey = false;
extern int applicationId;  // Add this line

#endif  // CHECKKEY_H