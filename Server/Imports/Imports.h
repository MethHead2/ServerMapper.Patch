#ifndef Imports_H
#define Imports_H

#include <iostream>
#include <winsock2.h>
#include <sqlite3.h>
#include <ctime>
#include <sstream>
#include <string>

std::string getCurrentDate();
time_t parseDate(const std::string& dateStr);

#endif  // DATEUTILS_H