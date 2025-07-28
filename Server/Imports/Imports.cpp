#include "Imports.h"

// Function to get the current date/time as a string
std::string getCurrentDate() {
    time_t now = time(0);
    struct tm tstruct;
    char buf[80];

    localtime_s(&tstruct, &now);
    strftime(buf, sizeof(buf), "%Y-%m-%d %X", &tstruct); // Format: YYYY-MM-DD HH:MM:SS
    return buf;
}

// Function to parse date from string
time_t parseDate(const std::string& dateStr) {
    std::tm tm = {};
    std::istringstream ss(dateStr);
    char dash1, dash2, space, colon1, colon2;
    ss >> tm.tm_year >> dash1 >> tm.tm_mon >> dash2 >> tm.tm_mday
        >> space >> tm.tm_hour >> colon1 >> tm.tm_min >> colon2 >> tm.tm_sec;

    tm.tm_year -= 1900; // tm_year is year since 1900
    tm.tm_mon -= 1;     // tm_mon is 0-based

    return mktime(&tm);
}