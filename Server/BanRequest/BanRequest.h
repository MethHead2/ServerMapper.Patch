#ifndef BANREQUEST_H
#define BANREQUEST_H

#include <string>
#include <iostream>
#include <winsock2.h>
#include <sqlite3.h>
#include <ctime>
#include <sstream>
#include <string>

bool banHWID(const std::string& hwid);

#endif  // BANHWID_H