#ifndef GetHWID_H
#define GetHWID_H

#include <iostream>
#include <string>
#include <sstream>
#include <iomanip>
#include <vector>
#include <array>
#include <stdexcept>
#include <cstdint>
#include <windows.h>
#include <memory>
#include <cstdio>
#include <cstring>
#include "../pch.h"


// Function to hash the HWID with SHA-256
std::string HashHWID(const std::string& hwid);

// Function to execute a command and get the output
std::string exec(const char* cmd);

// Function to get a list of hardware IDs (like CPU serial, etc.) using cmd
std::vector<std::string> GetHWIDs();

#endif