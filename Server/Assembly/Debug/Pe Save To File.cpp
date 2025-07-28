#include "Pe Save To File.h"
#include <fstream>
#include <iostream>
#include <iomanip>
#include <ctime>
#include <sstream>

bool SavePEToFile(const std::vector<BYTE>& peData, const std::string& outputPath) {
    try {
        // Open file for binary writing
        std::ofstream file(outputPath, std::ios::binary | std::ios::trunc);
        if (!file.is_open()) {
            std::cerr << "[!] Failed to create output file: " << outputPath << std::endl;
            return false;
        }

        // Write PE data
        file.write(reinterpret_cast<const char*>(peData.data()), peData.size());

        // Check for write errors
        if (!file.good()) {
            std::cerr << "[!] Error writing to file: " << outputPath << std::endl;
            file.close();
            return false;
        }

        file.close();

        std::cout << "[+] Successfully saved PE to: " << outputPath << std::endl;
        std::cout << "    File size: " << peData.size() << " bytes" << std::endl;

        return true;
    }
    catch (const std::exception& e) {
        std::cerr << "[!] Exception saving PE to file: " << e.what() << std::endl;
        return false;
    }
}

bool SavePEToFileWithTimestamp(const std::vector<BYTE>& peData,
    const std::string& baseFilename,
    const std::string& outputDir) {
    try {
        // Create timestamp
        std::time_t t = std::time(nullptr);
        std::tm tm;
        localtime_s(&tm, &t);

        std::stringstream ss;
        ss << outputDir;
        if (!outputDir.empty() && outputDir.back() != '\\' && outputDir.back() != '/') {
            ss << "\\";
        }
        ss << baseFilename << "_";
        ss << std::put_time(&tm, "%Y%m%d_%H%M%S");
        ss << ".exe";

        std::string outputPath = ss.str();

        return SavePEToFile(peData, outputPath);
    }
    catch (const std::exception& e) {
        std::cerr << "[!] Exception creating timestamped filename: " << e.what() << std::endl;
        return false;
    }
}

bool SavePESnapshot(const std::vector<BYTE>& peData,
    int applicationId,
    const std::string& stage,
    const std::string& outputDir) {
    try {
        std::stringstream ss;
        ss << outputDir;
        if (!outputDir.empty() && outputDir.back() != '\\' && outputDir.back() != '/') {
            ss << "\\";
        }
        ss << "app_" << applicationId << "_" << stage;

        return SavePEToFileWithTimestamp(peData, ss.str(), "");
    }
    catch (const std::exception& e) {
        std::cerr << "[!] Exception creating snapshot: " << e.what() << std::endl;
        return false;
    }
}