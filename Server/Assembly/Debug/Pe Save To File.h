#ifndef PE_SAVE_TO_FILE_H
#define PE_SAVE_TO_FILE_H

#include <Windows.h>
#include <vector>
#include <string>

// Save PE data to a file
bool SavePEToFile(const std::vector<BYTE>& peData, const std::string& outputPath);

// Save PE data with automatic timestamp in filename
bool SavePEToFileWithTimestamp(const std::vector<BYTE>& peData,
    const std::string& baseFilename = "output",
    const std::string& outputDir = ".");

// Save PE snapshot at different stages (useful for debugging)
bool SavePESnapshot(const std::vector<BYTE>& peData,
    int applicationId,
    const std::string& stage,
    const std::string& outputDir = "dumps");

#endif // PE_SAVE_TO_FILE_H