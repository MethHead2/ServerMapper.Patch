#include "HashUtils.h"

std::vector<BYTE> ComputeSHA256Hash(const std::wstring& filePath) {
    VMProtectBeginUltra("ComputeSHA256Hash");
    HANDLE file = CreateFileW(filePath.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE) {
        std::cout << (VMProtectDecryptStringA("Failed to open file."));
        exit(0);
    }

    // Read the file content
    LARGE_INTEGER fileSize;
    if (!GetFileSizeEx(file, &fileSize)) {
        CloseHandle(file);
        std::cout << (VMProtectDecryptStringA("Failed to get file size."));
        return {};
    }

    std::vector<BYTE> buffer(static_cast<size_t>(fileSize.QuadPart));
    DWORD bytesRead;
    if (!ReadFile(file, buffer.data(), static_cast<DWORD>(fileSize.QuadPart), &bytesRead, NULL)) {
        CloseHandle(file);
        std::cout << (VMProtectDecryptStringA("Failed to read file."));
        return {};
    }
    CloseHandle(file);

    // Compute the SHA-256 hash
    BCRYPT_ALG_HANDLE hAlgorithm = NULL;
    BCRYPT_HASH_HANDLE hHash = NULL;
    NTSTATUS status;
    DWORD hashObjectSize, hashSize;
    std::vector<BYTE> hash;

    status = BCryptOpenAlgorithmProvider(&hAlgorithm, BCRYPT_SHA256_ALGORITHM, NULL, 0);
    if (!BCRYPT_SUCCESS(status)) {
        std::cout << (VMProtectDecryptStringA("Failed to open algorithm provider."));
        return {};
    }

    status = BCryptGetProperty(hAlgorithm, BCRYPT_OBJECT_LENGTH, (PBYTE)&hashObjectSize, sizeof(hashObjectSize), &hashSize, 0);
    if (!BCRYPT_SUCCESS(status)) {
        BCryptCloseAlgorithmProvider(hAlgorithm, 0);
        std::cout << (VMProtectDecryptStringA("Failed to get hash object size."));
        return {};
    }

    hash.resize(hashObjectSize);
    status = BCryptCreateHash(hAlgorithm, &hHash, hash.data(), hashObjectSize, NULL, 0, 0);
    if (!BCRYPT_SUCCESS(status)) {
        BCryptCloseAlgorithmProvider(hAlgorithm, 0);
        std::cout << (VMProtectDecryptStringA("Failed to create hash."));
        return {};
    }

    status = BCryptHashData(hHash, buffer.data(), static_cast<ULONG>(buffer.size()), 0);
    if (!BCRYPT_SUCCESS(status)) {
        BCryptDestroyHash(hHash);
        BCryptCloseAlgorithmProvider(hAlgorithm, 0);
        std::cout << (VMProtectDecryptStringA("Failed to hash data."));
        return {};
    }

    ULONG resultSize;
    status = BCryptGetProperty(hAlgorithm, BCRYPT_HASH_LENGTH, (PBYTE)&resultSize, sizeof(resultSize), &hashSize, 0);
    if (!BCRYPT_SUCCESS(status)) {
        BCryptDestroyHash(hHash);
        BCryptCloseAlgorithmProvider(hAlgorithm, 0);
        std::cout << (VMProtectDecryptStringA("Failed to get hash length."));
        return {};
    }

    hash.resize(resultSize);
    status = BCryptFinishHash(hHash, hash.data(), resultSize, 0);
    if (!BCRYPT_SUCCESS(status)) {
        BCryptDestroyHash(hHash);
        BCryptCloseAlgorithmProvider(hAlgorithm, 0);
        std::cout << (VMProtectDecryptStringA("Failed to finish hash."));
        return {};
    }

    BCryptDestroyHash(hHash);
    BCryptCloseAlgorithmProvider(hAlgorithm, 0);

    return hash;
    VMProtectEnd();
}