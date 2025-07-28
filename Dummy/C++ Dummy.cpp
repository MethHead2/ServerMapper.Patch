#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <iostream>
#include <fstream>
#include <string>

// Global variables
std::ofstream g_logFile;
HANDLE g_hPipe = INVALID_HANDLE_VALUE;
void* g_baseAddress = nullptr;
uintptr_t g_entryPoint = 0;
volatile bool g_shouldExit = false;
volatile bool g_detached = false;
volatile bool g_stayAlive = true;  // Default to staying alive
volatile bool g_autoExecute = false; // Flag for auto-execution after client detaches

// Architecture information
volatile bool g_clientIs64Bit = false;  // Flag to track if the client is 64-bit

// Simple helper to create an exit event that keeps the process alive
HANDLE g_exitEvent = NULL;

void Log(const std::string& message) {
    if (g_logFile.is_open()) {
        g_logFile << message << std::endl;
        g_logFile.flush();
    }
}

// SEH-wrapped execution function - this is C-style without C++ objects, so SEH is fine
DWORD SafeExecuteEntryPoint(void* baseAddr, uintptr_t entryPoint) {
    typedef DWORD(WINAPI* EntryFunc)(void*);
    EntryFunc func = (EntryFunc)entryPoint;

    __try {
        return func(baseAddr);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        DWORD exceptionCode = GetExceptionCode();
        return exceptionCode;
    }
}

// C++ wrapper for execution thread without using SEH directly
DWORD WINAPI ExecuteThread(LPVOID lpParam) {
    Log("Starting execution at " + std::to_string(g_entryPoint) +
        " with base address " + std::to_string((uintptr_t)g_baseAddress));

    // Call the SEH-safe function
    DWORD result = SafeExecuteEntryPoint(g_baseAddress, g_entryPoint);

    Log("Execution completed with result: " + std::to_string(result));
    return result;
}

// A separate function to handle execution after client detachment
DWORD WINAPI AutoExecuteThread(LPVOID lpParam) {
    // Wait a moment to ensure client has fully detached
    Sleep(500);

    Log("Auto-executing mapped code after client detachment");

    // Call the execution function
    ExecuteThread(lpParam);

    return 0;
}

// Thread to handle pipe communication
DWORD WINAPI PipeServerThread(LPVOID lpParam) {
    const char* pipeName = (const char*)lpParam;

    while (g_stayAlive && !g_shouldExit) {
        Log("Creating named pipe: " + std::string(pipeName));

        // Create the named pipe
        g_hPipe = CreateNamedPipeA(
            pipeName,
            PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
            1,
            4096,
            4096,
            0,
            NULL
        );

        if (g_hPipe == INVALID_HANDLE_VALUE) {
            Log("Failed to create pipe: " + std::to_string(GetLastError()));
            return 1;
        }

        Log("Waiting for client connection...");

        // Wait for client to connect
        if (ConnectNamedPipe(g_hPipe, NULL) || GetLastError() == ERROR_PIPE_CONNECTED) {
            Log("Client connected");

            // Process client requests
            while (true) {
                // Read message type
                BYTE messageType = 0;
                DWORD bytesRead;

                if (!ReadFile(g_hPipe, &messageType, sizeof(messageType), &bytesRead, NULL) ||
                    bytesRead != sizeof(messageType)) {
                    DWORD error = GetLastError();
                    if (error == ERROR_BROKEN_PIPE || error == ERROR_PIPE_NOT_CONNECTED) {
                        Log("Client disconnected - pipe broken");
                        if (g_detached) {
                            Log("Already detached - keeping process alive");

                            // Check if we should auto-execute after unexpected client disconnect
                            if (g_autoExecute && g_baseAddress && g_entryPoint) {
                                Log("Auto-executing after client disconnect (pipe broken)");
                                g_autoExecute = false; // Reset so we don't run it again

                                // Create auto-execution thread
                                HANDLE hAutoThread = CreateThread(NULL, 0, AutoExecuteThread, NULL, 0, NULL);
                                if (hAutoThread) {
                                    CloseHandle(hAutoThread);
                                }
                            }
                        }
                        else {
                            // Auto-detach when client disconnects
                            Log("Auto-detaching");
                            g_detached = true;

                            // If we have executable info, run the code after client disconnect
                            if (g_baseAddress && g_entryPoint) {
                                Log("Auto-executing after client disconnect");

                                // Create auto-execution thread
                                HANDLE hAutoThread = CreateThread(NULL, 0, AutoExecuteThread, NULL, 0, NULL);
                                if (hAutoThread) {
                                    CloseHandle(hAutoThread);
                                }
                            }
                        }
                    }
                    else {
                        Log("Error reading message type: " + std::to_string(error));
                    }
                    break;
                }

                Log("Received message type: " + std::to_string((int)messageType));

                if (messageType == 1) {  // Import resolution
                    // Read module name length then name
                    DWORD moduleNameLen = 0;
                    if (!ReadFile(g_hPipe, &moduleNameLen, sizeof(moduleNameLen), &bytesRead, NULL) ||
                        bytesRead != sizeof(moduleNameLen)) {
                        Log("Error reading module name length");
                        break;
                    }

                    // Allocate buffer for module name
                    char* moduleName = new char[moduleNameLen + 1];
                    ZeroMemory(moduleName, moduleNameLen + 1);

                    if (!ReadFile(g_hPipe, moduleName, moduleNameLen, &bytesRead, NULL) ||
                        bytesRead != moduleNameLen) {
                        Log("Error reading module name");
                        delete[] moduleName;
                        break;
                    }

                    // Read function name length then name
                    DWORD funcNameLen = 0;
                    if (!ReadFile(g_hPipe, &funcNameLen, sizeof(funcNameLen), &bytesRead, NULL) ||
                        bytesRead != sizeof(funcNameLen)) {
                        Log("Error reading function name length");
                        delete[] moduleName;
                        break;
                    }

                    // Allocate buffer for function name
                    char* functionName = new char[funcNameLen + 1];
                    ZeroMemory(functionName, funcNameLen + 1);

                    if (!ReadFile(g_hPipe, functionName, funcNameLen, &bytesRead, NULL) ||
                        bytesRead != funcNameLen) {
                        Log("Error reading function name");
                        delete[] moduleName;
                        delete[] functionName;
                        break;
                    }

                    // Load the module
                    HMODULE hModule = LoadLibraryA(moduleName);
                    if (!hModule) {
                        Log("Failed to load module: " + std::string(moduleName));
                        // Send error response
                        if (g_clientIs64Bit) {
                            UINT64 address = 0;
                            WriteFile(g_hPipe, &address, sizeof(address), &bytesRead, NULL);
                        }
                        else {
                            DWORD address = 0;
                            WriteFile(g_hPipe, &address, sizeof(address), &bytesRead, NULL);
                        }

                        delete[] moduleName;
                        delete[] functionName;
                        continue;
                    }

                    // Get the function address
                    uintptr_t address = 0;

                    if (functionName[0] == '#') {
                        // It's an ordinal
                        WORD ordinal = static_cast<WORD>(std::stoi(functionName + 1));
                        address = (uintptr_t)GetProcAddress(hModule, MAKEINTRESOURCEA(ordinal));
                    }
                    else {
                        // It's a function name
                        address = (uintptr_t)GetProcAddress(hModule, functionName);
                    }

                    Log("Resolved import: " + std::string(moduleName) + "." +
                        std::string(functionName) + " to address 0x" + std::to_string(address));

                    // Send the address in the correct format based on client architecture
                    if (g_clientIs64Bit) {
                        // Send as 64-bit value
                        UINT64 address64 = static_cast<UINT64>(address);
                        if (!WriteFile(g_hPipe, &address64, sizeof(address64), &bytesRead, NULL)) {
                            Log("Failed to send 64-bit address: " + std::to_string(GetLastError()));
                        }
                        else {
                            Log("Sent 64-bit address: 0x" + std::to_string(address64));
                        }
                    }
                    else {
                        // Send as 32-bit value
                        DWORD address32 = static_cast<DWORD>(address);
                        if (!WriteFile(g_hPipe, &address32, sizeof(address32), &bytesRead, NULL)) {
                            Log("Failed to send 32-bit address: " + std::to_string(GetLastError()));
                        }
                        else {
                            Log("Sent 32-bit address: 0x" + std::to_string(address32));
                        }
                    }

                    delete[] moduleName;
                    delete[] functionName;
                }
                else if (messageType == 6) {  // Auto-execute after client detaches
                    Log("Received auto-execute command from client");

                    // Set the auto-execute flag to true
                    g_autoExecute = true;

                    // Send acknowledgment
                    BYTE ack = 1;
                    WriteFile(g_hPipe, &ack, sizeof(ack), &bytesRead, NULL);
                    Log("Sent auto-execute acknowledgment");
                }
                else if (messageType == 5) {  // Architecture info
                    // Read the architecture flag sent by the client
                    BYTE is64Bit;
                    if (!ReadFile(g_hPipe, &is64Bit, sizeof(is64Bit), &bytesRead, NULL) ||
                        bytesRead != sizeof(is64Bit)) {
                        Log("Error reading architecture flag");
                        break;
                    }

                    g_clientIs64Bit = (is64Bit != 0);
                    Log("Received architecture info - Client is " +
                        std::string(g_clientIs64Bit ? "64-bit" : "32-bit"));

                    // Send acknowledgment
                    BYTE ack = 1;
                    WriteFile(g_hPipe, &ack, sizeof(ack), &bytesRead, NULL);
                }
                else if (messageType == 2) {  // Detach
                    Log("Client requested detach");
                    g_detached = true;

                    // Send acknowledgment
                    BYTE ack = 1;
                    WriteFile(g_hPipe, &ack, sizeof(ack), &bytesRead, NULL);
                    Log("Sent detach acknowledgment");

                    // Break pipe loop so we can serve new clients after detach
                    break;
                }
                else if (messageType == 3) {  // Execute info
                    Log("Receiving execute information");

                    // Read entry point and base address with appropriate size based on client architecture
                    if (g_clientIs64Bit) {
                        // Read 64-bit values
                        UINT64 entryPoint64 = 0;
                        if (!ReadFile(g_hPipe, &entryPoint64, sizeof(entryPoint64), &bytesRead, NULL) ||
                            bytesRead != sizeof(entryPoint64)) {
                            Log("Error reading 64-bit entry point");
                            break;
                        }
                        g_entryPoint = static_cast<uintptr_t>(entryPoint64);

                        UINT64 baseAddress64 = 0;
                        if (!ReadFile(g_hPipe, &baseAddress64, sizeof(baseAddress64), &bytesRead, NULL) ||
                            bytesRead != sizeof(baseAddress64)) {
                            Log("Error reading 64-bit base address");
                            break;
                        }
                        g_baseAddress = reinterpret_cast<void*>(static_cast<uintptr_t>(baseAddress64));
                    }
                    else {
                        // Read 32-bit values
                        DWORD entryPoint32 = 0;
                        if (!ReadFile(g_hPipe, &entryPoint32, sizeof(entryPoint32), &bytesRead, NULL) ||
                            bytesRead != sizeof(entryPoint32)) {
                            Log("Error reading 32-bit entry point");
                            break;
                        }
                        g_entryPoint = static_cast<uintptr_t>(entryPoint32);

                        DWORD baseAddress32 = 0;
                        if (!ReadFile(g_hPipe, &baseAddress32, sizeof(baseAddress32), &bytesRead, NULL) ||
                            bytesRead != sizeof(baseAddress32)) {
                            Log("Error reading 32-bit base address");
                            break;
                        }
                        g_baseAddress = reinterpret_cast<void*>(static_cast<uintptr_t>(baseAddress32));
                    }

                    Log("Received execute info - Entry point: 0x" + std::to_string(g_entryPoint) +
                        ", Base address: 0x" + std::to_string((UINT_PTR)g_baseAddress));

                    // Send acknowledgment
                    BYTE ack = 1;
                    WriteFile(g_hPipe, &ack, sizeof(ack), &bytesRead, NULL);
                    Log("Sent execute acknowledgment");
                }
                else if (messageType == 4) {  // Exit
                    Log("Client requested process exit");
                    g_shouldExit = true;

                    // Send acknowledgment
                    BYTE ack = 1;
                    WriteFile(g_hPipe, &ack, sizeof(ack), &bytesRead, NULL);

                    break;
                }
                else if (messageType == 99) {  // Stay alive indicator
                    g_stayAlive = true;
                    Log("Received stay alive command");

                    // Send acknowledgment
                    BYTE ack = 1;
                    WriteFile(g_hPipe, &ack, sizeof(ack), &bytesRead, NULL);
                }
                else {
                    Log("Unknown message type: " + std::to_string((int)messageType));
                    break;
                }
            }

            // Disconnect the client
            DisconnectNamedPipe(g_hPipe);
            Log("Disconnected pipe");
        }
        else {
            Log("Failed to connect client. Error: " + std::to_string(GetLastError()));
        }

        // Close the pipe
        CloseHandle(g_hPipe);
        g_hPipe = INVALID_HANDLE_VALUE;

        // If we should exit, break the loop
        if (g_shouldExit) {
            break;
        }

        // Sleep a bit before recreating the pipe
        Sleep(100);

        // If detached and have executable info, run the code
        if (g_detached && g_baseAddress && g_entryPoint) {
            Log("Detached with valid executable - running independently");
            g_detached = false; // Reset so we don't run it again

            // Check if auto-execute was requested
            if (g_autoExecute) {
                Log("Auto-execute flag is set - executing code immediately");
                g_autoExecute = false; // Reset flag

                // Create execution thread
                HANDLE hExecThread = CreateThread(NULL, 0, ExecuteThread, NULL, 0, NULL);
                if (hExecThread) {
                    CloseHandle(hExecThread);
                }
                else {
                    Log("Failed to create execution thread: " + std::to_string(GetLastError()));
                }
            }
            else {
                // Normal execution thread
                Log("Creating normal execution thread");
                HANDLE hExecThread = CreateThread(NULL, 0, ExecuteThread, NULL, 0, NULL);
                if (hExecThread) {
                    CloseHandle(hExecThread);
                }
                else {
                    Log("Failed to create execution thread: " + std::to_string(GetLastError()));
                }
            }
        }
    }

    return 0;
}

// Global exception handler callback - RENAMED to avoid conflict with kernel32.lib
LONG WINAPI CustomUnhandledExceptionFilter(EXCEPTION_POINTERS* pExceptionInfo) {
    DWORD exceptionCode = pExceptionInfo->ExceptionRecord->ExceptionCode;

    if (g_logFile.is_open()) {
        Log("Unhandled exception occurred: 0x" + std::to_string(exceptionCode));
    }

    return EXCEPTION_CONTINUE_SEARCH;
}

int main(int argc, char* argv[]) {
    // Ensure we have a proper console
    if (GetConsoleWindow() == NULL) {
        AllocConsole();
    }

    // Ensure standard streams are properly connected
    freopen_s((FILE**)stdout, "CONOUT$", "w", stdout);
    freopen_s((FILE**)stderr, "CONOUT$", "w", stderr);
    freopen_s((FILE**)stdin, "CONIN$", "r", stdin);

    // Sync C++ streams with C streams
    std::ios::sync_with_stdio(true);

    // Set console title
    SetConsoleTitleA("Dummy Process Console");

    // Create log file
    g_logFile.open("dummy_log.txt");
    Log("Dummy process started");

    // Output to both console and log
    std::cout << "Dummy process started successfully!" << std::endl;
    std::cout << "Process ID: " << GetCurrentProcessId() << std::endl;

    // Detect if we're running as a 64-bit process
#ifdef _WIN64
    Log("Running as 64-bit process");
    std::cout << "Running as 64-bit process" << std::endl;
#else
    Log("Running as 32-bit process");
    std::cout << "Running as 32-bit process" << std::endl;
#endif

    // Set up global exception handler - using our renamed function
    SetUnhandledExceptionFilter(CustomUnhandledExceptionFilter);

    // Parse command line arguments
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--stay-alive") == 0) {
            g_stayAlive = true;
            Log("Stay alive mode enabled from command line");
            std::cout << "Stay alive mode enabled" << std::endl;
        }
    }

    // Create exit event to keep process alive
    g_exitEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    if (!g_exitEvent) {
        Log("Failed to create exit event");
        std::cout << "Failed to create exit event" << std::endl;
        return 1;
    }

    // Create a predictable pipe name using our process ID
    std::string pipeName = "\\\\.\\pipe\\DummyProcess_" +
        std::to_string(GetCurrentProcessId());

    Log("Using pipe name: " + pipeName);
    std::cout << "Using pipe name: " << pipeName << std::endl;

    // Create pipe server thread
    HANDLE hPipeThread = CreateThread(NULL, 0, PipeServerThread,
        (LPVOID)pipeName.c_str(), 0, NULL);
    if (!hPipeThread) {
        Log("Failed to create pipe server thread: " + std::to_string(GetLastError()));
        std::cout << "Failed to create pipe server thread: " << GetLastError() << std::endl;
        return 1;
    }

    Log("Created pipe server thread");
    std::cout << "Pipe server thread created successfully" << std::endl;

    // Wait on exit event - this keeps the process running
    Log("Main thread waiting on exit event");
    std::cout << "Main thread waiting... Console output should work now!" << std::endl;
    WaitForSingleObject(g_exitEvent, INFINITE);

    // If we get here, we're exiting
    Log("Exit event signaled");
    std::cout << "Exit event signaled" << std::endl;

    g_shouldExit = true;

    // Wait for pipe thread to exit
    WaitForSingleObject(hPipeThread, 5000);
    CloseHandle(hPipeThread);
    CloseHandle(g_exitEvent);

    Log("Dummy process exiting");
    std::cout << "Dummy process exiting" << std::endl;
    g_logFile.close();
    return 0;
}