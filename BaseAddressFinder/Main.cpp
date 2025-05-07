// Windows-specific includes for working with processes and modules
#include <windows.h>
#include <tlhelp32.h>
#include <tchar.h>
#include <iostream>
#include <vector>
#include <string>
#include <cwctype> 
#include <algorithm> // for std::sort

// Structure to hold process name and ID
struct ProcessInfo {
    DWORD pid;
    std::wstring name;
    bool hasWindow;
};

// SENT: nil
// RETURNS: vector of ProcessInfo eg. { {1234, L"example.exe", false}, {34234, L"ex2.exe, false} ... }
// DESC: Creates vector array of ProcessInfo objs to store all running processes, windowed set to false by default to be checked later
std::vector<ProcessInfo> ListRunningProcesses() {

	std::vector<ProcessInfo> processes; // Vector (Dynamic array) to hold process info

	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0); // Create a snapshot of all processes

    if (snapshot != INVALID_HANDLE_VALUE) {

		PROCESSENTRY32W pe;     // Process entry structure
		pe.dwSize = sizeof(pe); // Set the size of the structure to ensure compatibility

        // Process32FirstW: Retrieves information about the first process in the snapshot
        // Returns TRUE if successful (i.e., a process was found), FALSE otherwise
        if (Process32FirstW(snapshot, &pe)) {
            do {
				// Create a ProcessInfo object and add it to the vector
                processes.push_back({ pe.th32ProcessID, pe.szExeFile, false });
            }
            // Process32NextW: Continues enumeration and retrieves information about the next process in the snapshot
            // Returns TRUE as long as there are more processes to enumerate, FALSE when finished
            while (Process32NextW(snapshot, &pe));
        }
        CloseHandle(snapshot);
    }
    return processes;
}

// SENT: process ID
// RETURNS: true if a visible window is found, false otherwise
// DESC: Checks if a process has any visible windows
bool HasVisibleWindow(DWORD pid) {

    HWND hwnd = NULL;  // Initialize a window handle to NULL (used to iterate over top-level windows)

    // Loop through all top-level windows in the system
    // FindWindowEx allows us to iterate through them one by one
    while ((hwnd = FindWindowEx(NULL, hwnd, NULL, NULL)) != NULL) {

        DWORD windowPid = 0;  // Variable to hold the process ID for this window

        // Retrieves the process ID that owns the current window handle
        GetWindowThreadProcessId(hwnd, &windowPid);

        // Check:
        // 1. If this window belongs to the target process ID
		// 2. If this window is currently visible by OS (can be minimized, but not hidden)
        if (windowPid == pid && IsWindowVisible(hwnd)) {
            return true;  // Found a visible window belonging to the process
        }

        // If not, continue to next window
    }

    // No visible window was found for this process
    return false;
}

// SENT: process ID
// RETURNS: base address of the module (0 if not found)
// DESC: Retrieves the base address of the first module in the process
uintptr_t GetModuleBaseAddress(DWORD procId, const std::wstring& targetModuleName) {
    uintptr_t baseAddress = 0; // This will hold the base address we find, or remain 0 if we don't find it

    // Create a snapshot (basically a frozen list) of all modules (DLLs, .exe, etc.) loaded by this process
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, procId);

    // Make sure the snapshot is valid before using it
    if (hSnapshot != INVALID_HANDLE_VALUE) {
        MODULEENTRY32W me;       // Struct to hold module info like name, size, and base address
        me.dwSize = sizeof(me);  // Must set this or the function won't work

        // Module32FirstW: grabs the first module in the snapshot — this is usually the main .exe of the process
        if (Module32FirstW(hSnapshot, &me)) {
            do {
				// Compare the module name with the target module name (case-insensitive)
                if (_wcsicmp(me.szModule, targetModuleName.c_str()) == 0) {
                    baseAddress = (uintptr_t)me.modBaseAddr;
                    break;
                }
            } while (Module32NextW(hSnapshot, &me));
        }

        // Clean up the handle to avoid memory/resource leaks
        CloseHandle(hSnapshot);
    }

    // If no module was found or something failed, this will return 0
    return baseAddress;
}

// SENT: process ID
// RETURNS: name of the main module (e.g., L"notepad.exe"), or empty string if not found
// DESC: Retrieves the name of the main module (usually the executable) for a given process ID
std::wstring GetMainModuleName(DWORD procId) {
    std::wstring moduleName;

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, procId);

    if (hSnapshot != INVALID_HANDLE_VALUE) {
        MODULEENTRY32W me;
        me.dwSize = sizeof(me);

        if (Module32FirstW(hSnapshot, &me)) {
            moduleName = me.szModule; // This is the module name
        }

        CloseHandle(hSnapshot);
    }

    return moduleName; // Returns empty string if snapshot failed or nothing found
}


int wmain() {
    wchar_t arg = 0;

    std::wcout << L"Press \"A\" to get all processes, or \"W\" to retrieve only windowed programs\n";

    // Wait for 'A' or 'W' keypress
    while (true) {
        if (GetAsyncKeyState('A') & 0x8000) {
            arg = L'A';
            break;
        }
        else if (GetAsyncKeyState('W') & 0x8000) {
            arg = L'W';
            break;
        }
        Sleep(100); // Prevent high CPU usage
    }

	// Flush the input buffer so letter is not printed
	HANDLE hStdin = GetStdHandle(STD_INPUT_HANDLE); // Get the standard input handle
	FlushConsoleInputBuffer(hStdin); // Flush the input buffer to remove any unwanted characters

    // Retrieve all processes
    auto processes = ListRunningProcesses();

    // Flag processes with a visible window
    for (auto& proc : processes) {
        proc.hasWindow = HasVisibleWindow(proc.pid);
    }

    // If 'W' was selected, remove non-windowed processes
    if (arg == L'W') {
        processes.erase(
            std::remove_if(processes.begin(), processes.end(),
                [](const ProcessInfo& p) { return !p.hasWindow; }),
            processes.end());
    }

    // Sort: windowed apps first
    std::sort(processes.begin(), processes.end(), [](const ProcessInfo& a, const ProcessInfo& b) {
        return a.hasWindow < b.hasWindow; // Windowed apps at the bottom
        });

    // Display processes
    for (const auto& proc : processes) {
        std::wcout << L"[" << proc.pid << L"] " << proc.name;
        if (proc.hasWindow) std::wcout << L" (Window)";
        std::wcout << L"\n";
    }

    // Input PID from user
    std::wcout << L"\nEnter the process ID: ";
    std::wstring input;
    std::getline(std::wcin, input);

    DWORD pid = 0;
    try {
        pid = static_cast<DWORD>(std::stoul(input));
    }
    catch (...) {
        std::wcout << L"\nInvalid input.\n";
        return 1;
    }

    // Get base address
	std::wstring targetModuleName = GetMainModuleName(pid);

	if (targetModuleName.empty()) {
		std::wcout << L"\nProcess not found.\n";
		return 1;
	}

    uintptr_t baseAddr = GetModuleBaseAddress(pid, targetModuleName);
    if (baseAddr == 0) {
        std::wcout << L"\nBase address not found.\n";
        return 1;
    }

    std::wcout << L"\nProcess ID: " << pid << L"\n";
    std::wcout << L"Base Address: 0x" << std::hex << baseAddr << L"\n";

    return 0;
}
