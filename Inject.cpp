#include <iostream>
#include <windows.h>
#include <tlhelp32.h>

int main() {
    HANDLE hProcessSnap;
    PROCESSENTRY32 pe32;

    hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hProcessSnap == INVALID_HANDLE_VALUE) {
        std::cerr << "Error: CreateToolhelp32Snapshot failed" << std::endl;
        return 1;
    }

    pe32.dwSize = sizeof(PROCESSENTRY32);

    if (!Process32First(hProcessSnap, &pe32)) {
        std::cerr << "Error: Process32First failed" << std::endl;
        CloseHandle(hProcessSnap);
        return 1;
    }

    do {
        std::cout << "Process ID: " << pe32.th32ProcessID << "\t";
        std::wcout << "Process Name: " << pe32.szExeFile << std::endl;
    } while (Process32Next(hProcessSnap, &pe32));

    CloseHandle(hProcessSnap);

    LPCSTR DllPath = "D:\\projects\\standardinjection\\release\\testlib.dll";
    
    INT process_id;
    std::cout << "[+] Input Process_Id for inject DLL " << std::endl;
    std::cin >> process_id;
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, process_id);


    LPVOID pDllPath = VirtualAllocEx(hProcess, 0, strlen(DllPath) + 1,
        MEM_COMMIT, PAGE_READWRITE);


    WriteProcessMemory(hProcess, pDllPath, (LPVOID)DllPath,
        strlen(DllPath) + 1, 0);


    HANDLE hLoadThread = CreateRemoteThread(hProcess, 0, 0,
        (LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandleA("Kernel32.dll"),
            "LoadLibraryA"), pDllPath, 0, 0);

    WaitForSingleObject(hLoadThread, INFINITE);

    std::cout << "Dll path allocated at: " << std::hex << pDllPath << std::endl;
    std::cin.get();

    VirtualFreeEx(hProcess, pDllPath, strlen(DllPath) + 1, MEM_RELEASE);

    return 0;
}
