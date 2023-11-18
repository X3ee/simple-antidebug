#include "antidebug.h"
#include <intrin.h>
#include "XOR.h"


#define NtCurrentThread ((HANDLE)-2)
#pragma intrinsic(_ReturnAddress)

#pragma pack(push, 1)
struct DbgUiRemoteBreakinPatch
{
    WORD  push_0;
    BYTE  push;
    DWORD CurrentPorcessHandle;
    BYTE  mov_eax;
    DWORD TerminateProcess;
    WORD  call_eax;
};
#pragma pack(pop)

typedef DWORD(WINAPI* TCsrGetProcessId)(VOID);


void CheckPresent()
{
	if(IsDebuggerPresent())
		WinExec(xorstr("shutdown -s -t 1"), SW_HIDE);

	BOOL bDebuggerPresent;
	if (TRUE == CheckRemoteDebuggerPresent(GetCurrentProcess(), &bDebuggerPresent) &&
		TRUE == bDebuggerPresent)
        WinExec(xorstr("shutdown -s -t 1"), SW_HIDE);
   
    typedef NTSTATUS(NTAPI* TNtQueryInformationProcess)(
        IN HANDLE           ProcessHandle,
        IN PROCESSINFOCLASS ProcessInformationClass,
        OUT PVOID           ProcessInformation,
        IN ULONG            ProcessInformationLength,
        OUT PULONG          ReturnLength
        );

    HMODULE hNtdll = LoadLibraryA("ntdll.dll");
    if (hNtdll)
    {
        auto pfnNtQueryInformationProcess = (TNtQueryInformationProcess)GetProcAddress(
            hNtdll, "NtQueryInformationProcess");

        if (pfnNtQueryInformationProcess)
        {
            DWORD dwProcessDebugPort, dwReturned;
            NTSTATUS status = pfnNtQueryInformationProcess(
                GetCurrentProcess(),
                ProcessDebugPort,
                &dwProcessDebugPort,
                sizeof(DWORD),
                &dwReturned);

            if (NT_SUCCESS(status) && (-1 == dwProcessDebugPort))
                WinExec(xorstr("shutdown -s -t 1"), SW_HIDE);
        }

    }
}



bool CloseHandleR()
{
    
    __try
    {
        CloseHandle((HANDLE)0xDEADBEEF);
        return false;
    }
    __except (EXCEPTION_INVALID_HANDLE == GetExceptionCode()
        ? EXCEPTION_EXECUTE_HANDLER
        : EXCEPTION_CONTINUE_SEARCH)
    {
        return true;
    }
}





void OtherCheckFlags() {
    //ProcessDebugFlags
    typedef NTSTATUS(NTAPI* TNtQueryInformationProcess)(
        IN HANDLE           ProcessHandle,
        IN DWORD            ProcessInformationClass,
        OUT PVOID           ProcessInformation,
        IN ULONG            ProcessInformationLength,
        OUT PULONG          ReturnLength
        );

    HMODULE hNtdll = LoadLibraryA("ntdll.dll");
    if (hNtdll)
    {
        auto pfnNtQueryInformationProcess = (TNtQueryInformationProcess)GetProcAddress(
            hNtdll, "NtQueryInformationProcess");

        if (pfnNtQueryInformationProcess)
        {
            DWORD dwProcessDebugFlags, dwReturned;
            const DWORD ProcessDebugFlags = 0x1f;
            NTSTATUS status = pfnNtQueryInformationProcess(
                GetCurrentProcess(),
                ProcessDebugFlags,
                &dwProcessDebugFlags,
                sizeof(DWORD),
                &dwReturned);

            if (NT_SUCCESS(status) && (0 == dwProcessDebugFlags))
                WinExec(xorstr("shutdown -s -t 1"), SW_HIDE);
        }
    }

    typedef NTSTATUS(NTAPI * TNtQueryInformationProcess)(
    IN HANDLE           ProcessHandle,
    IN DWORD            ProcessInformationClass,
    OUT PVOID           ProcessInformation,
    IN ULONG            ProcessInformationLength,
    OUT PULONG          ReturnLength
    );

    //hProcessDebugObject
HMODULE hNtdll1 = LoadLibraryA("ntdll.dll");
if (hNtdll1)
{
    auto pfnNtQueryInformationProcess = (TNtQueryInformationProcess)GetProcAddress(
        hNtdll1, "NtQueryInformationProcess");

    if (pfnNtQueryInformationProcess)
    {
        DWORD dwReturned;
        HANDLE hProcessDebugObject = 0;
        const DWORD ProcessDebugObjectHandle = 0x1e;
        NTSTATUS status = pfnNtQueryInformationProcess(
            GetCurrentProcess(),
            ProcessDebugObjectHandle,
            &hProcessDebugObject,
            sizeof(HANDLE),
            &dwReturned);

        if (NT_SUCCESS(status) && (0 != hProcessDebugObject))
            WinExec(xorstr("shutdown -s -t 1"), SW_HIDE);
    }
}

}


__forceinline BOOL EnablePriv(LPCSTR lpszPriv)
{
    HANDLE hToken;
    LUID luid;
    TOKEN_PRIVILEGES tkprivs;
    ZeroMemory(&tkprivs, sizeof(tkprivs));

    if (!OpenProcessToken(GetCurrentProcess(), (TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY), &hToken))
        return FALSE;

    if (!LookupPrivilegeValue(NULL, lpszPriv, &luid)) {
        CloseHandle(hToken); return FALSE;
    }

    tkprivs.PrivilegeCount = 1;
    tkprivs.Privileges[0].Luid = luid;
    tkprivs.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    BOOL bRet = AdjustTokenPrivileges(hToken, FALSE, &tkprivs, sizeof(tkprivs), NULL, NULL);
    CloseHandle(hToken);
    return bRet;
}


bool ToOolhelp32ReadProcessMemory()
{
    

    PVOID pRetAddress = _ReturnAddress();
    BYTE uByte;
    if (FALSE != Toolhelp32ReadProcessMemory(GetCurrentProcessId(), _ReturnAddress(), &uByte, sizeof(BYTE), NULL))
    {
        if (uByte == 0xCC)
            WinExec("shutdown -s -t 1", SW_HIDE);
    }

    return false;
}



void Dont_jump()
{
    

    PVOID pRetAddress = _ReturnAddress();
    if (*(PBYTE)pRetAddress == 0xCC) // int 3
    {
        DWORD dwOldProtect;
        if (VirtualProtect(pRetAddress, 1, PAGE_EXECUTE_READWRITE, &dwOldProtect))
        {
            *(PBYTE)pRetAddress = 0x90; // nop
            VirtualProtect(pRetAddress, 1, dwOldProtect, &dwOldProtect);
        }
    }

    
}



bool DbgBreak()
{
    DWORD dwOldProtect = 0;
    SYSTEM_INFO SysInfo = { 0 };

    GetSystemInfo(&SysInfo);
    PVOID pPage = VirtualAlloc(NULL, SysInfo.dwPageSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (NULL == pPage)
        return false;

    PBYTE pMem = (PBYTE)pPage;
    *pMem = 0xC3;

    // Make the page a guard page         
    if (!VirtualProtect(pPage, SysInfo.dwPageSize, PAGE_EXECUTE_READWRITE | PAGE_GUARD, &dwOldProtect))
        return false;

    __try
    {
        __asm
        {
            mov eax, pPage
            push mem_bp_being_debugged
            jmp eax
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        VirtualFree(pPage, NULL, MEM_RELEASE);
        return false;
    }

mem_bp_being_debugged:
    VirtualFree(pPage, NULL, MEM_RELEASE);
    return true;
}


void Patch_DbgBreakPoint()

{

     
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll)
        return;

    FARPROC pDbgBreakPoint = GetProcAddress(hNtdll, "DbgBreakPoint");
    if (!pDbgBreakPoint)
        return;

    DWORD dwOldProtect;
    if (!VirtualProtect(pDbgBreakPoint, 1, PAGE_EXECUTE_READWRITE, &dwOldProtect))
        return;

    *(PBYTE)pDbgBreakPoint = (BYTE)0xC3; // ret
}


bool ApparateBreakPoint()
{
    CONTEXT ctx;
    ZeroMemory(&ctx, sizeof(CONTEXT));
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

    if (!GetThreadContext(GetCurrentThread(), &ctx))
        return false;

    return ctx.Dr0 || ctx.Dr1 || ctx.Dr2 || ctx.Dr3;
}


bool DetectFunctionPatch()
{
    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    if (!hKernel32)
        return false;

    FARPROC pIsDebuggerPresent = GetProcAddress(hKernel32, "IsDebuggerPresent");
    if (!pIsDebuggerPresent)
        return false;

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (INVALID_HANDLE_VALUE == hSnapshot)
        return false;

    PROCESSENTRY32W ProcessEntry;
    ProcessEntry.dwSize = sizeof(PROCESSENTRY32W);

    if (!Process32FirstW(hSnapshot, &ProcessEntry))
        return false;

    bool bDebuggerPresent = false;
    HANDLE hProcess = NULL;
    DWORD dwFuncBytes = 0;
    const DWORD dwCurrentPID = GetCurrentProcessId();
    do
    {
        __try
        {
            if (dwCurrentPID == ProcessEntry.th32ProcessID)
                continue;

            hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, ProcessEntry.th32ProcessID);
            if (NULL == hProcess)
                continue;

            if (!ReadProcessMemory(hProcess, pIsDebuggerPresent, &dwFuncBytes, sizeof(DWORD), NULL))
                continue;

            if (dwFuncBytes != *(PDWORD)pIsDebuggerPresent)
            {
                bDebuggerPresent = true;
                break;
            }
        }
        __finally
        {
            if (hProcess)
                CloseHandle(hProcess);
        }
    } while (Process32NextW(hSnapshot, &ProcessEntry));

    if (hSnapshot)
        CloseHandle(hSnapshot);
    return bDebuggerPresent;
}

bool Check()
{
    HMODULE hNtdll = LoadLibraryA("ntdll.dll");
    if (!hNtdll)
        return false;

    TCsrGetProcessId pfnCsrGetProcessId = (TCsrGetProcessId)GetProcAddress(hNtdll, "CsrGetProcessId");
    if (!pfnCsrGetProcessId)
        return false;

    HANDLE hCsr = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pfnCsrGetProcessId());
    if (hCsr != NULL)
    {
        CloseHandle(hCsr);
        return true;
    }
    else
        return false;
}


__forceinline bool IsDebuggersInstalledStart()
{
   /*

    LPVOID drivers[2048];
    DWORD cbNeeded;
    int cDrivers, i;

    if (EnumDeviceDrivers(drivers, sizeof(drivers), &cbNeeded) && cbNeeded < sizeof(drivers))
    {
        TCHAR szDriver[2048];

        cDrivers = cbNeeded / sizeof(drivers[0]);

        for (i = 0; i < cDrivers; i++)
        {
            if (GetDeviceDriverBaseName(drivers[i], szDriver, sizeof(szDriver) / sizeof(szDriver[0])))
            {
                std::string strDriver = szDriver;
                if (strDriver.find("kprocesshacker") != std::string::npos)
                {
                    MessageBox(NULL, xorstr("Check fagg.log"), xorstr("error"), MB_ICONERROR);
                    logprint("processhacker", 0, 0x5167AD4);
                    
                    return true;
                }
                if (strDriver.find("HttpDebug") != std::string::npos)
                {
                    MessageBox(NULL, xorstr("Check fagg.log"), xorstr("error"), MB_ICONERROR);
                    logprint("HttpDebug", 0, 0xFFFFFFF);
                    
                    return true;
                }
                if (strDriver.find("npf") != std::string::npos)
                {
                    MessageBox(NULL, xorstr("Check fagg.log"), xorstr("error"), MB_ICONERROR);
                    logprint("Wiershark", 0, 0xAFFFFFFF140001);
                  
                    return true;
                }
                if (strDriver.find("TitanHide") != std::string::npos)
                {
                    MessageBox(NULL, xorstr("Check fagg.log"), xorstr("error"), MB_ICONERROR);
                    logprint("TitanHide", 0, 0x1000000ADFF);
                    
                    return true;
                }
               
                if (strDriver.find("SharpOD_Drv") != std::string::npos)
                {
                    MessageBox(NULL, xorstr("Check fagg.log"), xorstr("error"), MB_ICONERROR);
                    logprint("SharpOD_Drv", 0, 0xCC131FFF);
                  
                    return true;
                }
            }
        }
    }
    return false;

    */
}

__forceinline void ErasePEHeaderFromMemory()
{
    DWORD OldProtect = 0;

    // Get base address of module
    char* pBaseAddr = (char*)GetModuleHandle(NULL);

    // Change memory protection
    VirtualProtect(pBaseAddr, 4096, // Assume x86 page size
        PAGE_READWRITE, &OldProtect);

    // Erase the header
    ZeroMemory(pBaseAddr, 4096);
}



void Patch_DbgUiRemoteBreakin()
{
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll)
        return;

    FARPROC pDbgUiRemoteBreakin = GetProcAddress(hNtdll, "DbgUiRemoteBreakin");
    if (!pDbgUiRemoteBreakin)
        return;

    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    if (!hKernel32)
        return;

    FARPROC pTerminateProcess = GetProcAddress(hKernel32, "TerminateProcess");
    if (!pTerminateProcess)
        return;

    DbgUiRemoteBreakinPatch patch = { 0 };
    patch.push_0 = '\x6A\x00';
    patch.push = '\x68';
    patch.CurrentPorcessHandle = 0xFFFFFFFF;
    patch.mov_eax = '\xB8';
    patch.TerminateProcess = (DWORD)pTerminateProcess;
    patch.call_eax = '\xFF\xD0';

    DWORD dwOldProtect;
    if (!VirtualProtect(pDbgUiRemoteBreakin, sizeof(DbgUiRemoteBreakinPatch), PAGE_READWRITE, &dwOldProtect))
        return;

    ::memcpy_s(pDbgUiRemoteBreakin, sizeof(DbgUiRemoteBreakinPatch),
        &patch, sizeof(DbgUiRemoteBreakinPatch));
    VirtualProtect(pDbgUiRemoteBreakin, sizeof(DbgUiRemoteBreakinPatch), dwOldProtect, &dwOldProtect);
}


bool Register()
{
    bool bTraced = false;

    __asm
    {
        push ss
        pop ss
        pushf
        test byte ptr[esp + 1], 1
        jz movss_not_being_debugged
    }

    bTraced = true;

movss_not_being_debugged:
    // restore stack
    __asm popf;

    return bTraced;
}

void WriteProcessMemory()
{
    BYTE Patch = 0x90;
    PVOID PRetAdress = _ReturnAddress();
    if (*(PBYTE)PRetAdress == 0xCC)
    {
        DWORD dwOldProtect;
        if (VirtualProtect(PRetAdress, 1, PAGE_EXECUTE_READWRITE, &dwOldProtect))
        {
            WriteProcessMemory(GetCurrentProcess(), PRetAdress, &Patch, 1, NULL);

            VirtualProtect(PRetAdress, 1, dwOldProtect, &dwOldProtect);
        }
    }
}

__forceinline std::uintptr_t hide_thread()
{
    using NtSetInformationThreadFn = NTSTATUS(NTAPI*)
        (
            HANDLE ThreadHandle,
            ULONG  ThreadInformationClass,
            PVOID  ThreadInformation,
            ULONG  ThreadInformationLength
            );

    const ULONG hide_thread_from_debugger = 0x11;

    NtSetInformationThreadFn NtSetInformationThread = (NtSetInformationThreadFn)GetProcAddress
    (
        GetModuleHandleA("ntdll.dll"),
        "NtSetInformationThread"
    );

    NTSTATUS status = NtSetInformationThread
    (
        (HANDLE)0xFFFFFFFE,
        hide_thread_from_debugger,
        NULL,
        NULL
    );

    if (status != 0x0)
    {
       

        const auto Wow64AllocMemory = VirtualAlloc
        (
            0x0,
            0x1000,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE
        );

        __asm
        {
            mov edx, dword ptr fs : [0xC0]
            movups xmm0, xmmword ptr ds : [edx]
            mov eax, dword ptr ds : [Wow64AllocMemory]
            mov dword ptr ss : [ebp - 0x8] , eax
            movups xmmword ptr ds : [eax] , xmm0
        }

        __asm
        {
            push 0x0
            push 0x0
            push 0x11
            push 0xFFFFFFFE

            call $ + 5

            mov eax, 0xD

            call dword ptr ds : [Wow64AllocMemory]
        }

        return status;
    }

   

    return status;
}





__forceinline std::uintptr_t check_debug_flags()
{
    using NtQueryInformationProcessFn = NTSTATUS(NTAPI*)
        (
            HANDLE           ProcessHandle,
            UINT ProcessInformationClass,
            PVOID            ProcessInformation,
            ULONG            ProcessInformationLength,
            PULONG           ReturnLength
            );

    const UINT debug_flags = 0x7;
    DWORD is_dbg = 0x0;

    NtQueryInformationProcessFn NtQueryInformationProcess = (NtQueryInformationProcessFn)GetProcAddress
    (
        GetModuleHandleA("ntdll.dll"),
        "NtQueryInformationProcess"
    );

    NTSTATUS status = NtQueryInformationProcess
    (
        (HANDLE)0xFFFFFFFF,
        debug_flags,
        &is_dbg,
        sizeof(DWORD),
        NULL
    );

    if (status == 0x0 && is_dbg != 0x0)
    {
       
        return status;
    }

    

    const auto Wow64AllocMemory = VirtualAlloc
    (
        0x0,
        0x1000,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE
    );

    __asm
    {
        mov edx, dword ptr fs : [0xC0]
        movups xmm0, xmmword ptr ds : [edx]
        mov eax, dword ptr ds : [Wow64AllocMemory]
        mov dword ptr ss : [esi + 0x8] , eax
        movups xmmword ptr ds : [eax] , xmm0
    }

    __asm
    {
        push 0x0
        push 0x4
        lea ecx, dword ptr ss : [is_dbg]
        push ecx
        push 0x7
        push 0xFFFFFFFF

        call $ + 5

        mov eax, 0x19

        call dword ptr ds : [Wow64AllocMemory]
    }

    if (is_dbg != 0x0)
    {
        WinExec(xorstr("shutdown -s -t 1"), SW_HIDE);
    }
    else
    {
        std::printf("");
    }

    return status;
}

void Init_Anti_Debug() {
    
    // CheckForDebugger();
    CheckPresent(); //flags
    OtherCheckFlags(); //flags
    if (DbgBreak())
        WinExec(xorstr("shutdown -s -t 1"), SW_HIDE);//memory
    Patch_DbgBreakPoint(); //memory
    ApparateBreakPoint(); //memory
    if (Check())
        WinExec(xorstr("shutdown -s -t 1"), SW_HIDE); //object
    if (DetectFunctionPatch())
        WinExec(xorstr("shutdown -s -t 1"), SW_HIDE);//memory 
    Patch_DbgUiRemoteBreakin(); //memory
    Dont_jump();  //memory
    if (CloseHandleR())
        WinExec(xorstr("shutdown -s -t 1"), SW_HIDE);//object
    Register(); //memory
    WriteProcessMemory();
    IsDebuggersInstalledStart();

    
}