#pragma once
#include <iostream>
#include <Windows.h>
#include <string>
#include <TlHelp32.h>
#include <fstream>
#include <stdio.h>
#include <winternl.h>
#include <intrin.h>
#include <WinUser.h>
#include <Psapi.h>

#include <winternl.h>
#include <winnt.h>
#include <thread>


void CheckPresent();
void OtherCheckFlags();
bool DbgBreak();
bool ApparateBreakPoint();
bool DetectFunctionPatch();
void Patch_DbgUiRemoteBreakin();
bool Check();
bool CloseHandleR();
 //void CheckForDebugger();
void Dont_jump();
//bool ToOolhelp32ReadProcessMemory();
bool Register();
void WriteProcessMemory();
__forceinline bool IsDebuggersInstalledStart();
void Init_Anti_Debug();
bool ToOolhelp32ReadProcessMemory();
__forceinline std::uintptr_t check_debug_flags();
__forceinline std::uintptr_t hide_thread();