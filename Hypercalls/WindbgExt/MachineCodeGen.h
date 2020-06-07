#pragma once
#include "pch.h"
#include <Wdbgexts.h>
#include <Dbgeng.h>



ULONG_PTR findFreeExecutableMemory(UINT32 size);
void clearUsedTargetMemory(ULONG_PTR addr, UINT32 size);
int getSizeOfCode(UINT32 skipListCount);
void generateCode(BYTE* buffer, UINT16* skipList, UINT32 skipListCount, ULONG_PTR trampoline);