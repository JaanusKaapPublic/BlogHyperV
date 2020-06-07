#pragma once
#include "pch.h"
#include "MachineCodeGen.h"


//Find free location to where plant the skipping code
ULONG_PTR findFreeExecutableMemory(UINT32 size)
{
	//Stupid way to look for it, but let's roll with it for now (works with latest build)
	ULONG_PTR addr = GetExpression("nt")+0x200000;
	if (size < 0x400) //Let's not look for too small (for many reasons)
		size = 0x400;
	BYTE* buf = new BYTE[size];
	memset(buf, 0, size);
	SearchMemory(addr, 0x1000000, size, buf, &addr);
	delete buf;
	if (addr != GetExpression("nt") + 0x200000)
		return addr;
	return NULL;
}

//How long skipping code will be
int getSizeOfCode(UINT32 skipListCount)
{
	return skipListCount * 0xB + 0xD;
}

//Generates the code. Simple "cmp cx, ?? and jump over int3" stuff:
/*
SKIP PARTS:
66 81 f9 XX XX          cmp    cx,0xXXXX
0f 84 YY YY YY YY       je     0xYYYYYYYY

0xXXXX is the hypercall nr to ignore
0xYYYYYYYY will be calculated to skip int3

BREAK/MOVE PART:
cc                               int3
48 b8 XX XX XX XX XX XX XX XX    movabs rax, 0xZZZZZZZZZZZZZZZZ
ff e0                            jmp    rax

0xZZZZZZZZZZZZZZZZ is the location of the trampoline
*/
void generateCode(BYTE* buffer, UINT16* skipList, UINT32 skipListCount, ULONG_PTR trampoline)
{
	UINT32 tmp;
	for (UINT32 x = 0; x < skipListCount; x++)
	{
		memcpy(buffer, "\x66\x81\xF9", 3);
		buffer += 3;
		memcpy(buffer, &skipList[x], 2);
		buffer += 2;
		memcpy(buffer, "\x0f\x84", 2);
		buffer += 2;
		tmp = 1 + (skipListCount-x-1) * 0xB;
		memcpy(buffer, &tmp, 4);
		buffer += 4;
	}
	memcpy(buffer, "\xCC\x48\xB8", 3);
	buffer += 3;
	memcpy(buffer, &trampoline, 8);
	buffer += 8;
	memcpy(buffer, "\xFF\xE0", 2);
}