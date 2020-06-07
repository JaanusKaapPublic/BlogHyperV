
#include "pch.h"
#define KDEXT_64BIT 
#include <Wdbgexts.h>
#include <Dbgeng.h>
#include <string>
#include "HypercallNames.h"
#include "MachineCodeGen.h"

//Types of environments we can be debugging
enum class Environment
{
	HYPERVISOR, //We are debugging Hypervisor
	KERNEL, //We are debugging kernel
	UNKNOWN //Hell if I know, what we are debugging
};

//Hypercall code structure
typedef struct _HV_X64_HYPERCALL_INPUT
{
	UINT32 callCode : 16;
	UINT32 Fast : 1;
	UINT32 varHdrrSize : 9;
	UINT32 dontCare1 : 5;
	UINT32 isNested : 1; UINT32 repCount : 12;
	UINT32 dontCare2 : 4;
	UINT32 repStart : 12;
	UINT32 dontCare3 : 4;
} HV_X64_HYPERCALL_INPUT, * PHV_X64_HYPERCALL_INPUT;

//Hypercall response structure
typedef struct _HV_X64_HYPERCALL_OUTPUT
{
	unsigned short result;
	UINT16 dontCare1;
	UINT32 repsCompleted : 12;
	UINT32 dontCare2 : 20;
} HV_X64_HYPERCALL_OUTPUT, * PHV_X64_HYPERCALL_OUTPUT;

//Some stuff needed by Windbg
EXT_API_VERSION g_ExtApiVersion = { 5, 5, EXT_API_VERSION_NUMBER64, 0 };
WINDBG_EXTENSION_APIS ExtensionApis = { 0 };

//Our globals
Environment env;
ULONG_PTR trampoline = NULL, oldInjection = NULL;
UINT32 oldSize = 0;


//Some of our functions (not exports) 
void showEnvironment(void);
void detectEnvironment(void);
void setEnvironment(PCSTR envIn);

//Well... DllMain of couse (we do nothing)
BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}

//Windbg needed version info
CPPMOD __declspec(dllexport)  LPEXT_API_VERSION WDBGAPI ExtensionApiVersion(void)
{
	return &g_ExtApiVersion;
}

//Windbg based initialization function
CPPMOD __declspec(dllexport)  VOID WDBGAPI WinDbgExtensionDllInit(PWINDBG_EXTENSION_APIS lpExtensionApis, USHORT usMajorVersion, USHORT usMinorVersion)
{
	ExtensionApis = *lpExtensionApis;
	detectEnvironment();
}

//Show where we are running
void showEnvironment(void)
{
	switch (env)
	{
	case Environment::HYPERVISOR:
		dprintf("[INFO] We seem to be running on hypervisor\n");
		break;
	case Environment::KERNEL:
		dprintf("[INFO] We seem to be running on kernel\n");
		break;
	case Environment::UNKNOWN:
		dprintf("[WARNING] We seem to be running on something weird.... Don't know what happened\n");
		break;
	}
}

//We try to detect where we are running
void detectEnvironment(void)
{
	if (GetExpression("hv"))
		env = Environment::HYPERVISOR;
	else if (GetExpression("nt"))
		env = Environment::KERNEL;
	else
		env = Environment::UNKNOWN;
	showEnvironment();
	dprintf("[INFO] If environment was wrong then set it manually by running: !hc_env [hypervisor/kernel]\n");
}

//Change the environment
void setEnvironment(PCSTR envIn)
{
	if (!strcmp(envIn, "hypervisor"))
		env = Environment::HYPERVISOR;
	else if (!strcmp(envIn, "kernel"))
		env = Environment::KERNEL;
	else
		dprintf("[WARNING] Incorrect environment type selected \n");
	showEnvironment();
}


//Windbg command !hv_env [environment]
CPPMOD __declspec(dllexport) VOID hc_env(HANDLE hCurrentProcess, HANDLE hCurrentThread, ULONG dwCurrentPc, ULONG dwProcessor, PCSTR args)
{
	if (!args || *args == 0)
		showEnvironment();
	else
		setEnvironment(args);
}

//Windbg command !hv_list [hypercall nr]
CPPMOD __declspec(dllexport) VOID hc_list(HANDLE hCurrentProcess, HANDLE hCurrentThread, ULONG dwCurrentPc, ULONG dwProcessor, PCSTR args)
{
	//Are we debugging hypervisor?
	if (env != Environment::HYPERVISOR)
	{
		dprintf("[ERROR] This command should be executed when debugging hypervisor!\n");
		return;
	}

	ULONG_PTR addr, noCall, handler;
	UINT32 start = 1, end = 0x100;

	//Parsing user arguments (only single value option for now, will improve in future)
	if (strlen(args) > 0)
	{
		try
		{
			start = std::stoi(args, 0, 10);
			end = start + 1;
		}
		catch (...) //Not nice, but we really don't care the reason
		{
			dprintf("[ERROR] Invalid number for hypercall\n");
		}
	}
	
	//Where is hypervisors base address
	addr = GetExpression("hv");
	if (!addr)
	{
		dprintf("[ERROR] This is very weird - can't find base address of 'hv'\n");
		return;
	}

	//This is twhere the table locates (hv+0xC00000)
	addr += 0xC00000;

	//Hypercall 0 does not exist so we can use it's handler address to detect where unused hypercall nr are redirected
	ReadMemory(addr, &noCall, sizeof(noCall), NULL);

	//Lets loop some
	for(UINT32 nr = start; nr < end; nr++)
	{
		addr += 0x18;
		//Handler address
		if (!ReadMemory(addr, &handler, sizeof(handler), NULL))
			break;
		//No handler == no more hypercalls
		if (!handler)
			break;

		//Display info
		dprintf("hypercall 0x%02x: %I64x", nr, handler);
		if (handler == noCall)
			dprintf("  [NOT ACTIVE/IMPLEMENTED HYPERCALL]\n");
		else
			dprintf("  %s\n", HypercallNames[nr].c_str()); //TODO: add limits
	}
}

//Windbg command !hv_filter [list of hypercalls to filter out, seperated by spaces]
CPPMOD __declspec(dllexport) VOID hc_filter(HANDLE hCurrentProcess, HANDLE hCurrentThread, ULONG dwCurrentPc, ULONG dwProcessor, PCSTR args)
{
	UINT32 codeCount = 0, len;
	UINT16 codes[0x100];
	ULONG_PTR ptr;
	PCSTR tmp = args;

	//Just parsing input (string of numbers -> array)
	do
	{
		args++;
		if (*args == ' ' || !*args)
		{
			if (tmp != args && *tmp)
			{
				if (codeCount >= 0x100)
				{
					dprintf("[ERROR] Too many hypercall\n");
					return;
				}
				try
				{
					codes[codeCount++] = std::stoi(tmp, 0, 10);
					tmp = args + 1;
				}
				catch (...) //Not nice, but we really don't care the reason
				{
					dprintf("[ERROR] Invalid number for hypercall\n");
					return;
				}
			}
			else
			{
				tmp++;
			}
		}
	} while (*args);

	//If there was some snippet already injected, then re overwrite it back to zeros
	if (oldInjection)
	{
		BYTE* buf = new BYTE[oldSize];
		memset(buf, 0, oldSize);
		WriteMemory(oldInjection, buf, oldSize, NULL);
		oldInjection = NULL;
		oldSize = 0;
	}

	//If no codes were selected, then we redirect nt!HvcallCodeVa to trampoline
	if (codeCount == 0)
	{
		dprintf("[INFO] Restoring original status\n");
		WriteMemory(GetExpression("nt!HvcallCodeVa"), &trampoline, sizeof(ptr), NULL);
		oldInjection = NULL;
		oldSize = 0;
		return;
	}

	//Determine the size of code and then try to find it
	len = getSizeOfCode(codeCount);
	ptr = findFreeExecutableMemory(len);
	if (!ptr)
	{
		dprintf("[ERROR] Could not find empty memory in target for code injection");
		return;
	}
	dprintf("[INFO] We need 0x%X (%d) bytes of memory for injection code\n", len, len);
	dprintf("[INFO] Found free memory @ 0x%P, hope it is executable (haven't added check yet)\n", ptr);

	//If it's our first time, then find out the trampoline pointer and store it for future
	if (!trampoline)
	{
		if (!ReadMemory(GetExpression("nt!HvcallCodeVa"), &trampoline, sizeof(trampoline), NULL))
		{
			dprintf("[ERROR] Could not find trampline pointer");
			return;
		}
	}
	dprintf("[INFO] Trampoline @ 0x%P\n", trampoline);
	
	//Generate and inject the code
	BYTE* buf = new BYTE[len];
	generateCode(buf, codes, codeCount, trampoline);
	WriteMemory(ptr, buf, len, NULL);
	WriteMemory(GetExpression("nt!HvcallCodeVa"), &ptr, sizeof(ptr), NULL);
	oldInjection = (ULONG_PTR)ptr;
	oldSize = len;
	delete buf;
}

//Decoding of hypercall code value
CPPMOD __declspec(dllexport) VOID hc_code(HANDLE hCurrentProcess, HANDLE hCurrentThread, ULONG dwCurrentPc, ULONG dwProcessor, PCSTR args)
{
	if (!args || *args == 0)
	{
		dprintf("[ERROR] You did not specify code value");
		return;
	}

	ULONG_PTR codeInt = GetExpression(args);
	PHV_X64_HYPERCALL_INPUT code = (PHV_X64_HYPERCALL_INPUT)&codeInt;

	dprintf("Hypercall code 0x%X (%d)\n", codeInt, codeInt);
	dprintf("  hypercall nr: 0x%X (%d)\n", code->callCode, code->callCode);
	dprintf("  fast call: 0x%X (%d)\n", code->Fast, code->Fast);
	dprintf("  variable header size: 0x%X (%d)\n", code->varHdrrSize, code->varHdrrSize);
	dprintf("  nested: 0x%X (%d)\n", code->isNested, code->isNested);
	dprintf("  rep count: 0x%X (%d)\n", code->repCount, code->repCount);
	dprintf("  rep start: 0x%X (%d)\n", code->repStart, code->repStart);
}

//Decoding of hypercall result value
CPPMOD __declspec(dllexport) VOID hc_result(HANDLE hCurrentProcess, HANDLE hCurrentThread, ULONG dwCurrentPc, ULONG dwProcessor, PCSTR args)
{
	if (!args || *args == 0)
	{
		dprintf("[ERROR] You did not specify result value");
		return;
	}

	ULONG_PTR codeInt = GetExpression(args);
	PHV_X64_HYPERCALL_OUTPUT code = (PHV_X64_HYPERCALL_OUTPUT)&codeInt;


	dprintf("Hypercall result 0x%X (%d)\n", codeInt, codeInt);
	dprintf("  result code: 0x%X (%d)\n", code->result, code->result);
	dprintf("  reps finished: 0x%X (%d)\n", code->repsCompleted, code->repsCompleted);
}

//Help message
CPPMOD __declspec(dllexport) VOID hc_help(HANDLE hCurrentProcess, HANDLE hCurrentThread, ULONG dwCurrentPc, ULONG dwProcessor, PCSTR args)
{
	dprintf("Hypercall tool to accompany Hyper-V blog series by Jaanus Kaap (@FoxHex0ne)\n\n");
	dprintf("Currently available commands:\n");
	dprintf("  !hc_env [environment]\n");
	dprintf("    Can give info about in what environment the tool thinks it's running and allows to change it (hypervisor/kernel)\n\n");
	dprintf("  !hc_list [hypercall number]\n");
	dprintf("    Shows list of hypercalls, their handlers and names (if known). If hypercall number is provided, then shows only that\n\n");
	dprintf("  !hc_filter [hypercall numbers to ignore, seperated by spaces]\n");
	dprintf("    Injects int3 and additional snippet of machinecode to break before hypercalls but only for hypercalls not in the list\n");
	dprintf("    Example: '!hv_filter 2 3' will start causing breaks with all hypercalls, except 2 and 3\n\n");
	dprintf("  !hc_code {code}\n");
	dprintf("    Decodes hypercall code value\n\n");
	dprintf("  !hc_result {result}\n");
	dprintf("    Decodes hypercall result value\n\n");
	dprintf("  !hc\n");
	dprintf("    Displays this info\n\n");
	dprintf("  !hc_help\n");
	dprintf("    Displays this info\n\n");

}

//Redirect to help message
CPPMOD __declspec(dllexport) VOID hc(HANDLE hCurrentProcess, HANDLE hCurrentThread, ULONG dwCurrentPc, ULONG dwProcessor, PCSTR args)
{
	hc_help(hCurrentProcess, hCurrentThread, dwCurrentPc, dwProcessor, args);
}