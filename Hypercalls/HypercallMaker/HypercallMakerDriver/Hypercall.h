#pragma once
#include<ntddk.h>
#include"Definitions.h"

extern "C" NTSYSAPI HV_X64_HYPERCALL_OUTPUT NTAPI HvlInvokeHypercall(HV_X64_HYPERCALL_INPUT InputValue, ULONGLONG InputPa, ULONGLONG OutputPa);

NTSTATUS generateMDL(ULONG size, PULONGLONG pa, PMDL* mdl, PVOID* ptr);
NTSTATUS generateMDLs(PVOID inBuffer, ULONG inBufferSize, ULONG outBufferSize, PULONGLONG inPA, PMDL* inMdl, PULONGLONG outPA, PMDL* outMdl);
NTSTATUS hypercall(HV_X64_HYPERCALL_INPUT hvInput, void* bufferIn, UINT32 bufferInLen, void* bufferOut, UINT32 bufferOutLen, PHV_X64_HYPERCALL_OUTPUT hvOutput);