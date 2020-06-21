#include "Hypercall.h"


//Getting contiguous (physical) memory pages
NTSTATUS generateMDL(ULONG size, PULONGLONG pa, PMDL* mdl, PVOID* ptr)
{
	PHYSICAL_ADDRESS low, high;
	NTSTATUS status = STATUS_SUCCESS;
	low.QuadPart = 0;
	high.QuadPart = ~0ULL;
	*mdl = NULL;

#	//Requesting contiguous (physical) memory pages
	*mdl = MmAllocatePartitionNodePagesForMdlEx(low, high, low, ROUND_TO_PAGES(size), MmCached, KeGetCurrentNodeNumber(), MM_ALLOCATE_REQUIRE_CONTIGUOUS_CHUNKS | MM_ALLOCATE_FULLY_REQUIRED | MM_DONT_ZERO_ALLOCATION, NULL);
	if (!(*mdl))
	{
		status = STATUS_INSUFFICIENT_RESOURCES;
		return status;
	}


	//Getting virtual address for these pages
	if (status == STATUS_SUCCESS && ptr)
	{
		*ptr = MmGetSystemAddressForMdlSafe(*mdl, MdlMappingNoExecute);
		if (!(*ptr))
			status = STATUS_INSUFFICIENT_RESOURCES;
	}

	//Getting physical address
	if (status == STATUS_SUCCESS)
		*pa = *MmGetMdlPfnArray(*mdl) << PAGE_SHIFT;

	//If we failed then release memory
	if (status != STATUS_SUCCESS)
	{
		MmFreePagesFromMdlEx(*mdl, 0);
		ExFreePool(*mdl);
	}
	return status;
}

//Getting input and output memory buffers for hypercall
NTSTATUS generateMDLs(PVOID inBuffer, ULONG inBufferSize, ULONG outBufferSize, PULONGLONG inPA, PMDL* inMdl, PULONGLONG outPA, PMDL* outMdl)
{
	NTSTATUS status = STATUS_SUCCESS;
	PVOID inPtr, outPtr;

	*inPA = NULL;
	*inMdl = NULL;
	*outPA = NULL;
	*outMdl = NULL;

	//Input buffer(if needed)
	if (inBufferSize)
	{
		status = generateMDL(inBufferSize, inPA, inMdl, &inPtr);
		if (status != STATUS_SUCCESS)
		{
			return status;
		}
		RtlCopyMemory(inPtr, inBuffer, inBufferSize);
	}
	//Output buffer(if needed)
	if (outBufferSize)
	{
		status = generateMDL(outBufferSize, outPA, outMdl, &outPtr);
		if (status != STATUS_SUCCESS)
		{
			if (*inMdl)
			{
				MmFreePagesFromMdlEx(*inMdl, 0);
				ExFreePool(*inMdl);
			}
			*inMdl = NULL;
			return status;
		}
		RtlZeroMemory(outPtr, outBufferSize);
	}
	return status;
}

//Function for doing hypercalls
NTSTATUS hypercall(HV_X64_HYPERCALL_INPUT hvInput, void* bufferIn, UINT32 bufferInLen, void* bufferOut, UINT32 bufferOutLen, PHV_X64_HYPERCALL_OUTPUT hvOutput)
{
	NTSTATUS status = STATUS_SUCCESS;
	ULONGLONG inPA, outPA;
	PMDL inMdl = NULL, outMdl = NULL;

	//fast hypercall input buffer has to be 16 bytes (2 x 8byte registers)
	if (hvInput.fast && bufferInLen != 16)
		return STATUS_NDIS_INVALID_LENGTH;

	if (hvInput.fast)
	{
		//Converting input buffer to two 8byte registers
		inPA = ((ULONGLONG*)bufferIn)[0];
		outPA = ((ULONGLONG*)bufferIn)[1];
	}
	else
	{
		//Generating buffers and getting their physuical addresses
		status = generateMDLs(bufferIn, bufferInLen, bufferOutLen, &inPA, &inMdl, &outPA, &outMdl);
	}


	if (status == STATUS_SUCCESS)
	{
		__try
		{
			//Doing the hypercall (function exported by kernel)
			* hvOutput = HvlInvokeHypercall(hvInput, inPA, outPA);
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			status = STATUS_ILLEGAL_INSTRUCTION;
		}
	}

	if (status == STATUS_SUCCESS && !hvInput.fast)
	{
		if (hvOutput->result == 0x0)
		{
			//Getting the output of the hypercall
			void* ptr = MmGetSystemAddressForMdlSafe(outMdl, NormalPagePriority);
			if (ptr)
			{
				RtlCopyMemory(bufferOut, ptr, bufferOutLen);
			}
			else
			{
				status = STATUS_INSUFFICIENT_RESOURCES;
			}
		}
	}
	if (inMdl)
	{
		//Freeing memory
		MmFreePagesFromMdlEx(inMdl, 0);
		ExFreePool(inMdl);
	}
	if (outMdl)
	{
		//Freeing memory
		MmFreePagesFromMdlEx(outMdl, 0);
		ExFreePool(outMdl);
	}
	return status;
}