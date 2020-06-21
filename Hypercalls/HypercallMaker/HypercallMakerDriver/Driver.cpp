#include<ntddk.h>
#include "Definitions.h"
#include "Hypercall.h"

#define DEVICE_NAME L"\\Device\\HypercallMaker"
#define SYMBOLIC_LINK_NAME L"\\DosDevices\\HypercallMaker"

//Handler for opening & closing driver device
NTSTATUS TracedrvDispatchOpenClose(IN PDEVICE_OBJECT pDO, IN PIRP Irp)
{
	UNREFERENCED_PARAMETER(pDO);
	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;
	PAGED_CODE();
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

//When driver is unloaded
VOID DriverUnload(PDRIVER_OBJECT  DriverObject)
{
	UNICODE_STRING usDosDeviceName;
	RtlInitUnicodeString(&usDosDeviceName, SYMBOLIC_LINK_NAME);
	IoDeleteSymbolicLink(&usDosDeviceName);
	IoDeleteDevice(DriverObject->DeviceObject);
}

//DeviceIoControl request handler
NTSTATUS DriverIoControl(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	UNREFERENCED_PARAMETER(DeviceObject);
	NTSTATUS ntStatus = STATUS_NOT_SUPPORTED;
	ULONGLONG dataLen = 0;

	//Current IRP stack location
	PIO_STACK_LOCATION pIoStackIrp = IoGetCurrentIrpStackLocation(Irp);

	//Is this call to make hypercall
	if (pIoStackIrp->Parameters.DeviceIoControl.IoControlCode == IOCTL_MAKE_HYPERCALL)
	{
		//Lengths and they checks
		UINT32 lenIn = pIoStackIrp->Parameters.DeviceIoControl.InputBufferLength;
		UINT32 lenOut = pIoStackIrp->Parameters.DeviceIoControl.OutputBufferLength;
		if (lenIn < sizeof(HV_X64_HYPERCALL_INPUT))
			return STATUS_NDIS_INVALID_LENGTH;
		if (lenOut < sizeof(HV_X64_HYPERCALL_OUTPUT))
			return STATUS_BUFFER_OVERFLOW;

		//Input code is the first 8 bytes of the input buffer
		PHV_X64_HYPERCALL_INPUT inputCode = (PHV_X64_HYPERCALL_INPUT)Irp->AssociatedIrp.SystemBuffer;
		PHV_X64_HYPERCALL_OUTPUT outputCode = (PHV_X64_HYPERCALL_OUTPUT)Irp->AssociatedIrp.SystemBuffer;

		//Everything after the first 8 bytes in the buffer, is the input for the hypercall
		unsigned char* buffer = ((unsigned char*)Irp->AssociatedIrp.SystemBuffer) + 8;

		ntStatus = hypercall(*inputCode, buffer, lenIn - sizeof(HV_X64_HYPERCALL_INPUT), buffer, lenOut - sizeof(HV_X64_HYPERCALL_OUTPUT), outputCode);
		dataLen = lenOut;
	}

	Irp->IoStatus.Status = ntStatus;
	Irp->IoStatus.Information = dataLen;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return ntStatus;
}

//Gets everything going after driver load
extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegistryPath)
{
	UNREFERENCED_PARAMETER(pRegistryPath);

	NTSTATUS NtStatus = STATUS_SUCCESS;
	PDEVICE_OBJECT pDeviceObject = NULL;
	UNICODE_STRING usDriverName, usDosDeviceName;

	//What Major functions are handled
	pDriverObject->MajorFunction[IRP_MJ_CLOSE] = TracedrvDispatchOpenClose;
	pDriverObject->MajorFunction[IRP_MJ_CREATE] = TracedrvDispatchOpenClose;
	pDriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DriverIoControl;

	//Lets create an device and symboli link to it("HypercallMaker")
	RtlInitUnicodeString(&usDriverName, DEVICE_NAME);
	RtlInitUnicodeString(&usDosDeviceName, SYMBOLIC_LINK_NAME);
	NtStatus = IoCreateDevice(pDriverObject, 0, &usDriverName, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &pDeviceObject);
	if (NtStatus == STATUS_SUCCESS)
	{
		IoCreateSymbolicLink(&usDosDeviceName, &usDriverName);
		pDriverObject->DriverUnload = DriverUnload;
	}
	return NtStatus;
}