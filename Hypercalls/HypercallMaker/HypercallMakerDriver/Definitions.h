#pragma once
#define IOCTL_MAKE_HYPERCALL CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)

typedef unsigned short HV_STATUS;

typedef struct _HV_X64_HYPERCALL_INPUT
{
    unsigned int callCode : 16;
    unsigned int fast : 1;
    unsigned int varHdrrSize : 9;
    unsigned int dontCare1 : 5;
    unsigned int isNested : 1;
    unsigned int repCount : 12;
    unsigned int dontCare2 : 4;
    unsigned int repStart : 12;
    unsigned int dontCare3 : 4;
} HV_X64_HYPERCALL_INPUT, * PHV_X64_HYPERCALL_INPUT;

typedef struct _HV_X64_HYPERCALL_OUTPUT
{
    HV_STATUS result;
    unsigned short dontCare1;
    unsigned int repsCompleted : 12;
    unsigned int dontCare2 : 20;
} HV_X64_HYPERCALL_OUTPUT, * PHV_X64_HYPERCALL_OUTPUT;