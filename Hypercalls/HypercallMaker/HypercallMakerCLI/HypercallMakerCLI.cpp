#include <iostream>
#include <string>
#include <Windows.h>
#include <iostream>
#include <fstream>
#include "Definitions.h"

bool devIOctrl(DWORD code, PVOID inBuffer, DWORD inBufferSize, PVOID outBuffer, UINT32* outBufferSize)
{
    HANDLE handle = CreateFile(L"\\\\.\\HypercallMaker", GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);

    if (handle == INVALID_HANDLE_VALUE)
    {
        std::cout << "Could not open handle to driver" << std::endl;
        return false;
    }

    bool result = false;
    DWORD recv, outBufferSizeVal = 0;
    if (outBufferSize)
        outBufferSizeVal = *outBufferSize;

    printf("Sending code 0x%X with 0x%X sized buffer, waiting back 0x%X bytes\n", code, inBufferSize, outBufferSizeVal);
    if (DeviceIoControl(handle, code, inBuffer, inBufferSize, outBuffer, outBufferSizeVal, &recv, NULL))
    {
        result = true;
        if (outBufferSize)
            *outBufferSize = recv;
    }
    return result;
}

UINT64 str2long(std::string input)
{
    if (input.substr(0, 2) == "0x")
        return std::stoll(input.substr(2), NULL, 16);
    else
        return std::stoll(input, NULL, 10);
}

void help()
{
    std::cout << "Correct syntax: HypercallMakerCLI {code} {input file} {output file} [output size]" << std::endl;
    exit(0);
}

int main(int argc, char* argv[])
{
    if (argc < 4 || argc > 6)
        help();

    PHV_X64_HYPERCALL_INPUT code;
    char *bufferIn = NULL, *bufferOut = NULL;
    UINT32 bufferInLen = 0, bufferOutLen = 0;
    UINT64 tmp;

    tmp = str2long(argv[1]);
    code = (PHV_X64_HYPERCALL_INPUT)&tmp;

    if (!code->fast && argc != 5)
    {
        std::cout << "This is not fast hypercall so you need to add length of the output you are expecting";
        return 0;
    }
    else
    {
        if (code->fast)
            bufferOutLen = sizeof(HV_X64_HYPERCALL_OUTPUT);
        else
            bufferOutLen = str2long(argv[4]) + sizeof(HV_X64_HYPERCALL_OUTPUT);

        bufferOut = new char[bufferOutLen];
    }

    try
    {
        std::ifstream fileIn(argv[2], std::ifstream::binary);
        std::filebuf* buf = fileIn.rdbuf();
        bufferInLen = buf->pubseekoff(0, fileIn.end, fileIn.in);

        if (code->fast && bufferInLen != 16)
        {
            std::cout << "In fast hypercalls the input buffer has to be 16 bytes" << std::endl;
            return 0;
        }

        buf->pubseekpos(0, fileIn.in);
        bufferIn = new char[bufferInLen + sizeof(HV_X64_HYPERCALL_INPUT)];
        buf->sgetn(bufferIn + 8, bufferInLen);
        fileIn.close();
        memcpy(bufferIn, code, sizeof(HV_X64_HYPERCALL_INPUT));
    }
    catch (...)
    {
        std::cout << "Could not read input file: " << argv[2] << std::endl;
        return 0;
    }

    std::cout << "Sending hypercall:" << std::endl;
    std::cout << "  call code: 0x" << std::hex << code->callCode << std::endl;
    std::cout << "  fast: 0x" << std::hex << code->fast << std::endl;
    std::cout << "  variable header size: 0x" << std::hex << code->varHdrrSize << std::endl;
    std::cout << "  nested: 0x" << std::hex << code->isNested << std::endl;
    std::cout << "  rep count: 0x" << std::hex << code->repCount << std::endl;
    std::cout << "  rep start: 0x" << std::hex << code->repStart << std::endl << std::endl;

    if(!devIOctrl(IOCTL_MAKE_HYPERCALL, bufferIn, bufferInLen + 8, bufferOut, &bufferOutLen))
    {
        std::cout << "Sending hypercall failed" << std::endl;
        return 0;
    }

    PHV_X64_HYPERCALL_OUTPUT output = (PHV_X64_HYPERCALL_OUTPUT)bufferOut;
    std::cout << "Result:" << std::endl;
    std::cout << "  code: " << std::hex << output->result << std::endl;
    std::cout << "  reps completed: " << std::hex << output->repsCompleted << std::endl;
    
    try
    {
        if (bufferOutLen > sizeof(HV_X64_HYPERCALL_OUTPUT))
        {
            std::ofstream out(argv[3], std::ios::binary | std::ios::out);
            out.write(bufferOut + sizeof(HV_X64_HYPERCALL_OUTPUT), bufferOutLen - sizeof(HV_X64_HYPERCALL_OUTPUT));
            out.close();
        }
    }
    catch (...)
    {
        std::cout << "Could not write output file: " << argv[3] << std::endl;
        return 0;
    }
}