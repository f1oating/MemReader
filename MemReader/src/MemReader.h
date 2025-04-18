#pragma once

#include "Windows.h"
#include "TlHelp32.h"
#include <psapi.h>
#include <cstring>
#include <stdexcept>
#include <string>

class MemReader
{
public:
    MemReader(const wchar_t* procName, UINT64 bufferSize = 32);
    ~MemReader();

    void Open(DWORD accessRights = PROCESS_ALL_ACCESS);
    void Close();

    void Write(void* ptr, uintptr_t to, UINT64 size, DWORD memProtect = PAGE_EXECUTE_READWRITE);
    MemReader& Read(uintptr_t from, UINT64 size, DWORD memProtect = PAGE_READWRITE);

    uintptr_t ReadPointer(uintptr_t base, const uintptr_t* offsets, UINT64 count);

    uintptr_t Alloc(UINT64 size, DWORD memProtect = PAGE_EXECUTE_READWRITE);
    void Free(uintptr_t ptr);

    uintptr_t FindSignature(uintptr_t base, size_t size, byte* sign, char* mask);

    void GetModuleInfo(const wchar_t* moduleName, MODULEENTRY32* mInfo, bool aboutProccess = false);
    
    DWORD GetPID() const { return m_id; }

    double ToDouble() const;
    float ToFloat() const;
    UINT64 ToUINT64() const;
    INT64 ToINT64() const;
    UINT32 ToUINT32() const;
    int ToINT32() const;
    UINT16 ToUINT16() const;
    short int ToINT16() const;
    UINT8 ToUINT8() const;
    char ToINT8() const;
    const char* ToStringA() const;
    const wchar_t* ToStringW() const;

private:
    wchar_t* m_name;
    HANDLE m_proc;
    DWORD m_id;
    byte* m_buffer;
    UINT64 m_bufferSize;

private:
    void SearchProcess();
    bool DataCompare(byte* data, byte* sign, char* mask);

};