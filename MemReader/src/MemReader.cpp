#include "MemReader.h"

MemReader::MemReader(const wchar_t* procName, UINT64 bufferSize)
    : m_name(nullptr), m_proc(nullptr), m_id(0), m_buffer(nullptr), m_bufferSize(bufferSize)
{
    UINT64 len = wcslen(procName) + 1;
    m_name = new wchar_t[len];
    wcscpy_s(m_name, len, procName);

    m_buffer = new byte[bufferSize]();
}

MemReader::~MemReader()
{
    Close();
    delete[] m_name;
    delete[] m_buffer;
}

void MemReader::Open(DWORD accessRights)
{
    SearchProcess();

    if (m_id != 0)
    {
        m_proc = OpenProcess(accessRights, FALSE, m_id);
        if (!m_proc)
        {
            throw std::runtime_error("Failed to open process.");
        }
    }
    else
    {
        throw std::runtime_error("Process not found.");
    }
}

void MemReader::Close()
{
    if (m_proc)
    {
        CloseHandle(m_proc);
        m_proc = nullptr;
    }
}

void MemReader::Write(void* ptr, uintptr_t to, UINT64 size, DWORD memProtect)
{
    DWORD oldMemProtect;
    if (VirtualProtectEx(m_proc, reinterpret_cast<LPVOID>(to), size, memProtect, &oldMemProtect))
    {
        if (!WriteProcessMemory(m_proc, reinterpret_cast<LPVOID>(to), ptr, size, nullptr))
        {
            throw std::runtime_error("Failed to write memory.");
        }
        VirtualProtectEx(m_proc, reinterpret_cast<LPVOID>(to), size, oldMemProtect, &oldMemProtect);
    }
    else
    {
        throw std::runtime_error("Failed to change memory protection.");
    }
}

MemReader& MemReader::Read(uintptr_t from, UINT64 size, DWORD memProtect)
{
    DWORD oldMemProtect;
    memset(m_buffer, 0, m_bufferSize);

    if (VirtualProtectEx(m_proc, reinterpret_cast<LPVOID>(from), size, memProtect, &oldMemProtect))
    {
        if (!ReadProcessMemory(m_proc, reinterpret_cast<LPVOID>(from), m_buffer, size, nullptr))
        {
            throw std::runtime_error("Failed to read memory.");
        }
        VirtualProtectEx(m_proc, reinterpret_cast<LPVOID>(from), size, oldMemProtect, &oldMemProtect);
    }
    else
    {
        throw std::runtime_error("Failed to change memory protection.");
    }

    return *this;
}

uintptr_t MemReader::ReadPointer(uintptr_t base, const uintptr_t* offsets, UINT64 count)
{
    for (size_t i = 0; i < count - 1; ++i)
    {
        base = Read(base + offsets[i], sizeof(uintptr_t)).ToUINT64();
    }
    return base + offsets[count - 1];
}

uintptr_t MemReader::Alloc(UINT64 size, DWORD memProtect)
{
    LPVOID addr = VirtualAllocEx(m_proc, nullptr, size, MEM_COMMIT | MEM_RESERVE, memProtect);
    if (!addr)
    {
        throw std::runtime_error("Failed to allocate memory.");
    }
    return reinterpret_cast<uintptr_t>(addr);
}

void MemReader::Free(uintptr_t ptr)
{
    if (!VirtualFreeEx(m_proc, reinterpret_cast<LPVOID>(ptr), 0, MEM_RELEASE))
    {
        throw std::runtime_error("Failed to free memory.");
    }
}

uintptr_t MemReader::FindSignature(uintptr_t base, size_t size, byte* sign, char* mask)
{
    MEMORY_BASIC_INFORMATION mbi = {};
    uintptr_t offset = 0;

    while (offset < size)
    {
        VirtualQueryEx(m_proc, (LPCVOID)(base + offset), &mbi, sizeof(MEMORY_BASIC_INFORMATION));
        if (mbi.State == MEM_FREE)
        {
            byte* buffer = new byte[mbi.RegionSize];

            ReadProcessMemory(m_proc, mbi.BaseAddress, buffer, mbi.RegionSize, nullptr);
            for (size_t i = 0; i < mbi.RegionSize; i++)
            {
                if (DataCompare(buffer + i, sign, mask))
                {
                    delete[] buffer;
                    return (uintptr_t)mbi.BaseAddress + i;
                }
            }

            delete[] buffer;
        }
        offset += mbi.RegionSize;
    }

    return 0;
}

void MemReader::GetModuleInfo(const wchar_t* moduleName, MODULEENTRY32* mInfo, bool aboutProccess)
{
    HANDLE snapShot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, m_id);
    mInfo->dwSize = sizeof(MODULEENTRY32);

    if (Module32First(snapShot, mInfo))
    {
        if (aboutProccess) { CloseHandle(snapShot); return; }
        do
        {
            if (_wcsicmp(moduleName, mInfo->szModule) == 0)
            {
                CloseHandle(snapShot);
                return;
            }
        } while (Module32Next(snapShot, mInfo));
    }

    CloseHandle(snapShot);
    memset(mInfo, 0, sizeof(MODULEENTRY32));
}

double MemReader::ToDouble() const { double v; memcpy(&v, m_buffer, sizeof(double)); return v; }
float MemReader::ToFloat() const { float v; memcpy(&v, m_buffer, sizeof(float)); return v; }
UINT64 MemReader::ToUINT64() const { UINT64 v; memcpy(&v, m_buffer, sizeof(UINT64)); return v; }
INT64 MemReader::ToINT64() const { INT64 v; memcpy(&v, m_buffer, sizeof(INT64)); return v; }
UINT32 MemReader::ToUINT32() const { UINT32 v; memcpy(&v, m_buffer, sizeof(UINT32)); return v; }
int MemReader::ToINT32() const { int v; memcpy(&v, m_buffer, sizeof(int)); return v; }
UINT16 MemReader::ToUINT16() const { UINT16 v; memcpy(&v, m_buffer, sizeof(UINT16)); return v; }
short int MemReader::ToINT16() const { short int v; memcpy(&v, m_buffer, sizeof(short int)); return v; }
UINT8 MemReader::ToUINT8() const { UINT8 v; memcpy(&v, m_buffer, sizeof(UINT8)); return v; }
char MemReader::ToINT8() const { char v; memcpy(&v, m_buffer, sizeof(char)); return v; }
const char* MemReader::ToStringA() const { return reinterpret_cast<const char*>(m_buffer); }
const wchar_t* MemReader::ToStringW() const { return reinterpret_cast<const wchar_t*>(m_buffer); }

void MemReader::SearchProcess()
{
    HANDLE snapShot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapShot == INVALID_HANDLE_VALUE)
    {
        throw std::runtime_error("Failed to create process snapshot.");
    }

    PROCESSENTRY32 processInfo = { 0 };
    processInfo.dwSize = sizeof(PROCESSENTRY32);

    if (Process32First(snapShot, &processInfo))
    {
        do
        {
            if (_wcsicmp(m_name, processInfo.szExeFile) == 0)
            {
                m_id = processInfo.th32ProcessID;
                CloseHandle(snapShot);
                return;
            }
        } while (Process32Next(snapShot, &processInfo));
    }

    CloseHandle(snapShot);
    m_id = 0;
    throw std::runtime_error("Process not found.");
}

bool MemReader::DataCompare(byte* data, byte* sign, char* mask)
{
    for (; *mask; mask++, sign++, data++)
    {
        if (*mask == 'x' && *data != *sign)
            return false;
    }

    return true;
}