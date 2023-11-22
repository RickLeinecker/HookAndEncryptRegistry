#define _CRT_SECURE_NO_WARNINGS
#include <Windows.h>
#include <iostream>
#include <string>
#include <detours.h>
using namespace std;

const wchar_t *encryptionKey = L"mySecureEncryptionKey";

wchar_t dataToWrite[5000];
const char message[] = "This was found in the list of keys to encrypt.";

#define ENCRYPTION_LIST_SIZE 2

struct RegistryKeysToEncrypt
{
    HKEY key;
    wchar_t keyName[256];
    wchar_t valueName[256];
    HKEY openKey;
};

struct RegistryKeysToEncrypt list[] =
{
    { HKEY_LOCAL_MACHINE, L"Software\\Key1", L"SensitiveData1", 0},
    { HKEY_LOCAL_MACHINE, L"Software\\Key2", L"SensitiveData2", 0}
};

void clearOpenedKeys()
{
    for (int i = 0; i < ENCRYPTION_LIST_SIZE; i++)
    {
        list[i].openKey = 0;
    }
}

int keyInList(HKEY key, LPCWSTR keyName, HKEY openKey)
{
    int returnIndex = -1;

    for (int i = 0; i < ENCRYPTION_LIST_SIZE; i++)
    {
        if ((list[i].key == key || list[i].key == (HKEY)0xffff) && wcscmp(list[i].keyName, keyName) == 0)
        {
            list[i].openKey = openKey;
            return i;
        }
    }

    return returnIndex;
}

int inList(LPCWSTR valueName, HKEY openKey)
{
    int returnIndex = -1;

    for (int i = 0; i < ENCRYPTION_LIST_SIZE; i++)
    {
        if (wcscmp(list[i].valueName, valueName) == 0 && list[i].openKey == openKey)
        {
            list[i].openKey = openKey;
            return i;
        }
    }

    return returnIndex;
}

void clearOpenKey(HKEY openKey)
{
    for (int i = 0; i < ENCRYPTION_LIST_SIZE; i++)
    {
        if (list[i].openKey == openKey)
        {
            list[i].openKey = 0;
        }
    }
}

void encryptDecryptData(wchar_t *data, DWORD size)
{
    int len = wcslen(encryptionKey);
    for (DWORD i = 0; i < size; ++i) 
    {
        data[i] ^= encryptionKey[i % len];
    }
}

typedef LSTATUS(WINAPI* RealRegSetValueExW)(HKEY, LPCWSTR, DWORD, DWORD, const BYTE*, DWORD);
RealRegSetValueExW RealRegSetValueExWPtr = nullptr;
LSTATUS WINAPI MyRegSetValueExW(HKEY hKey, LPCWSTR lpValueName, DWORD Reserved, DWORD dwType, const BYTE* lpData, DWORD cbData)
{
    wcscpy(dataToWrite, (wchar_t *)lpData);
    int dataSize = cbData;
    wcout << "MyRegSetValueExW" << " Value Name:" << lpValueName << " Value:" << (wchar_t *)lpData << endl;
    if (inList(lpValueName, hKey) >= 0)
    {
        encryptDecryptData(dataToWrite, cbData - 1);
        cout << message << endl;
    }
    LSTATUS ret = RealRegSetValueExWPtr(hKey, lpValueName, Reserved, dwType, (const BYTE *)dataToWrite, dataSize);
    return ret;
}

typedef LSTATUS(WINAPI* RealRegCreateKeyExW)(HKEY, LPCWSTR, DWORD, LPSTR, DWORD, REGSAM, const LPSECURITY_ATTRIBUTES, PHKEY, LPDWORD);
RealRegCreateKeyExW RealRegCreateKeyExWPtr = nullptr;
LSTATUS WINAPI MyRegCreateKeyExW(HKEY hKey, LPCWSTR lpSubKey, DWORD Reserved, LPSTR lpClass, DWORD dwOptions, REGSAM samDesired, const LPSECURITY_ATTRIBUTES lpSecurityAttributes, PHKEY phkResult, LPDWORD lpdwDisposition)
{
    wcout << "MyRegCreateKeyExW" << " HKEY:" << hKey << " Subkey:" << lpSubKey << endl;
    LSTATUS ret = RealRegCreateKeyExWPtr(hKey, lpSubKey, Reserved, lpClass, dwOptions, samDesired, lpSecurityAttributes, phkResult, lpdwDisposition);
    if (ret == ERROR_SUCCESS)
    {
        if (keyInList(hKey, lpSubKey, *phkResult) >= 0)
        {
            cout << message << endl;
        }
    }
    return ret;
}

typedef LSTATUS(WINAPI* RealRegOpenKeyExW)(HKEY, LPCWSTR, DWORD, REGSAM, PHKEY);
RealRegOpenKeyExW RealRegOpenKeyExWPtr = nullptr;
LSTATUS WINAPI MyRegOpenKeyExW(HKEY hKey, LPCWSTR lpSubKey, DWORD ulOptions, REGSAM samDesired, PHKEY phkResult)
{
    wcout << "MyRegOpenKeyExW" << " HKEY:" << hKey << " Subkey:" << lpSubKey << endl;
    LSTATUS ret = RealRegOpenKeyExWPtr(hKey, lpSubKey, ulOptions, samDesired, phkResult);
    if (ret == ERROR_SUCCESS)
    {
        if (keyInList(hKey, lpSubKey, *phkResult) >= 0)
        {
            cout << message << endl;
        }
    }
    return ret;
}

typedef LSTATUS(WINAPI* RealRegGetValueW)(HKEY, LPCWSTR, LPCWSTR, DWORD, LPDWORD, PVOID, LPDWORD);
RealRegGetValueW RealRegGetValueWPtr = nullptr;
LSTATUS WINAPI MyRegGetValueW(HKEY hKey, LPCWSTR lpSubKey, LPCWSTR lpValue, DWORD dwFlags, LPDWORD pdwType, PVOID pvData, LPDWORD pcbData)
{
    wcout << "MyRegGetValueW" << " HKEY:" << hKey << " Subkey:" << lpSubKey << endl;
    LSTATUS ret = RealRegGetValueWPtr(hKey, lpSubKey, lpValue, dwFlags, pdwType, pvData, pcbData);
    if (keyInList((HKEY)0xffff, lpSubKey, hKey) >= 0)
    {
        encryptDecryptData((wchar_t *)pvData, *pcbData);
        cout << message << endl;
    }
    return ret;
}

typedef LSTATUS(WINAPI* RealRegQueryValueExW)(HKEY, LPCWSTR, LPDWORD, LPDWORD, LPBYTE, LPDWORD);
RealRegQueryValueExW RealRegQueryValueExWPtr = nullptr;
LSTATUS WINAPI MyRegQueryValueExW(HKEY hKey, LPCWSTR lpValueName, LPDWORD lpReserved, LPDWORD lpType, LPBYTE lpData, LPDWORD lpcbData)
{
    wcout << "MyRegQueryValueExW" << " HKEY:" << hKey << " Value Name:" << lpValueName << endl;
    LSTATUS ret = RealRegQueryValueExWPtr(hKey, lpValueName, lpReserved, lpType, lpData, lpcbData);
    if (inList(lpValueName, hKey) >= 0)
    {
        encryptDecryptData((wchar_t*)lpData, *lpcbData);
        cout << message << endl;
    }
    return ret;
}

typedef LSTATUS(WINAPI* RealRegCloseKey)(HKEY);
RealRegCloseKey RealRegCloseKeyPtr = nullptr;
LSTATUS WINAPI MyRegCloseKey(HKEY hKey)
{
    cout << "MyRegCloseKey" << endl;
    clearOpenKey(hKey);
    return RealRegCloseKeyPtr(hKey);
}

void installHooks()
{
    // Hook RegSetValueExW
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());

    // Get the address of the real RegSetValueExW function
    RealRegSetValueExWPtr = reinterpret_cast<RealRegSetValueExW>(GetProcAddress(GetModuleHandle(L"advapi32.dll"), "RegSetValueExW"));
    // Get the address of the real RegCreateKeyExW function
    RealRegCreateKeyExWPtr = reinterpret_cast<RealRegCreateKeyExW>(GetProcAddress(GetModuleHandle(L"advapi32.dll"), "RegCreateKeyExW"));
    // Get the address of the real RegOpenKeyExW function
    RealRegOpenKeyExWPtr = reinterpret_cast<RealRegOpenKeyExW>(GetProcAddress(GetModuleHandle(L"advapi32.dll"), "RegOpenKeyExW"));
    // Get the address of the real RegGetValueW function
    RealRegGetValueWPtr = reinterpret_cast<RealRegGetValueW>(GetProcAddress(GetModuleHandle(L"advapi32.dll"), "RegGetValueW"));
    // Get the address of the real RegCloseKey function
    RealRegCloseKeyPtr = reinterpret_cast<RealRegCloseKey>(GetProcAddress(GetModuleHandle(L"advapi32.dll"), "RegCloseKey"));
    // Get the address of the real RegQueryValueExW function
    RealRegQueryValueExWPtr = reinterpret_cast<RealRegQueryValueExW>(GetProcAddress(GetModuleHandle(L"advapi32.dll"), "RegQueryValueExW"));

    // Attach the detoured function for RegSetValueExW
    DetourAttach(&(PVOID&)RealRegSetValueExWPtr, MyRegSetValueExW);
    // Attach the detoured function for RegCreateKeyExW
    DetourAttach(&(PVOID&)RealRegCreateKeyExWPtr, MyRegCreateKeyExW);
    // Attach the detoured function for RegOpenKeyExW
    DetourAttach(&(PVOID&)RealRegOpenKeyExWPtr, MyRegOpenKeyExW);
    // Attach the detoured function for RegGetValueW
    DetourAttach(&(PVOID&)RealRegGetValueWPtr, MyRegGetValueW);
    // Attach the detoured function for RegCloseKey
    DetourAttach(&(PVOID&)RealRegCloseKeyPtr, MyRegCloseKey);
    // Attach the detoured function for RegQueryValueExW
    DetourAttach(&(PVOID&)RealRegQueryValueExWPtr, MyRegQueryValueExW);

    // Commit the transaction
    DetourTransactionCommit();
}

void releaseHooks()
{
    // Unhook RegSetValueExW
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());

    DetourDetach(&(PVOID&)RealRegSetValueExWPtr, MyRegSetValueExW);
    DetourDetach(&(PVOID&)RealRegCreateKeyExWPtr, MyRegCreateKeyExW);
    DetourDetach(&(PVOID&)RealRegOpenKeyExWPtr, MyRegOpenKeyExW);
    DetourDetach(&(PVOID&)RealRegGetValueWPtr, MyRegGetValueW);
    DetourDetach(&(PVOID&)RealRegCloseKeyPtr, MyRegCloseKey);
    DetourDetach(&(PVOID&)RealRegQueryValueExWPtr, MyRegQueryValueExW);

    DetourTransactionCommit();
}

int main()
{
    HKEY hKey;
    LONG result;
    DWORD data = 0, size = 0, type = 0;
    wchar_t value[1000];

    installHooks();

    // Ready to create key at HKEY_LOCAL_MACHINE / "Software\\Key100" (It is not in the list)
    result = RegCreateKeyEx(HKEY_LOCAL_MACHINE, L"Software\\Key100", 0, nullptr, 0, KEY_READ | KEY_WRITE, nullptr, &hKey, nullptr);
    RegSetValueExW(hKey, L"ValueKey100", 0, REG_SZ, (LPBYTE)L"Value100", 20);
    RegCloseKey(hKey);

    // Ready to create key at HKEY_LOCAL_MACHINE / "Software\\Key1" (It IS in the list)
    result = RegCreateKeyEx(HKEY_LOCAL_MACHINE, L"Software\\Key1", 0, nullptr, 0, KEY_READ | KEY_WRITE, nullptr, &hKey, nullptr);
    RegSetValueExW(hKey, L"SensitiveData1", 0, REG_SZ, (LPBYTE)L"Value1", 16);
    RegCloseKey(hKey);

    // Ready to open key at HKEY_LOCAL_MACHINE / "Software\\Key100" (It is not in the list)
    result = RegOpenKeyEx(HKEY_LOCAL_MACHINE, L"Software\\Key100", 0, KEY_READ | KEY_WRITE, &hKey);
    size = 1000;
    RegQueryValueExW(hKey, L"ValueKey100", NULL, &type, (LPBYTE)value, &size);
    RegCloseKey(hKey);

    // Ready to open key at HKEY_LOCAL_MACHINE / "Software\\Key1" (It IS not in the list)
    result = RegOpenKeyEx(HKEY_LOCAL_MACHINE, L"Software\\Key1", 0, KEY_READ | KEY_WRITE, &hKey);
    size = 1000;
    RegQueryValueExW(hKey, L"SensitiveData1", NULL, &type, (LPBYTE)value, &size);
    RegCloseKey(hKey);

    releaseHooks();

    return 0;
}
