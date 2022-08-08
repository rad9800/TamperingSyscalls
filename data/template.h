/*++
TamperingSyscalls
- @rad98
- @__mez0__ for getting the generation working, and great ideas.

How this works?
We set a HWBP on syscall address, remove the HWBP, fix the arguments, and make the call
Thus avoiding reveal our malicious arguments to the EDR telemetry.

(possibility for you to include your own fake arguments to feed EDR the wrong telemetry.
Maybe I will write a blog post on this)

Or use the script provided.
We need to setup the states (what we want to fix the arguments to) and then make the right
corresponding calls. I have provided various examples.
--*/

#include <Windows.h>
#include <winternl.h>
#include <stdio.h>

constexpr ULONG HashStringFowlerNollVoVariant1a(const char* String);
constexpr ULONG HashStringFowlerNollVoVariant1a(const wchar_t* String);

#pragma region macros

#define NtCurrentThread() (  ( HANDLE ) ( LONG_PTR ) -2 )
#define NtCurrentProcess() ( ( HANDLE ) ( LONG_PTR ) -1 )

template <typename Type>
inline Type RVA2VA(LPVOID Base, LONG Rva) {
    return (Type)((ULONG_PTR)Base + Rva);
}

#define HASHALGO HashStringFowlerNollVoVariant1a         // specify algorithm here

#pragma region HashStringFowlerNollVoVariant1a

constexpr ULONG HashStringFowlerNollVoVariant1a(const char* String)
{
    ULONG Hash = 0x811c9dc5;

    while (*String)
    {
        Hash ^= (UCHAR)*String++;
        Hash *= 0x01000193;
    }

    return Hash;
}

constexpr ULONG HashStringFowlerNollVoVariant1a(const wchar_t* String)
{
    ULONG Hash = 0x811c9dc5;

    while (*String)
    {
        Hash ^= (UCHAR)*String++;
        Hash *= 0x01000193;
    }

    return Hash;
}
#pragma endregion

#define TOKENIZE( x ) #x
#define CONCAT( X, Y ) X##Y
#define hash( VAL ) constexpr auto CONCAT( hash, VAL ) = HASHALGO( TOKENIZE( VAL ) );                           
#define dllhash(DLL, VAL ) constexpr auto CONCAT( hash, DLL ) = HASHALGO( VAL );                                                

dllhash(NTDLL, L"NTDLL.DLL")
#pragma endregion

$ARG_TYPEDEFS$

typedef struct {
    int     index;
    LPVOID  arguments;
} STATE;
#pragma endregion

#pragma region typedefs

$FUNCTION_DEFS$

#pragma endregion

$ARG_DEFS$
$FUNC_DEFS$
$ENUM_DEFS$
$STATE_ARRAY$

DWORD EnumState;

LONG WINAPI OneShotHardwareBreakpointHandler(PEXCEPTION_POINTERS ExceptionInfo);

LPVOID FindSyscallAddress(LPVOID function);

VOID SetOneshotHardwareBreakpoint(LPVOID address);

PVOID GetProcAddrExH(UINT funcHash, UINT moduleHash);

void RtlInitUnicodeString(PUNICODE_STRING target, PCWSTR source);