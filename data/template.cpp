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

This is an example of mapping 2 dlls from KnownDlls as an example of using, and re-using
functions.
--*/
#include <Windows.h>
#include <winternl.h>

constexpr ULONG HashStringFowlerNollVoVariant1a( const char* String );
constexpr ULONG HashStringFowlerNollVoVariant1a( const wchar_t* String );

#pragma region macros

#define _DEBUG 1
#if _DEBUG == 0
#define PRINT( STR, ... )
#else
#define PRINT( STR, ... )                                                                   \
    if (1) {                                                                                \
        LPSTR buf = (LPSTR)HeapAlloc( GetProcessHeap(), HEAP_ZERO_MEMORY, 1024 );			\
        if ( buf != NULL ) {                                                                \
            int len = wsprintfA( buf, STR, __VA_ARGS__ );                                   \
            WriteConsoleA( GetStdHandle( STD_OUTPUT_HANDLE ), buf, len, NULL, NULL );       \
            HeapFree( GetProcessHeap(), 0, buf );                                           \
        }                                                                                   \
    }  
#endif

#define NtCurrentThread() (  ( HANDLE ) ( LONG_PTR ) -2 )
#define NtCurrentProcess() ( ( HANDLE ) ( LONG_PTR ) -1 )

template <typename Type>
inline Type RVA2VA( LPVOID Base, LONG Rva ) {
	return (Type)((ULONG_PTR)Base + Rva);
}

#define HASHALGO HashStringFowlerNollVoVariant1a         // specify algorithm here

#pragma region HashStringFowlerNollVoVariant1a

constexpr ULONG HashStringFowlerNollVoVariant1a( const char* String )
{
	ULONG Hash = 0x811c9dc5;

	while( *String )
	{
		Hash ^= (UCHAR)*String++;
		Hash *= 0x01000193;
	}

	return Hash;
}

constexpr ULONG HashStringFowlerNollVoVariant1a( const wchar_t* String )
{
	ULONG Hash = 0x811c9dc5;

	while( *String )
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

dllhash( NTDLL, L"NTDLL.DLL" )
#pragma endregion

#pragma region structs
// Can't do it for NtResumeThread or NtSetEvent as these are used after the hardware breakpoint is set.
// Need to make a struct with the arguments.

$ARG_TYPEDEFS$

// typedef struct {
// 	HANDLE                     SectionHandle;
// 	HANDLE                     ProcessHandle;
// 	PVOID                      BaseAddress;
// 	ULONG                      ZeroBits;
// 	SIZE_T                     CommitSize;
// 	PLARGE_INTEGER             SectionOffset;
// 	PSIZE_T                    ViewSize;
// 	DWORD					   InheritDisposition;
// 	ULONG                      AllocationType;
// 	ULONG                      Win32Protect;
// } NtMapViewOfSectionArgs;

// typedef struct {
// 	HANDLE					   ProcessHandle;
// 	PVOID                      BaseAddress;
// } NtUnmapViewOfSectionArgs;

// typedef struct {
// 	PHANDLE                    SectionHandle;
// 	ACCESS_MASK                DesiredAccess;
// 	POBJECT_ATTRIBUTES         ObjectAttributes;
// } NtOpenSectionArgs;


typedef struct {
	int		index;
	LPVOID	arguments;
} STATE;
#pragma endregion

#pragma region typedefs
$FUNCTION_DEFS$
// typedef NTSTATUS( NTAPI* typeNtMapViewOfSection )(
// 	HANDLE                   SectionHandle,
// 	HANDLE                   ProcessHandle,
// 	PVOID                    BaseAddress,
// 	ULONG                    ZeroBits,
// 	SIZE_T                   CommitSize,
// 	PLARGE_INTEGER           SectionOffset,
// 	PSIZE_T                  ViewSize,
// 	DWORD			         InheritDisposition,
// 	ULONG                    AllocationType,
// 	ULONG                    Win32Protect
// 	);

// typedef NTSTATUS( NTAPI* typeNtUnmapViewOfSection )(
// 	HANDLE                   ProcessHandle,
// 	PVOID                    BaseAddress
// 	);

// typedef NTSTATUS( NTAPI* typeNtOpenSection )(
// 	PHANDLE                  SectionHandle,
// 	ACCESS_MASK              DesiredAccess,
// 	POBJECT_ATTRIBUTES       ObjectAttributes
// 	);
#pragma endregion

// Need to make a global variable of our struct (which we fix the arguments in the handler)
//NtGetContextThreadArgs pNtGetThreadContextArgs;

$ARG_DEFS$

// NtMapViewOfSectionArgs pNtMapViewOfSectionArgs;
// NtUnmapViewOfSectionArgs pNtUnmapViewOfSectionArgs;
// NtOpenSectionArgs pNtOpenSectionArgs;

$FUNC_DEFS$

// NTSTATUS pNtMapViewOfSection( HANDLE SectionHandle, HANDLE ProcessHandle, PVOID BaseAddress, ULONG ZeroBits, SIZE_T CommitSize, PLARGE_INTEGER SectionOffset, PSIZE_T ViewSize, DWORD InheritDisposition, ULONG AllocationType, ULONG Win32Protect );
// NTSTATUS pNtUnmapViewOfSection( HANDLE ProcessHandle, PVOID BaseAddress );
// NTSTATUS pNtOpenSection( PHANDLE SectionHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes );

// enums
$ENUM_DEFS$
// enum
// {
// 	NTMAPVIEWOFSECTION_ENUM = 0,
// 	NTUNMAPVIEWOFSECTION_ENUM,
// 	NTOPENSECTION_ENUM
// };

// Need to setup states in order you call the functions.
$STATE_ARRAY$
// STATE StateArray[] = {
// 	{ NTMAPVIEWOFSECTION_ENUM,		&pNtMapViewOfSectionArgs	},
// 	{ NTUNMAPVIEWOFSECTION_ENUM,	&pNtUnmapViewOfSectionArgs	},
// 	{ NTOPENSECTION_ENUM,			&pNtOpenSectionArgs			}
// };

DWORD EnumState;

LONG WINAPI OneShotHardwareBreakpointHandler( PEXCEPTION_POINTERS ExceptionInfo );

LPVOID FindSyscallAddress( LPVOID function );

VOID SetOneshotHardwareBreakpoint( LPVOID address );

PVOID GetProcAddrExH( UINT funcHash, UINT moduleHash );

void RtlInitUnicodeString( PUNICODE_STRING target, PCWSTR source );

LONG WINAPI OneShotHardwareBreakpointHandler( PEXCEPTION_POINTERS ExceptionInfo )
{
	if( ExceptionInfo->ExceptionRecord->ExceptionCode == STATUS_SINGLE_STEP )
	{
		if( ExceptionInfo->ContextRecord->Dr7 & 1 ) {
			// if the ExceptionInfo->ContextRecord->Rip == ExceptionInfo->ContextRecord->Dr0 
			// then we are at the one shot breakpoint address
			// ExceptionInfo->ContextRecord->Rax should hold the syscall number
			PRINT( "Syscall : 0x%x\n", ExceptionInfo->ContextRecord->Rax );
			if( ExceptionInfo->ContextRecord->Rip == ExceptionInfo->ContextRecord->Dr0 ) {
				ExceptionInfo->ContextRecord->Dr0 = 0;

				// You need to fix your arguments in the right registers and stack here.
				switch( EnumState ) {
					// RCX moved into R10!!! Kudos to @anthonyprintup for catching this 
$ONESHOT_CASE$					
				// case NTMAPVIEWOFSECTION_ENUM:
				// 	ExceptionInfo->ContextRecord->R10 =
				// 		(DWORD_PTR)((NtMapViewOfSectionArgs*)(StateArray[EnumState].arguments))->SectionHandle;

				// 	ExceptionInfo->ContextRecord->Rdx =
				// 		(DWORD_PTR)((NtMapViewOfSectionArgs*)(StateArray[EnumState].arguments))->ProcessHandle;

				// 	ExceptionInfo->ContextRecord->R8 =
				// 		(DWORD_PTR)((NtMapViewOfSectionArgs*)(StateArray[EnumState].arguments))->BaseAddress;

				// 	ExceptionInfo->ContextRecord->R9 =
				// 		(DWORD_PTR)((NtMapViewOfSectionArgs*)(StateArray[EnumState].arguments))->ZeroBits;

				// 	break;

				// case NTUNMAPVIEWOFSECTION_ENUM:
				// 	ExceptionInfo->ContextRecord->R10 =
				// 		(DWORD_PTR)((NtUnmapViewOfSectionArgs*)(StateArray[EnumState].arguments))->ProcessHandle;

				// 	ExceptionInfo->ContextRecord->Rdx =
				// 		(DWORD_PTR)((NtUnmapViewOfSectionArgs*)(StateArray[EnumState].arguments))->BaseAddress;

				// 	break;

				// case NTOPENSECTION_ENUM:
				// 	ExceptionInfo->ContextRecord->R10 =
				// 		(DWORD_PTR)((NtOpenSectionArgs*)(StateArray[EnumState].arguments))->SectionHandle;

				// 	ExceptionInfo->ContextRecord->Rdx =
				// 		(DWORD_PTR)((NtOpenSectionArgs*)(StateArray[EnumState].arguments))->DesiredAccess;

				// 	ExceptionInfo->ContextRecord->R8 =
				// 		(DWORD_PTR)((NtOpenSectionArgs*)(StateArray[EnumState].arguments))->ObjectAttributes;

				// 	break;

					// you have messed up by not providing the indexed state
				default:
					ExceptionInfo->ContextRecord->Rip += 1;	// just so we don't hang
					break;
				}
				return EXCEPTION_CONTINUE_EXECUTION;
			}
		}
	}
	return EXCEPTION_CONTINUE_SEARCH;
}

VOID SetOneshotHardwareBreakpoint( LPVOID address )
{
	CONTEXT context = { 0 };
	context.ContextFlags = CONTEXT_DEBUG_REGISTERS;
	GetThreadContext( GetCurrentThread(), &context );

	context.Dr0 = (DWORD64)address;
	context.Dr6 = 0;
	context.Dr7 = (context.Dr7 & ~(((1 << 2) - 1) << 16)) | (0 << 16);
	context.Dr7 = (context.Dr7 & ~(((1 << 2) - 1) << 18)) | (0 << 18);
	context.Dr7 = (context.Dr7 & ~(((1 << 1) - 1) << 0)) | (1 << 0);

	context.ContextFlags = CONTEXT_DEBUG_REGISTERS;
	SetThreadContext( GetCurrentThread(), &context );

	return;
}

/// + 0x12 generally 
LPVOID FindSyscallAddress( LPVOID function )
{
	BYTE stub[] = { 0x0F, 0x05 };
	for( unsigned int i = 0; i < (unsigned int)25; i++ )
	{
		if( memcmp( (LPVOID)((DWORD_PTR)function + i), stub, 2 ) == 0 ) {
			return (LPVOID)((DWORD_PTR)function + i);
		}
	}
	return NULL;
}

void RtlInitUnicodeString( PUNICODE_STRING target, PCWSTR source )
{
	if( (target->Buffer = (PWSTR)source) )
	{
		unsigned int length = wcslen( source ) * sizeof( WCHAR );
		if( length > 0xfffc )
			length = 0xfffc;

		target->Length = length;
		target->MaximumLength = target->Length + sizeof( WCHAR );
	}
	else target->Length = target->MaximumLength = 0;
}

PVOID GetProcAddrExH( UINT funcHash, UINT moduleHash )
{
	PPEB peb = NtCurrentTeb()->ProcessEnvironmentBlock;
	LIST_ENTRY* head = &peb->Ldr->InMemoryOrderModuleList;
	LIST_ENTRY* next = head->Flink;
	PVOID base = NULL;

	while( next != head )
	{
		LDR_DATA_TABLE_ENTRY* entry = (LDR_DATA_TABLE_ENTRY*)((PBYTE)next - offsetof( LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks ));

		UNICODE_STRING* fullname = &entry->FullDllName;
		UNICODE_STRING* basename = (UNICODE_STRING*)((PBYTE)fullname + sizeof( UNICODE_STRING ));

		char  name[64];
		if( basename->Length < sizeof( name ) - 1 )
		{
			int i = 0;
			while( basename->Buffer[i] && i < sizeof( name ) - 1 )
			{
				name[i] = (basename->Buffer[i] >= 'a' && 'c' <= 'z') ? basename->Buffer[i] - 'a' + 'A' : basename->Buffer[i];
				i++;
			}
			name[i] = 0;
			UINT hash = HASHALGO( name );
			// is this our moduleHash?
			if( hash == moduleHash ) {
				base = entry->DllBase;

				PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)base;
				PIMAGE_NT_HEADERS nt = RVA2VA<PIMAGE_NT_HEADERS>( base, dos->e_lfanew );

				PIMAGE_EXPORT_DIRECTORY exports = RVA2VA<PIMAGE_EXPORT_DIRECTORY>( base, nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress );
				if( exports->AddressOfNames != 0 )
				{
					PWORD ordinals = RVA2VA<PWORD>( base, exports->AddressOfNameOrdinals );
					PDWORD names = RVA2VA<PDWORD>( base, exports->AddressOfNames );
					PDWORD functions = RVA2VA<PDWORD>( base, exports->AddressOfFunctions );

					for( DWORD i = 0; i < exports->NumberOfNames; i++ ) {
						LPSTR name = RVA2VA<LPSTR>( base, names[i] );
						if( HASHALGO( name ) == funcHash ) {
							PBYTE function = RVA2VA<PBYTE>( base, functions[ordinals[i]] );
							return function;
						}
					}
				}
			}
		}
		next = next->Flink;
	}

	return NULL;
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/// Wrappers
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////


$WRAPPER_FUNCTIONS$

// NTSTATUS pNtMapViewOfSection( HANDLE SectionHandle, HANDLE ProcessHandle, PVOID BaseAddress, ULONG ZeroBits, SIZE_T CommitSize, PLARGE_INTEGER SectionOffset, PSIZE_T ViewSize, DWORD InheritDisposition, ULONG AllocationType, ULONG Win32Protect ) {
// 	LPVOID FunctionAddress;
// 	NTSTATUS status;
// 	hash( NtMapViewOfSection );
// 	FunctionAddress = GetProcAddrExH( hashNtMapViewOfSection, hashNTDLL );    typeNtMapViewOfSection fNtMapViewOfSection;

// 	pNtMapViewOfSectionArgs.SectionHandle = SectionHandle;
// 	pNtMapViewOfSectionArgs.ProcessHandle = ProcessHandle;
// 	pNtMapViewOfSectionArgs.BaseAddress = BaseAddress;
// 	pNtMapViewOfSectionArgs.ZeroBits = ZeroBits;
// 	pNtMapViewOfSectionArgs.CommitSize = CommitSize;
// 	pNtMapViewOfSectionArgs.SectionOffset = SectionOffset;
// 	pNtMapViewOfSectionArgs.ViewSize = ViewSize;
// 	pNtMapViewOfSectionArgs.InheritDisposition = InheritDisposition;
// 	pNtMapViewOfSectionArgs.AllocationType = AllocationType;
// 	pNtMapViewOfSectionArgs.Win32Protect = Win32Protect;
// 	fNtMapViewOfSection = (typeNtMapViewOfSection)FunctionAddress;

// 	EnumState = NTMAPVIEWOFSECTION_ENUM;

// 	SetOneshotHardwareBreakpoint( FindSyscallAddress( FunctionAddress ) );
// 	status = fNtMapViewOfSection( NULL, NULL, NULL, NULL, pNtMapViewOfSectionArgs.CommitSize, pNtMapViewOfSectionArgs.SectionOffset, pNtMapViewOfSectionArgs.ViewSize, pNtMapViewOfSectionArgs.InheritDisposition, pNtMapViewOfSectionArgs.AllocationType, pNtMapViewOfSectionArgs.Win32Protect );
// 	return status;
// }

// NTSTATUS pNtUnmapViewOfSection( HANDLE ProcessHandle, PVOID BaseAddress ) {
// 	LPVOID FunctionAddress;
// 	NTSTATUS status;
// 	hash( NtUnmapViewOfSection );
// 	FunctionAddress = GetProcAddrExH( hashNtUnmapViewOfSection, hashNTDLL );

// 	typeNtUnmapViewOfSection fNtUnmapViewOfSection;

// 	pNtUnmapViewOfSectionArgs.ProcessHandle = ProcessHandle;
// 	pNtUnmapViewOfSectionArgs.BaseAddress = BaseAddress;
// 	fNtUnmapViewOfSection = (typeNtUnmapViewOfSection)FunctionAddress;

// 	EnumState = NTUNMAPVIEWOFSECTION_ENUM;

// 	SetOneshotHardwareBreakpoint( FindSyscallAddress( FunctionAddress ) );
// 	status = fNtUnmapViewOfSection( NULL, NULL );
// 	return status;
// }

// NTSTATUS pNtOpenSection( PHANDLE SectionHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes ) {
// 	LPVOID FunctionAddress;
// 	NTSTATUS status;
// 	hash( NtOpenSection );
// 	FunctionAddress = GetProcAddrExH( hashNtOpenSection, hashNTDLL );

// 	typeNtOpenSection fNtOpenSection;

// 	pNtOpenSectionArgs.SectionHandle = SectionHandle;
// 	pNtOpenSectionArgs.DesiredAccess = DesiredAccess;
// 	pNtOpenSectionArgs.ObjectAttributes = ObjectAttributes;
// 	fNtOpenSection = (typeNtOpenSection)FunctionAddress;

// 	EnumState = NTOPENSECTION_ENUM;

// 	SetOneshotHardwareBreakpoint( FindSyscallAddress( FunctionAddress ) );
// 	status = fNtOpenSection( NULL, NULL, NULL );
// 	return status;
// }