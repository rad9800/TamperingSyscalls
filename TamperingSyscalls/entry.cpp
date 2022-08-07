/*++
TamperingSyscallsOnly
- rad98

This is only the syscall retrieval method which works by placing a HWBP on syscall
then retrieving the value stored in RAX which should be the syscall number.
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
#pragma endregion

// Can't do it for NtResumeThread or NtSetEvent as these are used after the hardware breakpoint is set.

LONG WINAPI OneShotHardwareBreakpointHandler( PEXCEPTION_POINTERS ExceptionInfo );

LPVOID FindSyscallAddress( LPVOID function );

VOID SetOneshotHardwareBreakpoint( LPVOID address );

DWORD RetrieveSyscall( PVOID FunctionAddress )
{
	DWORD ssn;
	typedef DWORD( WINAPI* typeReturn )();


	SetOneshotHardwareBreakpoint( FindSyscallAddress( FunctionAddress ) );
	typeReturn ReturnNtStatus = (typeReturn)FunctionAddress;
	ssn = ReturnNtStatus();

	return ssn;
}

int main()
{
	SetUnhandledExceptionFilter( OneShotHardwareBreakpointHandler );
	
	DWORD ssn;

	// You can use API Hashing or something else. It wasn't exclusive to this project so I didn't
	// include it.
	ssn = RetrieveSyscall( GetProcAddress( GetModuleHandleA( "NTDLL.dll" ), "NtGetContextThread" ) );
	PRINT( "NtGetContextThread SSN \t: 0x%x\n", ssn );
	ssn = RetrieveSyscall( GetProcAddress( GetModuleHandleA( "NTDLL.dll" ), "NtMapViewOfSection" ) );
	PRINT( "NtMapViewOfSection SSN \t: 0x%x\n", ssn );
	ssn = RetrieveSyscall( GetProcAddress( GetModuleHandleA( "NTDLL.dll" ), "NtQueueApcThreadEx" ) );
	PRINT( "NtQueueApcThreadEx SSN \t: 0x%x\n", ssn );
	ssn = RetrieveSyscall( GetProcAddress( GetModuleHandleA( "NTDLL.dll" ), "NtOpenProcess" ) );
	PRINT( "NtOpenProcess SSN \t: 0x%x\n", ssn );

	return 0;
}


LONG WINAPI OneShotHardwareBreakpointHandler( PEXCEPTION_POINTERS ExceptionInfo )
{
	if( ExceptionInfo->ExceptionRecord->ExceptionCode == STATUS_SINGLE_STEP )
	{
		if( ExceptionInfo->ContextRecord->Dr7 & 1 ) {
			// if the ExceptionInfo->ContextRecord->Rip == ExceptionInfo->ContextRecord->Dr0 
			// then we are at the one shot breakpoint address
			if( ExceptionInfo->ContextRecord->Rip == ExceptionInfo->ContextRecord->Dr0 ) {
				ExceptionInfo->ContextRecord->Dr0 = 0;

				ExceptionInfo->ContextRecord->Rip += 2;	
				// ExceptionInfo->ContextRecord->Rax should hold the syscall number
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
