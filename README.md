# TamperingSyscalls

**Tampering with syscalls.** 

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
6. It will then skip over the syscall instruction, not executing and return the value in RAX.
```c
ExceptionInfo->ContextRecord->Rip += 2;	
```

[TamperingSyscall's Blog Post](https://fool.ish.wtf/2022/08/tamperingsyscalls.html)
