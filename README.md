# TamperingSyscalls
TamperingSyscalls is a 2 part novel project consisting of argument spoofing and syscall retrival which both abuse EH in order to subvert EDRs. This project consists of both of these projects in order to provide an alternative solution to direct syscalls.

**Tampering with syscalls.** 
1. Set up a global EH which will be used later.
```c
SetUnhandledExceptionFilter( OneShotHardwareBreakpointHandler );
```
2. Set a hardware breakpoint on the address of a syscall instruction which has the bytes `0f05` on the Dr0 register.
We can locate the address of the syscall stub with this quick memory byte search.
```c
BYTE stub[] = { 0x0F, 0x05 };
for( unsigned int i = 0; i < (unsigned int)25; i++ )
{
	if( memcmp( (LPVOID)((DWORD_PTR)function + i), stub, 2 ) == 0 ) {
		return (LPVOID)((DWORD_PTR)function + i);
	}
}
  ```
3. We can then make a call to this function passing NULL for the <=4 arguments (which tend to be the more important arguments holding information such as process handles .etc) We also set the EnumState to the corresponding Enum for this function (so we can later fix the arguments).
4. While the EDR has full introspection into our arguments, it cannot confidently make the decision we are performing a malicious action as we have passed NULL as the first <=4 arguments.
5. The EDR will then return the syscall number(SSN) and store it in RAX. If you are only interested in retreiving syscalls, [check out the stripped branch of this repository.](https://github.com/rad9800/TamperingSyscalls/blob/stripped/TamperingSyscalls/entry.cpp)
6. The program then flows into the syscall instruction { 0x0F, 0x05 } which hits the breakpoint we previously set. This will then throw a SINGLE_STEP exception which will be handled by the exception handler we setup in Step 1.
```c
if( ExceptionInfo->ExceptionRecord->ExceptionCode == STATUS_SINGLE_STEP )
```
7. This exception handler will disable the hardware breakpoint for Dr0 only if the Dr0 and RIP match by setting the value the Dr0 register points to 0 (which should be the current RIP)
```c
if( ExceptionInfo->ExceptionRecord->ExceptionCode == STATUS_SINGLE_STEP )
{
	if( ExceptionInfo->ContextRecord->Dr7 & 1 ) {
		if( ExceptionInfo->ContextRecord->Rip == ExceptionInfo->ContextRecord->Dr0 ) {
			ExceptionInfo->ContextRecord->Dr0 = 0;
```
7. We will then fix the remaining registers we had previously set to NULL. The reason it is 4 is that this the x64 calling convention dictates we use RCX, RDX, R8, R9 for the first 4 arguments, and the rest are setup on the stack. It is possible to manually set these up the >4 parameters on the stack but this is beyond the scope of this project as it would require inline assembly. The reason why it is R10 not RCX is that at the start of every syscall stub `mov r10, rcx` as the RCX register is destroyed in the next instructions.
```c
case NTMAPVIEWOFSECTION_ENUM:
	ExceptionInfo->ContextRecord->R10 =
		(DWORD_PTR)((NtMapViewOfSectionArgs*)(StateArray[EnumState].arguments))->SectionHandle;

	ExceptionInfo->ContextRecord->Rdx =
		(DWORD_PTR)((NtMapViewOfSectionArgs*)(StateArray[EnumState].arguments))->ProcessHandle;

	ExceptionInfo->ContextRecord->R8 =
		(DWORD_PTR)((NtMapViewOfSectionArgs*)(StateArray[EnumState].arguments))->BaseAddress;

	ExceptionInfo->ContextRecord->R9 =
		(DWORD_PTR)((NtMapViewOfSectionArgs*)(StateArray[EnumState].arguments))->ZeroBits;
```
We can see in this example we are fixing the arguments for NtMapViewOfSection.

## Howto
If you'd like to start to fake EDR telemetry it is possible to modify the p[FunctionName] definitions where they are currently set to NULL. 

## Generation

To generate the required functions, use `gen.py`. This supports either:

- Comma separated functions
```
python gen.py NtOpenSection,NtMapViewOfSection,NtUnmapViewOfSection
```

It will produce 3 files: TamperingSyscalls.cpp, TamperingSyscalls.h, and main.cpp. You can `#include "TamperingSyscalls.h"` into your project. We can call the functions by appending the function name to p, for example `pNtOpenSection(...);`


### Limitations
We cannot set a breakpoint on NtSetThreadContext or it's variants as this is used to set the debug registers.
There is a brief period where the debug registers are set, but this is very small and I do not think we will be detected for holding an open Dr0.

I have published a small blog post, touching upon these techniques.

[TamperingSyscall's Overview Blog Post](https://fool.ish.wtf/2022/08/tamperingsyscalls.html)

[TamperingSyscall's Fake Intropspection Blog Post](https://fool.ish.wtf/2022/08/feeding-edrs-false-telemetry.html)
