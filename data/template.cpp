#include "$FILE_NAME$"

VOID SetOneshotHardwareBreakpoint(LPVOID address)
{
    CONTEXT context = { 0 };
    context.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    GetThreadContext(GetCurrentThread(), &context);

    context.Dr0 = (DWORD64)address;
    context.Dr6 = 0;
    context.Dr7 = (context.Dr7 & ~(((1 << 2) - 1) << 16)) | (0 << 16);
    context.Dr7 = (context.Dr7 & ~(((1 << 2) - 1) << 18)) | (0 << 18);
    context.Dr7 = (context.Dr7 & ~(((1 << 1) - 1) << 0)) | (1 << 0);

    context.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    SetThreadContext(GetCurrentThread(), &context);

    return;
}

/// + 0x12 generally 
LPVOID FindSyscallAddress(LPVOID function)
{
    BYTE stub[] = { 0x0F, 0x05 };
    for (unsigned int i = 0; i < (unsigned int)25; i++)
    {
        if (memcmp((LPVOID)((DWORD_PTR)function + i), stub, 2) == 0) {
            return (LPVOID)((DWORD_PTR)function + i);
        }
    }
    return NULL;
}

void RtlInitUnicodeString(PUNICODE_STRING target, PCWSTR source)
{
    if ((target->Buffer = (PWSTR)source))
    {
        unsigned int length = wcslen(source) * sizeof(WCHAR);
        if (length > 0xfffc)
            length = 0xfffc;

        target->Length = length;
        target->MaximumLength = target->Length + sizeof(WCHAR);
    }
    else target->Length = target->MaximumLength = 0;
}

PVOID GetProcAddrExH(UINT funcHash, UINT moduleHash)
{
    PPEB peb = NtCurrentTeb()->ProcessEnvironmentBlock;
    LIST_ENTRY* head = &peb->Ldr->InMemoryOrderModuleList;
    LIST_ENTRY* next = head->Flink;
    PVOID base = NULL;

    while (next != head)
    {
        LDR_DATA_TABLE_ENTRY* entry = (LDR_DATA_TABLE_ENTRY*)((PBYTE)next - offsetof(LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks));

        UNICODE_STRING* fullname = &entry->FullDllName;
        UNICODE_STRING* basename = (UNICODE_STRING*)((PBYTE)fullname + sizeof(UNICODE_STRING));

        char  name[64];
        if (basename->Length < sizeof(name) - 1)
        {
            int i = 0;
            while (basename->Buffer[i] && i < sizeof(name) - 1)
            {
                name[i] = (basename->Buffer[i] >= 'a' && 'c' <= 'z') ? basename->Buffer[i] - 'a' + 'A' : basename->Buffer[i];
                i++;
            }
            name[i] = 0;
            UINT hash = HASHALGO(name);
            // is this our moduleHash?
            if (hash == moduleHash) {
                base = entry->DllBase;

                PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)base;
                PIMAGE_NT_HEADERS nt = RVA2VA<PIMAGE_NT_HEADERS>(base, dos->e_lfanew);

                PIMAGE_EXPORT_DIRECTORY exports = RVA2VA<PIMAGE_EXPORT_DIRECTORY>(base, nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
                if (exports->AddressOfNames != 0)
                {
                    PWORD ordinals = RVA2VA<PWORD>(base, exports->AddressOfNameOrdinals);
                    PDWORD names = RVA2VA<PDWORD>(base, exports->AddressOfNames);
                    PDWORD functions = RVA2VA<PDWORD>(base, exports->AddressOfFunctions);

                    for (DWORD i = 0; i < exports->NumberOfNames; i++) {
                        LPSTR name = RVA2VA<LPSTR>(base, names[i]);
                        if (HASHALGO(name) == funcHash) {
                            PBYTE function = RVA2VA<PBYTE>(base, functions[ordinals[i]]);
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


LONG WINAPI OneShotHardwareBreakpointHandler(PEXCEPTION_POINTERS ExceptionInfo)
{
    if (ExceptionInfo->ExceptionRecord->ExceptionCode == STATUS_SINGLE_STEP)
    {
        if (ExceptionInfo->ContextRecord->Dr7 & 1) {
            // if the ExceptionInfo->ContextRecord->Rip == ExceptionInfo->ContextRecord->Dr0 
            // then we are at the one shot breakpoint address
            // ExceptionInfo->ContextRecord->Rax should hold the syscall number
            PRINT("Syscall : 0x%x\n", ExceptionInfo->ContextRecord->Rax);
            if (ExceptionInfo->ContextRecord->Rip == ExceptionInfo->ContextRecord->Dr0) {
                ExceptionInfo->ContextRecord->Dr0 = 0;

                // You need to fix your arguments in the right registers and stack here.
                switch (EnumState) {
                    // RCX moved into R10!!! Kudos to @anthonyprintup for catching this 
$ONESHOT_CASE$
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

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/// Wrappers
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

$WRAPPER_FUNCTIONS$#include "TamperingSyscalls.h"

VOID SetOneshotHardwareBreakpoint(LPVOID address)
{
    CONTEXT context = { 0 };
    context.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    GetThreadContext(GetCurrentThread(), &context);

    context.Dr0 = (DWORD64)address;
    context.Dr6 = 0;
    context.Dr7 = (context.Dr7 & ~(((1 << 2) - 1) << 16)) | (0 << 16);
    context.Dr7 = (context.Dr7 & ~(((1 << 2) - 1) << 18)) | (0 << 18);
    context.Dr7 = (context.Dr7 & ~(((1 << 1) - 1) << 0)) | (1 << 0);

    context.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    SetThreadContext(GetCurrentThread(), &context);

    return;
}

/// + 0x12 generally 
LPVOID FindSyscallAddress(LPVOID function)
{
    BYTE stub[] = { 0x0F, 0x05 };
    for (unsigned int i = 0; i < (unsigned int)25; i++)
    {
        if (memcmp((LPVOID)((DWORD_PTR)function + i), stub, 2) == 0) {
            return (LPVOID)((DWORD_PTR)function + i);
        }
    }
    return NULL;
}

void RtlInitUnicodeString(PUNICODE_STRING target, PCWSTR source)
{
    if ((target->Buffer = (PWSTR)source))
    {
        unsigned int length = wcslen(source) * sizeof(WCHAR);
        if (length > 0xfffc)
            length = 0xfffc;

        target->Length = length;
        target->MaximumLength = target->Length + sizeof(WCHAR);
    }
    else target->Length = target->MaximumLength = 0;
}

PVOID GetProcAddrExH(UINT funcHash, UINT moduleHash)
{
    PPEB peb = NtCurrentTeb()->ProcessEnvironmentBlock;
    LIST_ENTRY* head = &peb->Ldr->InMemoryOrderModuleList;
    LIST_ENTRY* next = head->Flink;
    PVOID base = NULL;

    while (next != head)
    {
        LDR_DATA_TABLE_ENTRY* entry = (LDR_DATA_TABLE_ENTRY*)((PBYTE)next - offsetof(LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks));

        UNICODE_STRING* fullname = &entry->FullDllName;
        UNICODE_STRING* basename = (UNICODE_STRING*)((PBYTE)fullname + sizeof(UNICODE_STRING));

        char  name[64];
        if (basename->Length < sizeof(name) - 1)
        {
            int i = 0;
            while (basename->Buffer[i] && i < sizeof(name) - 1)
            {
                name[i] = (basename->Buffer[i] >= 'a' && 'c' <= 'z') ? basename->Buffer[i] - 'a' + 'A' : basename->Buffer[i];
                i++;
            }
            name[i] = 0;
            UINT hash = HASHALGO(name);
            // is this our moduleHash?
            if (hash == moduleHash) {
                base = entry->DllBase;

                PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)base;
                PIMAGE_NT_HEADERS nt = RVA2VA<PIMAGE_NT_HEADERS>(base, dos->e_lfanew);

                PIMAGE_EXPORT_DIRECTORY exports = RVA2VA<PIMAGE_EXPORT_DIRECTORY>(base, nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
                if (exports->AddressOfNames != 0)
                {
                    PWORD ordinals = RVA2VA<PWORD>(base, exports->AddressOfNameOrdinals);
                    PDWORD names = RVA2VA<PDWORD>(base, exports->AddressOfNames);
                    PDWORD functions = RVA2VA<PDWORD>(base, exports->AddressOfFunctions);

                    for (DWORD i = 0; i < exports->NumberOfNames; i++) {
                        LPSTR name = RVA2VA<LPSTR>(base, names[i]);
                        if (HASHALGO(name) == funcHash) {
                            PBYTE function = RVA2VA<PBYTE>(base, functions[ordinals[i]]);
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


LONG WINAPI OneShotHardwareBreakpointHandler(PEXCEPTION_POINTERS ExceptionInfo)
{
    if (ExceptionInfo->ExceptionRecord->ExceptionCode == STATUS_SINGLE_STEP)
    {
        if (ExceptionInfo->ContextRecord->Dr7 & 1) {
            // if the ExceptionInfo->ContextRecord->Rip == ExceptionInfo->ContextRecord->Dr0 
            // then we are at the one shot breakpoint address
            // ExceptionInfo->ContextRecord->Rax should hold the syscall number
            PRINT("Syscall : 0x%x\n", ExceptionInfo->ContextRecord->Rax);
            if (ExceptionInfo->ContextRecord->Rip == ExceptionInfo->ContextRecord->Dr0) {
                ExceptionInfo->ContextRecord->Dr0 = 0;

                // You need to fix your arguments in the right registers and stack here.
                switch (EnumState) {
                    // RCX moved into R10!!! Kudos to @anthonyprintup for catching this 
                    case NTMAPVIEWOFSECTION_ENUM:
                        ExceptionInfo->ContextRecord->R10 = (DWORD_PTR)((NtMapViewOfSectionArgs*)(StateArray[EnumState].arguments))->SectionHandle;
                        ExceptionInfo->ContextRecord->Rdx = (DWORD_PTR)((NtMapViewOfSectionArgs*)(StateArray[EnumState].arguments))->ProcessHandle;
                        ExceptionInfo->ContextRecord->R8 = (DWORD_PTR)((NtMapViewOfSectionArgs*)(StateArray[EnumState].arguments))->BaseAddress;
                        ExceptionInfo->ContextRecord->R9 = (DWORD_PTR)((NtMapViewOfSectionArgs*)(StateArray[EnumState].arguments))->ZeroBits;
                        break;
                    case NTUNMAPVIEWOFSECTION_ENUM:
                        ExceptionInfo->ContextRecord->R10 = (DWORD_PTR)((NtUnmapViewOfSectionArgs*)(StateArray[EnumState].arguments))->ProcessHandle;
                        ExceptionInfo->ContextRecord->Rdx = (DWORD_PTR)((NtUnmapViewOfSectionArgs*)(StateArray[EnumState].arguments))->BaseAddress;
                        break;
                    case NTOPENSECTION_ENUM:
                        ExceptionInfo->ContextRecord->R10 = (DWORD_PTR)((NtOpenSectionArgs*)(StateArray[EnumState].arguments))->SectionHandle;
                        ExceptionInfo->ContextRecord->Rdx = (DWORD_PTR)((NtOpenSectionArgs*)(StateArray[EnumState].arguments))->DesiredAccess;
                        ExceptionInfo->ContextRecord->R8 = (DWORD_PTR)((NtOpenSectionArgs*)(StateArray[EnumState].arguments))->ObjectAttributes;
                        break;


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

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/// Wrappers
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

NTSTATUS pNtMapViewOfSection(HANDLE SectionHandle, HANDLE ProcessHandle, PVOID BaseAddress, ULONG ZeroBits, SIZE_T CommitSize, PLARGE_INTEGER SectionOffset, PSIZE_T ViewSize, SECTION_INHERIT InheritDisposition, ULONG AllocationType, ULONG Win32Protect) {
    LPVOID FunctionAddress;
    NTSTATUS status;

    hash( NtMapViewOfSection );
    FunctionAddress = GetProcAddrExH( hashNtMapViewOfSection, hashNTDLL );
    typeNtMapViewOfSection fNtMapViewOfSection;

    pNtMapViewOfSectionArgs.SectionHandle = SectionHandle;
    pNtMapViewOfSectionArgs.ProcessHandle = ProcessHandle;
    pNtMapViewOfSectionArgs.BaseAddress = BaseAddress;
    pNtMapViewOfSectionArgs.ZeroBits = ZeroBits;
    pNtMapViewOfSectionArgs.CommitSize = CommitSize;
    pNtMapViewOfSectionArgs.SectionOffset = SectionOffset;
    pNtMapViewOfSectionArgs.ViewSize = ViewSize;
    pNtMapViewOfSectionArgs.InheritDisposition = InheritDisposition;
    pNtMapViewOfSectionArgs.AllocationType = AllocationType;
    pNtMapViewOfSectionArgs.Win32Protect = Win32Protect;
    fNtMapViewOfSection = (typeNtMapViewOfSection)FunctionAddress;

    EnumState = NTMAPVIEWOFSECTION_ENUM;

    SetOneshotHardwareBreakpoint( FindSyscallAddress( FunctionAddress ) );
    status = fNtMapViewOfSection(NULL, NULL, NULL, NULL, pNtMapViewOfSectionArgs.CommitSize, pNtMapViewOfSectionArgs.SectionOffset, pNtMapViewOfSectionArgs.ViewSize, pNtMapViewOfSectionArgs.InheritDisposition, pNtMapViewOfSectionArgs.AllocationType, pNtMapViewOfSectionArgs.Win32Protect);
    return status;
}

NTSTATUS pNtUnmapViewOfSection(HANDLE ProcessHandle, PVOID BaseAddress) {
    LPVOID FunctionAddress;
    NTSTATUS status;

    hash( NtUnmapViewOfSection );
    FunctionAddress = GetProcAddrExH( hashNtUnmapViewOfSection, hashNTDLL );
    typeNtUnmapViewOfSection fNtUnmapViewOfSection;

    pNtUnmapViewOfSectionArgs.ProcessHandle = ProcessHandle;
    pNtUnmapViewOfSectionArgs.BaseAddress = BaseAddress;
    fNtUnmapViewOfSection = (typeNtUnmapViewOfSection)FunctionAddress;

    EnumState = NTUNMAPVIEWOFSECTION_ENUM;

    SetOneshotHardwareBreakpoint( FindSyscallAddress( FunctionAddress ) );
    status = fNtUnmapViewOfSection(NULL, NULL);
    return status;
}

NTSTATUS pNtOpenSection(PHANDLE SectionHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes) {
    LPVOID FunctionAddress;
    NTSTATUS status;

    hash( NtOpenSection );
    FunctionAddress = GetProcAddrExH( hashNtOpenSection, hashNTDLL );
    typeNtOpenSection fNtOpenSection;

    pNtOpenSectionArgs.SectionHandle = SectionHandle;
    pNtOpenSectionArgs.DesiredAccess = DesiredAccess;
    pNtOpenSectionArgs.ObjectAttributes = ObjectAttributes;
    fNtOpenSection = (typeNtOpenSection)FunctionAddress;

    EnumState = NTOPENSECTION_ENUM;

    SetOneshotHardwareBreakpoint( FindSyscallAddress( FunctionAddress ) );
    status = fNtOpenSection(NULL, NULL, NULL);
    return status;
}

#include "TamperingSyscalls.h"

VOID SetOneshotHardwareBreakpoint(LPVOID address)
{
    CONTEXT context = { 0 };
    context.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    GetThreadContext(GetCurrentThread(), &context);

    context.Dr0 = (DWORD64)address;
    context.Dr6 = 0;
    context.Dr7 = (context.Dr7 & ~(((1 << 2) - 1) << 16)) | (0 << 16);
    context.Dr7 = (context.Dr7 & ~(((1 << 2) - 1) << 18)) | (0 << 18);
    context.Dr7 = (context.Dr7 & ~(((1 << 1) - 1) << 0)) | (1 << 0);

    context.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    SetThreadContext(GetCurrentThread(), &context);

    return;
}

/// + 0x12 generally 
LPVOID FindSyscallAddress(LPVOID function)
{
    BYTE stub[] = { 0x0F, 0x05 };
    for (unsigned int i = 0; i < (unsigned int)25; i++)
    {
        if (memcmp((LPVOID)((DWORD_PTR)function + i), stub, 2) == 0) {
            return (LPVOID)((DWORD_PTR)function + i);
        }
    }
    return NULL;
}

void RtlInitUnicodeString(PUNICODE_STRING target, PCWSTR source)
{
    if ((target->Buffer = (PWSTR)source))
    {
        unsigned int length = wcslen(source) * sizeof(WCHAR);
        if (length > 0xfffc)
            length = 0xfffc;

        target->Length = length;
        target->MaximumLength = target->Length + sizeof(WCHAR);
    }
    else target->Length = target->MaximumLength = 0;
}

PVOID GetProcAddrExH(UINT funcHash, UINT moduleHash)
{
    PPEB peb = NtCurrentTeb()->ProcessEnvironmentBlock;
    LIST_ENTRY* head = &peb->Ldr->InMemoryOrderModuleList;
    LIST_ENTRY* next = head->Flink;
    PVOID base = NULL;

    while (next != head)
    {
        LDR_DATA_TABLE_ENTRY* entry = (LDR_DATA_TABLE_ENTRY*)((PBYTE)next - offsetof(LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks));

        UNICODE_STRING* fullname = &entry->FullDllName;
        UNICODE_STRING* basename = (UNICODE_STRING*)((PBYTE)fullname + sizeof(UNICODE_STRING));

        char  name[64];
        if (basename->Length < sizeof(name) - 1)
        {
            int i = 0;
            while (basename->Buffer[i] && i < sizeof(name) - 1)
            {
                name[i] = (basename->Buffer[i] >= 'a' && 'c' <= 'z') ? basename->Buffer[i] - 'a' + 'A' : basename->Buffer[i];
                i++;
            }
            name[i] = 0;
            UINT hash = HASHALGO(name);
            // is this our moduleHash?
            if (hash == moduleHash) {
                base = entry->DllBase;

                PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)base;
                PIMAGE_NT_HEADERS nt = RVA2VA<PIMAGE_NT_HEADERS>(base, dos->e_lfanew);

                PIMAGE_EXPORT_DIRECTORY exports = RVA2VA<PIMAGE_EXPORT_DIRECTORY>(base, nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
                if (exports->AddressOfNames != 0)
                {
                    PWORD ordinals = RVA2VA<PWORD>(base, exports->AddressOfNameOrdinals);
                    PDWORD names = RVA2VA<PDWORD>(base, exports->AddressOfNames);
                    PDWORD functions = RVA2VA<PDWORD>(base, exports->AddressOfFunctions);

                    for (DWORD i = 0; i < exports->NumberOfNames; i++) {
                        LPSTR name = RVA2VA<LPSTR>(base, names[i]);
                        if (HASHALGO(name) == funcHash) {
                            PBYTE function = RVA2VA<PBYTE>(base, functions[ordinals[i]]);
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


LONG WINAPI OneShotHardwareBreakpointHandler(PEXCEPTION_POINTERS ExceptionInfo)
{
    if (ExceptionInfo->ExceptionRecord->ExceptionCode == STATUS_SINGLE_STEP)
    {
        if (ExceptionInfo->ContextRecord->Dr7 & 1) {
            // if the ExceptionInfo->ContextRecord->Rip == ExceptionInfo->ContextRecord->Dr0 
            // then we are at the one shot breakpoint address
            // ExceptionInfo->ContextRecord->Rax should hold the syscall number
            PRINT("Syscall : 0x%x\n", ExceptionInfo->ContextRecord->Rax);
            if (ExceptionInfo->ContextRecord->Rip == ExceptionInfo->ContextRecord->Dr0) {
                ExceptionInfo->ContextRecord->Dr0 = 0;

                // You need to fix your arguments in the right registers and stack here.
                switch (EnumState) {
                    // RCX moved into R10!!! Kudos to @anthonyprintup for catching this 
                    case NTMAPVIEWOFSECTION_ENUM:
                        ExceptionInfo->ContextRecord->R10 = (DWORD_PTR)((NtMapViewOfSectionArgs*)(StateArray[EnumState].arguments))->SectionHandle;
                        ExceptionInfo->ContextRecord->Rdx = (DWORD_PTR)((NtMapViewOfSectionArgs*)(StateArray[EnumState].arguments))->ProcessHandle;
                        ExceptionInfo->ContextRecord->R8 = (DWORD_PTR)((NtMapViewOfSectionArgs*)(StateArray[EnumState].arguments))->BaseAddress;
                        ExceptionInfo->ContextRecord->R9 = (DWORD_PTR)((NtMapViewOfSectionArgs*)(StateArray[EnumState].arguments))->ZeroBits;
                        break;
                    case NTUNMAPVIEWOFSECTION_ENUM:
                        ExceptionInfo->ContextRecord->R10 = (DWORD_PTR)((NtUnmapViewOfSectionArgs*)(StateArray[EnumState].arguments))->ProcessHandle;
                        ExceptionInfo->ContextRecord->Rdx = (DWORD_PTR)((NtUnmapViewOfSectionArgs*)(StateArray[EnumState].arguments))->BaseAddress;
                        break;
                    case NTOPENSECTION_ENUM:
                        ExceptionInfo->ContextRecord->R10 = (DWORD_PTR)((NtOpenSectionArgs*)(StateArray[EnumState].arguments))->SectionHandle;
                        ExceptionInfo->ContextRecord->Rdx = (DWORD_PTR)((NtOpenSectionArgs*)(StateArray[EnumState].arguments))->DesiredAccess;
                        ExceptionInfo->ContextRecord->R8 = (DWORD_PTR)((NtOpenSectionArgs*)(StateArray[EnumState].arguments))->ObjectAttributes;
                        break;


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

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/// Wrappers
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

NTSTATUS pNtMapViewOfSection(HANDLE SectionHandle, HANDLE ProcessHandle, PVOID BaseAddress, ULONG ZeroBits, SIZE_T CommitSize, PLARGE_INTEGER SectionOffset, PSIZE_T ViewSize, SECTION_INHERIT InheritDisposition, ULONG AllocationType, ULONG Win32Protect) {
    LPVOID FunctionAddress;
    NTSTATUS status;

    hash( NtMapViewOfSection );
    FunctionAddress = GetProcAddrExH( hashNtMapViewOfSection, hashNTDLL );
    typeNtMapViewOfSection fNtMapViewOfSection;

    pNtMapViewOfSectionArgs.SectionHandle = SectionHandle;
    pNtMapViewOfSectionArgs.ProcessHandle = ProcessHandle;
    pNtMapViewOfSectionArgs.BaseAddress = BaseAddress;
    pNtMapViewOfSectionArgs.ZeroBits = ZeroBits;
    pNtMapViewOfSectionArgs.CommitSize = CommitSize;
    pNtMapViewOfSectionArgs.SectionOffset = SectionOffset;
    pNtMapViewOfSectionArgs.ViewSize = ViewSize;
    pNtMapViewOfSectionArgs.InheritDisposition = InheritDisposition;
    pNtMapViewOfSectionArgs.AllocationType = AllocationType;
    pNtMapViewOfSectionArgs.Win32Protect = Win32Protect;
    fNtMapViewOfSection = (typeNtMapViewOfSection)FunctionAddress;

    EnumState = NTMAPVIEWOFSECTION_ENUM;

    SetOneshotHardwareBreakpoint( FindSyscallAddress( FunctionAddress ) );
    status = fNtMapViewOfSection(NULL, NULL, NULL, NULL, pNtMapViewOfSectionArgs.CommitSize, pNtMapViewOfSectionArgs.SectionOffset, pNtMapViewOfSectionArgs.ViewSize, pNtMapViewOfSectionArgs.InheritDisposition, pNtMapViewOfSectionArgs.AllocationType, pNtMapViewOfSectionArgs.Win32Protect);
    return status;
}

NTSTATUS pNtUnmapViewOfSection(HANDLE ProcessHandle, PVOID BaseAddress) {
    LPVOID FunctionAddress;
    NTSTATUS status;

    hash( NtUnmapViewOfSection );
    FunctionAddress = GetProcAddrExH( hashNtUnmapViewOfSection, hashNTDLL );
    typeNtUnmapViewOfSection fNtUnmapViewOfSection;

    pNtUnmapViewOfSectionArgs.ProcessHandle = ProcessHandle;
    pNtUnmapViewOfSectionArgs.BaseAddress = BaseAddress;
    fNtUnmapViewOfSection = (typeNtUnmapViewOfSection)FunctionAddress;

    EnumState = NTUNMAPVIEWOFSECTION_ENUM;

    SetOneshotHardwareBreakpoint( FindSyscallAddress( FunctionAddress ) );
    status = fNtUnmapViewOfSection(NULL, NULL);
    return status;
}

NTSTATUS pNtOpenSection(PHANDLE SectionHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes) {
    LPVOID FunctionAddress;
    NTSTATUS status;

    hash( NtOpenSection );
    FunctionAddress = GetProcAddrExH( hashNtOpenSection, hashNTDLL );
    typeNtOpenSection fNtOpenSection;

    pNtOpenSectionArgs.SectionHandle = SectionHandle;
    pNtOpenSectionArgs.DesiredAccess = DesiredAccess;
    pNtOpenSectionArgs.ObjectAttributes = ObjectAttributes;
    fNtOpenSection = (typeNtOpenSection)FunctionAddress;

    EnumState = NTOPENSECTION_ENUM;

    SetOneshotHardwareBreakpoint( FindSyscallAddress( FunctionAddress ) );
    status = fNtOpenSection(NULL, NULL, NULL);
    return status;
}

#include "TamperingSyscalls.h"

VOID SetOneshotHardwareBreakpoint(LPVOID address)
{
    CONTEXT context = { 0 };
    context.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    GetThreadContext(GetCurrentThread(), &context);

    context.Dr0 = (DWORD64)address;
    context.Dr6 = 0;
    context.Dr7 = (context.Dr7 & ~(((1 << 2) - 1) << 16)) | (0 << 16);
    context.Dr7 = (context.Dr7 & ~(((1 << 2) - 1) << 18)) | (0 << 18);
    context.Dr7 = (context.Dr7 & ~(((1 << 1) - 1) << 0)) | (1 << 0);

    context.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    SetThreadContext(GetCurrentThread(), &context);

    return;
}

/// + 0x12 generally 
LPVOID FindSyscallAddress(LPVOID function)
{
    BYTE stub[] = { 0x0F, 0x05 };
    for (unsigned int i = 0; i < (unsigned int)25; i++)
    {
        if (memcmp((LPVOID)((DWORD_PTR)function + i), stub, 2) == 0) {
            return (LPVOID)((DWORD_PTR)function + i);
        }
    }
    return NULL;
}

void RtlInitUnicodeString(PUNICODE_STRING target, PCWSTR source)
{
    if ((target->Buffer = (PWSTR)source))
    {
        unsigned int length = wcslen(source) * sizeof(WCHAR);
        if (length > 0xfffc)
            length = 0xfffc;

        target->Length = length;
        target->MaximumLength = target->Length + sizeof(WCHAR);
    }
    else target->Length = target->MaximumLength = 0;
}

PVOID GetProcAddrExH(UINT funcHash, UINT moduleHash)
{
    PPEB peb = NtCurrentTeb()->ProcessEnvironmentBlock;
    LIST_ENTRY* head = &peb->Ldr->InMemoryOrderModuleList;
    LIST_ENTRY* next = head->Flink;
    PVOID base = NULL;

    while (next != head)
    {
        LDR_DATA_TABLE_ENTRY* entry = (LDR_DATA_TABLE_ENTRY*)((PBYTE)next - offsetof(LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks));

        UNICODE_STRING* fullname = &entry->FullDllName;
        UNICODE_STRING* basename = (UNICODE_STRING*)((PBYTE)fullname + sizeof(UNICODE_STRING));

        char  name[64];
        if (basename->Length < sizeof(name) - 1)
        {
            int i = 0;
            while (basename->Buffer[i] && i < sizeof(name) - 1)
            {
                name[i] = (basename->Buffer[i] >= 'a' && 'c' <= 'z') ? basename->Buffer[i] - 'a' + 'A' : basename->Buffer[i];
                i++;
            }
            name[i] = 0;
            UINT hash = HASHALGO(name);
            // is this our moduleHash?
            if (hash == moduleHash) {
                base = entry->DllBase;

                PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)base;
                PIMAGE_NT_HEADERS nt = RVA2VA<PIMAGE_NT_HEADERS>(base, dos->e_lfanew);

                PIMAGE_EXPORT_DIRECTORY exports = RVA2VA<PIMAGE_EXPORT_DIRECTORY>(base, nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
                if (exports->AddressOfNames != 0)
                {
                    PWORD ordinals = RVA2VA<PWORD>(base, exports->AddressOfNameOrdinals);
                    PDWORD names = RVA2VA<PDWORD>(base, exports->AddressOfNames);
                    PDWORD functions = RVA2VA<PDWORD>(base, exports->AddressOfFunctions);

                    for (DWORD i = 0; i < exports->NumberOfNames; i++) {
                        LPSTR name = RVA2VA<LPSTR>(base, names[i]);
                        if (HASHALGO(name) == funcHash) {
                            PBYTE function = RVA2VA<PBYTE>(base, functions[ordinals[i]]);
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


LONG WINAPI OneShotHardwareBreakpointHandler(PEXCEPTION_POINTERS ExceptionInfo)
{
    if (ExceptionInfo->ExceptionRecord->ExceptionCode == STATUS_SINGLE_STEP)
    {
        if (ExceptionInfo->ContextRecord->Dr7 & 1) {
            // if the ExceptionInfo->ContextRecord->Rip == ExceptionInfo->ContextRecord->Dr0 
            // then we are at the one shot breakpoint address
            // ExceptionInfo->ContextRecord->Rax should hold the syscall number
            PRINT("Syscall : 0x%x\n", ExceptionInfo->ContextRecord->Rax);
            if (ExceptionInfo->ContextRecord->Rip == ExceptionInfo->ContextRecord->Dr0) {
                ExceptionInfo->ContextRecord->Dr0 = 0;

                // You need to fix your arguments in the right registers and stack here.
                switch (EnumState) {
                    // RCX moved into R10!!! Kudos to @anthonyprintup for catching this 
                    case NTMAPVIEWOFSECTION_ENUM:
                        ExceptionInfo->ContextRecord->R10 = (DWORD_PTR)((NtMapViewOfSectionArgs*)(StateArray[EnumState].arguments))->SectionHandle;
                        ExceptionInfo->ContextRecord->Rdx = (DWORD_PTR)((NtMapViewOfSectionArgs*)(StateArray[EnumState].arguments))->ProcessHandle;
                        ExceptionInfo->ContextRecord->R8 = (DWORD_PTR)((NtMapViewOfSectionArgs*)(StateArray[EnumState].arguments))->BaseAddress;
                        ExceptionInfo->ContextRecord->R9 = (DWORD_PTR)((NtMapViewOfSectionArgs*)(StateArray[EnumState].arguments))->ZeroBits;
                        break;
                    case NTUNMAPVIEWOFSECTION_ENUM:
                        ExceptionInfo->ContextRecord->R10 = (DWORD_PTR)((NtUnmapViewOfSectionArgs*)(StateArray[EnumState].arguments))->ProcessHandle;
                        ExceptionInfo->ContextRecord->Rdx = (DWORD_PTR)((NtUnmapViewOfSectionArgs*)(StateArray[EnumState].arguments))->BaseAddress;
                        break;
                    case NTOPENSECTION_ENUM:
                        ExceptionInfo->ContextRecord->R10 = (DWORD_PTR)((NtOpenSectionArgs*)(StateArray[EnumState].arguments))->SectionHandle;
                        ExceptionInfo->ContextRecord->Rdx = (DWORD_PTR)((NtOpenSectionArgs*)(StateArray[EnumState].arguments))->DesiredAccess;
                        ExceptionInfo->ContextRecord->R8 = (DWORD_PTR)((NtOpenSectionArgs*)(StateArray[EnumState].arguments))->ObjectAttributes;
                        break;


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

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/// Wrappers
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

NTSTATUS pNtMapViewOfSection(HANDLE SectionHandle, HANDLE ProcessHandle, PVOID BaseAddress, ULONG ZeroBits, SIZE_T CommitSize, PLARGE_INTEGER SectionOffset, PSIZE_T ViewSize, SECTION_INHERIT InheritDisposition, ULONG AllocationType, ULONG Win32Protect) {
    LPVOID FunctionAddress;
    NTSTATUS status;

    hash( NtMapViewOfSection );
    FunctionAddress = GetProcAddrExH( hashNtMapViewOfSection, hashNTDLL );
    typeNtMapViewOfSection fNtMapViewOfSection;

    pNtMapViewOfSectionArgs.SectionHandle = SectionHandle;
    pNtMapViewOfSectionArgs.ProcessHandle = ProcessHandle;
    pNtMapViewOfSectionArgs.BaseAddress = BaseAddress;
    pNtMapViewOfSectionArgs.ZeroBits = ZeroBits;
    pNtMapViewOfSectionArgs.CommitSize = CommitSize;
    pNtMapViewOfSectionArgs.SectionOffset = SectionOffset;
    pNtMapViewOfSectionArgs.ViewSize = ViewSize;
    pNtMapViewOfSectionArgs.InheritDisposition = InheritDisposition;
    pNtMapViewOfSectionArgs.AllocationType = AllocationType;
    pNtMapViewOfSectionArgs.Win32Protect = Win32Protect;
    fNtMapViewOfSection = (typeNtMapViewOfSection)FunctionAddress;

    EnumState = NTMAPVIEWOFSECTION_ENUM;

    SetOneshotHardwareBreakpoint( FindSyscallAddress( FunctionAddress ) );
    status = fNtMapViewOfSection(NULL, NULL, NULL, NULL, pNtMapViewOfSectionArgs.CommitSize, pNtMapViewOfSectionArgs.SectionOffset, pNtMapViewOfSectionArgs.ViewSize, pNtMapViewOfSectionArgs.InheritDisposition, pNtMapViewOfSectionArgs.AllocationType, pNtMapViewOfSectionArgs.Win32Protect);
    return status;
}

NTSTATUS pNtUnmapViewOfSection(HANDLE ProcessHandle, PVOID BaseAddress) {
    LPVOID FunctionAddress;
    NTSTATUS status;

    hash( NtUnmapViewOfSection );
    FunctionAddress = GetProcAddrExH( hashNtUnmapViewOfSection, hashNTDLL );
    typeNtUnmapViewOfSection fNtUnmapViewOfSection;

    pNtUnmapViewOfSectionArgs.ProcessHandle = ProcessHandle;
    pNtUnmapViewOfSectionArgs.BaseAddress = BaseAddress;
    fNtUnmapViewOfSection = (typeNtUnmapViewOfSection)FunctionAddress;

    EnumState = NTUNMAPVIEWOFSECTION_ENUM;

    SetOneshotHardwareBreakpoint( FindSyscallAddress( FunctionAddress ) );
    status = fNtUnmapViewOfSection(NULL, NULL);
    return status;
}

NTSTATUS pNtOpenSection(PHANDLE SectionHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes) {
    LPVOID FunctionAddress;
    NTSTATUS status;

    hash( NtOpenSection );
    FunctionAddress = GetProcAddrExH( hashNtOpenSection, hashNTDLL );
    typeNtOpenSection fNtOpenSection;

    pNtOpenSectionArgs.SectionHandle = SectionHandle;
    pNtOpenSectionArgs.DesiredAccess = DesiredAccess;
    pNtOpenSectionArgs.ObjectAttributes = ObjectAttributes;
    fNtOpenSection = (typeNtOpenSection)FunctionAddress;

    EnumState = NTOPENSECTION_ENUM;

    SetOneshotHardwareBreakpoint( FindSyscallAddress( FunctionAddress ) );
    status = fNtOpenSection(NULL, NULL, NULL);
    return status;
}

