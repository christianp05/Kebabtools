from ctypes import wintypes
import ctypes


class STARTUPINFOA(ctypes.Structure):
    """https://msdn.microsoft.com/en-us/library/ms686331"""

    _fields_ = (
        ("cb", wintypes.DWORD),
        ("lpReserved", wintypes.LPSTR),
        ("lpDesktop", wintypes.LPSTR),
        ("lpTitle", wintypes.LPSTR),
        ("dwX", wintypes.DWORD),
        ("dwY", wintypes.DWORD),
        ("dwXSize", wintypes.DWORD),
        ("dwYSize", wintypes.DWORD),
        ("dwXCountChars", wintypes.DWORD),
        ("dwYCountChars", wintypes.DWORD),
        ("dwFillAttribute", wintypes.DWORD),
        ("dwFlags", wintypes.DWORD),
        ("wShowWindow", wintypes.WORD),
        ("cbReserved2", wintypes.WORD),
        ("lpReserved2", wintypes.LPBYTE),
        ("hStdInput", wintypes.HANDLE),
        ("hStdOutput", wintypes.HANDLE),
        ("hStdError", wintypes.HANDLE),
    )

    def __init__(self, **kwds):
        self.cb = ctypes.sizeof(self)
        super(STARTUPINFOA, self).__init__(**kwds)


from ctypes import *

# Let's map the Microsoft types to ctypes for clarity
BYTE = c_ubyte
WORD = c_ushort
DWORD = c_ulong
LPBYTE = POINTER(c_ubyte)
LPTSTR = POINTER(c_char)
HANDLE = c_void_p
PVOID = c_void_p
LPVOID = c_void_p
UINT_PTR = c_ulong
SIZE_T = c_ulong

# Constants
DEBUG_PROCESS = 0x00000001
CREATE_NEW_CONSOLE = 0x00000010
PROCESS_ALL_ACCESS = 0x001F0FFF
INFINITE = 0xFFFFFFFF
DBG_CONTINUE = 0x00010002
# DSUM
DBG_EXCEPTION_NOT_HANDLED = 0x80010001

# Debug event constants
EXCEPTION_DEBUG_EVENT = 0x1
CREATE_THREAD_DEBUG_EVENT = 0x2
CREATE_PROCESS_DEBUG_EVENT = 0x3
EXIT_THREAD_DEBUG_EVENT = 0x4
EXIT_PROCESS_DEBUG_EVENT = 0x5
LOAD_DLL_DEBUG_EVENT = 0x6
UNLOAD_DLL_DEBUG_EVENT = 0x7
OUTPUT_DEBUG_STRING_EVENT = 0x8
RIP_EVENT = 0x9

# debug exception codes.
EXCEPTION_ACCESS_VIOLATION = 0xC0000005
EXCEPTION_BREAKPOINT = 0x80000003
EXCEPTION_GUARD_PAGE = 0x80000001
EXCEPTION_SINGLE_STEP = 0x80000004


# Thread constants for CreateToolhelp32Snapshot()
TH32CS_SNAPHEAPLIST = 0x00000001
TH32CS_SNAPPROCESS = 0x00000002
TH32CS_SNAPTHREAD = 0x00000004
TH32CS_SNAPMODULE = 0x00000008
TH32CS_INHERIT = 0x80000000
TH32CS_SNAPALL = (
    TH32CS_SNAPHEAPLIST | TH32CS_SNAPPROCESS | TH32CS_SNAPTHREAD | TH32CS_SNAPMODULE
)
THREAD_ALL_ACCESS = 0x001F03FF

# Context flags for GetThreadContext()
CONTEXT_FULL = 0x00010007
CONTEXT_DEBUG_REGISTERS = 0x00010010

# Memory permissions
PAGE_EXECUTE_READWRITE = 0x00000040

# Hardware breakpoint conditions
HW_ACCESS = 0x00000003
HW_EXECUTE = 0x00000000
HW_WRITE = 0x00000001

# Memory page permissions, used by VirtualProtect()
PAGE_NOACCESS = 0x00000001
PAGE_READONLY = 0x00000002
PAGE_READWRITE = 0x00000004
PAGE_WRITECOPY = 0x00000008
PAGE_EXECUTE = 0x00000010
PAGE_EXECUTE_READ = 0x00000020
PAGE_EXECUTE_READWRITE = 0x00000040
PAGE_EXECUTE_WRITECOPY = 0x00000080
PAGE_GUARD = 0x00000100
PAGE_NOCACHE = 0x00000200
PAGE_WRITECOMBINE = 0x00000400


# Structures for CreateProcessA() function
# STARTUPINFO describes how to spawn the process
class STARTUPINFO(Structure):
    _fields_ = [
        ("cb", DWORD),
        ("lpReserved", LPTSTR),
        ("lpDesktop", LPTSTR),
        ("lpTitle", LPTSTR),
        ("dwX", DWORD),
        ("dwY", DWORD),
        ("dwXSize", DWORD),
        ("dwYSize", DWORD),
        ("dwXCountChars", DWORD),
        ("dwYCountChars", DWORD),
        ("dwFillAttribute", DWORD),
        ("dwFlags", DWORD),
        ("wShowWindow", WORD),
        ("cbReserved2", WORD),
        ("lpReserved2", LPBYTE),
        ("hStdInput", HANDLE),
        ("hStdOutput", HANDLE),
        ("hStdError", HANDLE),
    ]


# PROCESS_INFORMATION receives its information
# after the target process has been successfully
# started.
class PROCESS_INFORMATION(Structure):
    _fields_ = [
        ("hProcess", HANDLE),
        ("hThread", HANDLE),
        ("dwProcessId", DWORD),
        ("dwThreadId", DWORD),
    ]


# When the dwDebugEventCode is evaluated
class EXCEPTION_RECORD(Structure):
    pass


EXCEPTION_RECORD._fields_ = [
    ("ExceptionCode", DWORD),
    ("ExceptionFlags", DWORD),
    ("ExceptionRecord", POINTER(EXCEPTION_RECORD)),
    ("ExceptionAddress", PVOID),
    ("NumberParameters", DWORD),
    ("ExceptionInformation", UINT_PTR * 15),
]


class _EXCEPTION_RECORD(Structure):
    _fields_ = [
        ("ExceptionCode", DWORD),
        ("ExceptionFlags", DWORD),
        ("ExceptionRecord", POINTER(EXCEPTION_RECORD)),
        ("ExceptionAddress", PVOID),
        ("NumberParameters", DWORD),
        ("ExceptionInformation", UINT_PTR * 15),
    ]


# Exceptions
class EXCEPTION_DEBUG_INFO(Structure):
    _fields_ = [
        ("ExceptionRecord", EXCEPTION_RECORD),
        ("dwFirstChance", DWORD),
    ]


# it populates this union appropriately
class DEBUG_EVENT_UNION(Union):
    _fields_ = [
        ("Exception", EXCEPTION_DEBUG_INFO),
        #        ("CreateThread",      CREATE_THREAD_DEBUG_INFO),
        #        ("CreateProcessInfo", CREATE_PROCESS_DEBUG_INFO),
        #        ("ExitThread",        EXIT_THREAD_DEBUG_INFO),
        #        ("ExitProcess",       EXIT_PROCESS_DEBUG_INFO),
        #        ("LoadDll",           LOAD_DLL_DEBUG_INFO),
        #        ("UnloadDll",         UNLOAD_DLL_DEBUG_INFO),
        #        ("DebugString",       OUTPUT_DEBUG_STRING_INFO),
        #        ("RipInfo",           RIP_INFO),
    ]


# DEBUG_EVENT describes a debugging event
# that the debugger has trapped
class DEBUG_EVENT(Structure):
    _fields_ = [
        ("dwDebugEventCode", DWORD),
        ("dwProcessId", DWORD),
        ("dwThreadId", DWORD),
        ("u", DEBUG_EVENT_UNION),
    ]


# Used by the CONTEXT structure
class FLOATING_SAVE_AREA(Structure):
    _fields_ = [
        ("ControlWord", DWORD),
        ("StatusWord", DWORD),
        ("TagWord", DWORD),
        ("ErrorOffset", DWORD),
        ("ErrorSelector", DWORD),
        ("DataOffset", DWORD),
        ("DataSelector", DWORD),
        ("RegisterArea", BYTE * 80),
        ("Cr0NpxState", DWORD),
    ]




class M128A(ctypes.Structure):
    _fields_ = [("Low", ctypes.c_ulonglong), ("High", ctypes.c_ulonglong)]


class XMM_SAVE_AREA32(ctypes.Structure):
    _fields_ = [
        ("ControlWord", WORD),
        ("StatusWord", WORD),
        ("TagWord", BYTE),
        ("Reserved1", BYTE),
        ("ErrorOpcode", WORD),
        ("ErrorOffset", DWORD),
        ("ErrorSelector", WORD),
        ("Reserved2", WORD),
        ("DataOffset", DWORD),
        ("DataSelector", WORD),
        ("Reserved3", WORD),
        ("MxCsr", DWORD),
        ("MxCsr_Mask", DWORD),
        ("FloatRegisters", M128A * 8),
        ("XmmRegisters", M128A * 16),
        ("Reserved4", BYTE * 96),
    ]


class DUMMYSTRUCTNAME(ctypes.Structure):
    _fields_ = [
        ("Header", M128A * 2),
        ("Legacy", M128A * 8),
        ("Xmm0", M128A),
        ("Xmm1", M128A),
        ("Xmm2", M128A),
        ("Xmm3", M128A),
        ("Xmm4", M128A),
        ("Xmm5", M128A),
        ("Xmm6", M128A),
        ("Xmm7", M128A),
        ("Xmm8", M128A),
        ("Xmm9", M128A),
        ("Xmm10", M128A),
        ("Xmm11", M128A),
        ("Xmm12", M128A),
        ("Xmm13", M128A),
        ("Xmm14", M128A),
        ("Xmm15", M128A),
    ]


class DUMMYUNIONNAME(ctypes.Union):
    _fields_ = [("FltSave", XMM_SAVE_AREA32), ("DummyStruct", DUMMYSTRUCTNAME)]


class CONTEXT64(ctypes.Structure):
    _fields_ = [
        ("p1home", ctypes.c_ulonglong),
        ("p2home", ctypes.c_ulonglong),
        ("p3home", ctypes.c_ulonglong),
        ("p4home", ctypes.c_ulonglong),
        ("p5home", ctypes.c_ulonglong),
        ("p6home", ctypes.c_ulonglong),
        ("ContextFlags", wintypes.DWORD),
        ("mxcsr", wintypes.DWORD),
        ("segcs", wintypes.WORD),
        ("segds", wintypes.WORD),
        ("seges", wintypes.WORD),
        ("segfs", wintypes.WORD),
        ("seggs", wintypes.WORD),
        ("segss", wintypes.WORD),
        ("eflags", wintypes.DWORD),
        ("dr0", ctypes.c_ulonglong),
        ("dr1", ctypes.c_ulonglong),
        ("dr2", ctypes.c_ulonglong),
        ("dr3", ctypes.c_ulonglong),
        ("dr6", ctypes.c_ulonglong),
        ("dr7", ctypes.c_ulonglong),
        ("rax", ctypes.c_ulonglong),
        ("rcx", ctypes.c_ulonglong),
        ("rdx", ctypes.c_ulonglong),
        ("rbx", ctypes.c_ulonglong),
        ("rsp", ctypes.c_ulonglong),
        ("rbp", ctypes.c_ulonglong),
        ("rsi", ctypes.c_ulonglong),
        ("rdi", ctypes.c_ulonglong),
        ("r8", ctypes.c_ulonglong),
        ("r9", ctypes.c_ulonglong),
        ("r10", ctypes.c_ulonglong),
        ("r11", ctypes.c_ulonglong),
        ("r12", ctypes.c_ulonglong),
        ("r13", ctypes.c_ulonglong),
        ("r14", ctypes.c_ulonglong),
        ("r15", ctypes.c_ulonglong),
        ("rip", ctypes.c_ulonglong),
        ("debugcontrol", ctypes.c_ulonglong),
        ("lastbranchtorip", ctypes.c_ulonglong),
        ("lastbranchfromrip", ctypes.c_ulonglong),
        ("lastexceptiontorip", ctypes.c_ulonglong),
        ("lastexceptionfromrip", ctypes.c_ulonglong),
        ("dummyunionname", DUMMYUNIONNAME),
        ("vectorregister", M128A * 26),
        ("vectorcontrol", ctypes.c_ulonglong),
    ]
