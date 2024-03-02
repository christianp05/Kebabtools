import ctypes
from ctypes import wintypes
import pefile
from .customwinclasses import *

kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
ntdll = ctypes.WinDLL("ntdll.dll", use_last_error=True)


def GetPEBAdr(ProcHandle):
    INFO = PROCESS_BASIC_INFORMATION()
    print(ctypes.sizeof(INFO))
    ntdll.NtQueryInformationProcess(ProcHandle,0,ctypes.byref(INFO),48,0)
    PEBADR = INFO.PebBaseAddress
    return PEBADR

    

