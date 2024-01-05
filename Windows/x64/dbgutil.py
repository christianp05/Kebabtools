import ctypes
from ctypes import wintypes
import pefile
from .customwinclasses import *

kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
EXCEPTION_BREAKPOINT = 0x80000003
INFINITE = 0xFFFFFFFF


class Breakpoint:
    def __init__(self, process, address, orgbyte):
        self.process = process
        self.address = address
        self.orgbyte = orgbyte
        self.disabled = False

    def disable(self):
        self.process.MemWrite(self.address, self.orgbyte)
        self.disabled = True

    def enable(self):
        self.process.MemWrite(self.address, b"\xcc")
        self.disabled = False


class Module:
    def __init__(self, name, fullPath, handle,exportedFuncs):
        self.name = name
        self.fullPath = fullPath
        self.handle = handle
        self.exportedFuncs = exportedFuncs


def ReadProcessMem():
    pass


def GetModules(handle):
    retdict = {}

    cbNeeded = pointer(ctypes.c_uint32())
    OutArray = (wintypes.HMODULE * 1000)()
    result = kernel32.K32EnumProcessModulesEx(
        handle, OutArray, sizeof(OutArray), cbNeeded, 0x0
    )
    if result == 0:
        raise ctypes.WinError(ctypes.get_last_error())

    for module in OutArray:
        if module == None:
            break
        newModHandle = wintypes.HMODULE(
            module
        )  # We need to convert module from int to a HMODULE because ctypes shenanigans

        nameArray = (ctypes.c_char * 260)()  # 260 is MAX_PATH

        result = kernel32.K32GetModuleFileNameExA(
            handle, newModHandle, nameArray, wintypes.DWORD(260)
        )
        if result == 0:
            raise ctypes.WinError(ctypes.get_last_error())

        newByteString = ""
        for i in nameArray:
            if i == b"\x00":
                break
            newByteString += i.decode()
        fullPath = newByteString
        

        name = fullPath.split("\\")[-1] #just want dll name not fullpath

        peObject = pefile.PE(fullPath)
        #check if the module is a dll. 0x2000 = IMAGE_FILE_DLL
        functions = {}
        if peObject.FILE_HEADER.Characteristics & 0x2000 == 0:
            functions = None
        else:
            for exp in peObject.DIRECTORY_ENTRY_EXPORT.symbols:
                functions.update({exp.name:modHandle.value + exp.address })

        modHandle = newModHandle
        retModule = Module(name, fullPath, modHandle,functions)
        retdict.update({retModule.name:retModule})
    return retdict


def WaitForDebugEvent():

    debug_event = DEBUG_EVENT()

    # Call WaitForDebugEvent
    result = kernel32.WaitForDebugEvent(ctypes.byref(debug_event), INFINITE)
    if result == 0:
        raise ctypes.WinError(ctypes.get_last_error())
    return debug_event


def ContinueDebugEvent(procid, threadid):
    result = kernel32.ContinueDebugEvent(procid, threadid, 0x00010002)
    if result == 0:
        raise ctypes.WinError(ctypes.get_last_error())
    return result


def SuspendThread(threadHandle):
    result = kernel32.SuspendThread(threadHandle)
    return result


def ResumeThread(threadHandle):
    result = kernel32.ResumeThread(threadHandle)
    return result


def GetContext(thread):

    ctx = CONTEXT64()
    ctx.ContextFlags = 0x10007
    SuspendThread(thread)

    result = kernel32.GetThreadContext(thread, byref(ctx))
    if result == 0:
        raise ctypes.WinError(ctypes.get_last_error())
    ResumeThread(thread)
    return ctx


def SetContext(thread, ctx):
    SuspendThread(thread)
    result = kernel32.SetThreadContext(thread, ctx)
    if result == 0:
        raise ctypes.WinError(ctypes.get_last_error())
    ResumeThread(thread)


def OpenThread(threadid):
    dwDesiredAccess = wintypes.DWORD(0x1FFFFF)
    bInheritHandle = wintypes.BOOL(False)
    dwThreadId = wintypes.DWORD(threadid)

    result = kernel32.OpenThread(dwDesiredAccess, bInheritHandle, dwThreadId)
    if result == 0:
        raise ctypes.WinError(ctypes.get_last_error())
    return result


def CreateDebugeeProcess(exename):
    kernel32.CreateProcessA.argtypes = (
        wintypes.LPCSTR,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.LPVOID,
        wintypes.BOOL,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.LPCSTR,
        ctypes.POINTER(STARTUPINFOA),
        ctypes.POINTER(PROCESS_INFORMATION),
    )

    # CreateUserProcessA takes in the path of the process to be created as a string
    process_path = exename.encode("utf-8")

    startup_info = STARTUPINFOA()
    process_info = PROCESS_INFORMATION()

    # Call CreateProcessA
    result = kernel32.CreateProcessA(
        process_path,
        0,
        None,
        None,
        False,
        0x10 | 0x1,
        None,
        None,
        ctypes.byref(startup_info),
        ctypes.byref(process_info),
    )

    if result == 0:
        raise ctypes.WinError(ctypes.get_last_error())

    while 1:
        event = WaitForDebugEvent()
        if event.dwDebugEventCode == 1:
            if event.u.Exception.ExceptionRecord.ExceptionCode == EXCEPTION_BREAKPOINT:
                print("Breakpoint")
                break
        ContinueDebugEvent(event.dwProcessId, event.dwThreadId)
    return (process_info, event)

def ContinueFromBreak(process):
    process.Breaked = False
    newRip = process.GetRegs().rip - 1
    process.SetReg("rip", newRip)
    process.SingleStep()
    # If the breakpoint we hit isnt disabled then enable it again
    if process.LatestBreakpoint.disabled != True:
        process.LatestBreakpoint.enable()
def AttachProcess(PID):
    Handle = kernel32.OpenProcess((0xf0000 | 0x100000| 0xFFFF),0,PID)
    kernel32.DebugActiveProcess(PID)


    while 1:
        event = WaitForDebugEvent()
        if event.dwDebugEventCode == 1:
            if event.u.Exception.ExceptionRecord.ExceptionCode == EXCEPTION_BREAKPOINT:
                print("Breakpoint")
                break
        ContinueDebugEvent(event.dwProcessId, event.dwThreadId)
    return ([Handle,event.dwThreadId], event)
        