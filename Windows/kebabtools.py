import sys
sys.dont_write_bytecode = True


import ctypes
from ctypes import wintypes
import pefile
import psutil
from .util import *
from .heaputil import *

kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)


supportedArches = {
    0x8664: "x64",
    0x14c: "x86",
}

def GetProcessPath(pid):
    try:
        p = psutil.Process(pid)
    except psutil.NoSuchProcess:
        print("Invalid process ID given")
    return p.exe()


def GetBinaryArch(path):
    peobject = pefile.PE(path)
    machinetype = peobject.FILE_HEADER.Machine
    if machinetype not in supportedArches:
        print("EXE FILE GIVEN UNSUPPORTED ARCH")
    else:
        return supportedArches[machinetype]

class Process:
    def __init__(self, path):
        self.arch = GetBinaryArch(path)
        if self.arch == "x64":
            from .x64 import dbghandler
            from .x64 import dbgutil
            from .x64 import winutil
            self.dbghandler = dbghandler
            self.dbgutil = dbgutil
            self.winutil = winutil
        elif self.arch == "x86":
            from .x86 import dbghandler
            from .x86 import dbgutil

            self.dbghandler = dbghandler
            self.dbgutil = dbgutil

        retvalues = self.dbgutil.CreateDebugeeProcess(path)
        self.LastEvent = retvalues[1]
        self.Exename = path.split("/")[-1]
        self.Handle = wintypes.HANDLE(retvalues[0].hProcess)
        self.ThreadHandle = retvalues[0].hThread
        self.Pid = retvalues[0].dwProcessId
        self.Modules = self.dbgutil.GetModules(self.Handle)
        self.PEBAddress = self.winutil.GetPEBAdr(self.Handle)
        self.BreakPoints = []
        self.BaseAdress = self.Modules[self.Exename].handle.value
        self.Breaked = False
        self.LatestBreakpoint = None
        self.Continue()

    def Continue(self):
        # If the process has hit a breakpoint we need to recover from it
        if self.Breaked == True:
            self.dbgutil.ContinueFromBreak(self)

        while 1:
            self.dbgutil.ContinueDebugEvent(self.LastEvent.dwProcessId, self.LastEvent.dwThreadId)
            self.LastEvent = self.dbgutil.WaitForDebugEvent()
            result = self.dbghandler.dbghandler[self.LastEvent.dwDebugEventCode](self, self.LastEvent)
            # If our handler returned a -1 we need to give user control again
            if result == -1:
                break

    def MemRead(self, address, numberOfBytes):
        # Make arguments into ctypes
        lpBaseAddress = ctypes.c_ulonglong(address)
        lpBuffer = (ctypes.c_char * numberOfBytes)()
        nSize = ctypes.c_size_t(numberOfBytes)
        lpNumberOfBytesRead = ctypes.c_size_t()

        result = kernel32.ReadProcessMemory(
            self.Handle, lpBaseAddress, lpBuffer, nSize, ctypes.byref(lpNumberOfBytesRead)
        )
        if result == 0:
            raise ctypes.WinError(ctypes.get_last_error())
        # Return a correct array in case we read less than the asked amount of bytes
        CorrectlySizedArray = (ctypes.c_char * lpNumberOfBytesRead.value)()
        ctypes.memmove(CorrectlySizedArray, lpBuffer, lpNumberOfBytesRead.value)
        return CorrectlySizedArray.raw

    def MemWrite(self, address, buffer):

        lpBaseAddress = ctypes.c_ulonglong(address)

        #if type equals int then its a single byte write
        if type(buffer) == int:
            result = kernel32.WriteProcessMemory(self.Handle, lpBaseAddress, buffer.to_bytes(1,"little"), 1, None)
            if result == 0:
                raise ctypes.WinError(ctypes.get_last_error())
            return None

        lpBuffer = (ctypes.c_char * len(buffer))()
        ctypes.memmove(lpBuffer, buffer, len(buffer))

        nSize = ctypes.c_size_t(len(buffer))

        result = kernel32.WriteProcessMemory(
            self.Handle, lpBaseAddress, lpBuffer, nSize, None
        )
        if result == 0:
            raise ctypes.WinError(ctypes.get_last_error())
        return None

    def SetBreakPoint(self, address):
        org = self.MemRead(address, 1)[0]
        newBreakPoint = self.dbgutil.Breakpoint(self, address, org)
        self.BreakPoints.append(newBreakPoint)
        self.MemWrite(address, b"\xcc")
        return newBreakPoint

    def GetRegs(self):
        return self.dbgutil.GetContext(self.ThreadHandle)

    def SetReg(self, reg, value):
        currentRegs = self.GetRegs()
        setattr(currentRegs, reg.lower(), value)
        self.dbgutil.SetContext(self.ThreadHandle, currentRegs)

    def SingleStep(self):
        currentRegs = self.GetRegs()
        currentRegs.eflags = currentRegs.eflags | 0x0100
        self.SetReg("eflags", currentRegs.eflags)
        self.Continue()
        currentRegs.eflags = currentRegs.eflags ^ 0x0100
        self.SetReg("eflags", currentRegs.eflags)
    
    def GetHeapInfo(self):

        # cool decomp https://github.com/wmliang/windowsland/blob/master/rtlpfreeheap.cpp
        # https://github.com/0x00ach/stuff/blob/master/heap_walk_test.c

        print(colorGreen("-----HEAP INFO-----"))
        heapCount = unpack(self.MemRead(self.PEBAddress + 0xe8, 4))
        print("Heap count: ",heapCount)
        heapList = unpack(self.MemRead(self.PEBAddress + 0xf0, 8))
        heaps = [] #array with all _HEAP structs of different heaps
        print(colorGreen("-----HEAPS-----"))
        for i in range(heapCount):
            currentHeap = unpack(self.MemRead(heapList + 8*i,8))
            print(f"Heap {i}")
            flags = unpack(self.MemRead(currentHeap+0x70,4))
            for flag in checkHeapSetFlags(flags):
                print(f"{colorYellow(flag)} | ",end="")
            print("")
            print("_HEAP base: ",colorBlue(hex(currentHeap)))
            print("Heap signature: ",hex(unpack(self.MemRead(currentHeap+0x98,4))))
            XORMASK = unpack(self.MemRead(currentHeap+0x88,8)) #XOR mask that chunk headers get xored with
            print("Heap xor mask: ", colorRed(hex(XORMASK)))
            print("\n")
            lastValidEntry = unpack(self.MemRead(currentHeap+0x48,8))
            print("Heap lastValidEntry: ",colorBlue(hex(lastValidEntry)))

            heaps.append(Heap(XORMASK,currentHeap,lastValidEntry))
        
        
        for x,heap in enumerate(heaps):
            print(colorGreen(f"-----WALKING HEAP {x}-----"))

            """
            FLINK #0x0
            BLINK #0x8
            POINTER TO SEGMENTSTRUCT 0x10
            """
            print(colorGreen("----FINDING SEGMENTS----"))
            segments = []

            firstLink = unpack(self.MemRead(heap.base +0x120,8)) # _HEAP.SegmentList.Flink
            firstSegmentPtr = unpack(self.MemRead(firstLink+0x10,8))
            
            currentLink = firstLink
            SegmentPointer = firstSegmentPtr
            while 1:
                SegmentPointer = currentLink-0x18
                segments.append(SegmentPointer)
                currentLink = unpack(self.MemRead(currentLink,8))
                if currentLink == heap.base +0x120:
                    break
            for x,segment in enumerate(segments):
                print(f"Segment {x}: ",colorBlue(hex(segment)))

            for x,segmentStruct in enumerate(segments):


                lastvalidentry = unpack(self.MemRead(segmentStruct+0x48,8))#_HEAP_SEGMENT->LastValidEntry
                firstEntry = unpack(self.MemRead(segmentStruct+0x40,8)) #_HEAP_SEGMENT->FirstEntry


                print(colorGreen(f"-----WALKING ENTRIES IN SEGMENT {x}-----"))
                print(f"First entry: ",colorBlue(hex(firstEntry)))
                print("Last valid: ",colorBlue(hex(lastValidEntry)))
                currentEntry = firstEntry
                while 1:
                    chunkHeader = (unpack(self.MemRead(currentEntry+8,8)) ^ heap.XORMASK).to_bytes(8,"little")
                    size = parseChunk(chunkHeader,currentEntry)
                    currentEntry = currentEntry +size

                    if size == 0x40:
                        print("LastChunk")
                        while(isUncommitted(self,currentEntry,segmentStruct)):
                            currentEntry = (currentEntry +0x1000) & ~0xfff
                                    

                            
                    if currentEntry >= lastvalidentry:
                        break
                currentLink = unpack(self.MemRead(currentLink,8))

            





class Attach:
    def __init__(self, PID):
        self.path = GetProcessPath(PID)
        print(self.path)
        self.arch = GetBinaryArch(self.path)
        if self.arch == "x64":
            from .x64 import dbghandler
            from .x64 import dbgutil

            self.dbghandler = dbghandler
            self.dbgutil = dbgutil
        elif self.arch == "x86":
            from .x86 import dbghandler
            from .x86 import dbgutil

            self.dbghandler = dbghandler
            self.dbgutil = dbgutil

        retvalues = self.dbgutil.AttachProcess(PID)
        self.LastEvent = retvalues[1]
        self.Exename = self.path.split("\\")[-1]
        self.Handle = wintypes.HANDLE(retvalues[0][0])
        self.ThreadHandle = kernel32.OpenThread((0xf0000 | 0x100000| 0xFFFF),False, retvalues[0][1])
        self.Pid = PID
        self.Modules = self.dbgutil.GetModules(self.Handle)
        self.BreakPoints = []
        self.BaseAdress = self.Modules[self.Exename].handle.value
        self.Breaked = False
        self.LatestBreakpoint = None
        

    def Continue(self):
        # If the process has hit a breakpoint we need to recover from it
        if self.Breaked == True:
            self.dbgutil.ContinueFromBreak(self)

        while 1:
            self.dbgutil.ContinueDebugEvent(self.LastEvent.dwProcessId, self.LastEvent.dwThreadId)
            self.LastEvent = self.dbgutil.WaitForDebugEvent()
            result = self.dbghandler.dbghandler[self.LastEvent.dwDebugEventCode](self, self.LastEvent)
            
            # If our handler returned a -1 we need to give user control again
            if result == -1:
                self.ThreadHandle = kernel32.OpenThread((0xf0000 | 0x100000| 0xFFFF),False, self.LastEvent.dwThreadId)
                break

    def MemRead(self, address, numberOfBytes):
        # Make arguments into ctypes
        lpBaseAddress = ctypes.c_ulonglong(address)
        lpBuffer = (ctypes.c_char * numberOfBytes)()
        nSize = ctypes.c_size_t(numberOfBytes)
        lpNumberOfBytesRead = ctypes.c_size_t()

        result = kernel32.ReadProcessMemory(
            self.Handle, lpBaseAddress, lpBuffer, nSize, ctypes.byref(lpNumberOfBytesRead)
        )
        if result == 0:
            raise ctypes.WinError(ctypes.get_last_error())
        # Return a correct array in case we read less than the asked amount of bytes
        CorrectlySizedArray = (ctypes.c_char * lpNumberOfBytesRead.value)()
        ctypes.memmove(CorrectlySizedArray, lpBuffer, lpNumberOfBytesRead.value)
        return CorrectlySizedArray

    def MemWrite(self, address, buffer):

        lpBaseAddress = ctypes.c_ulonglong(address)

        lpBuffer = (ctypes.c_char * len(buffer))()
        ctypes.memmove(lpBuffer, buffer, len(buffer))

        nSize = ctypes.c_size_t(len(buffer))

        result = kernel32.WriteProcessMemory(
            self.Handle, lpBaseAddress, lpBuffer, nSize, None
        )
        if result == 0:
            raise ctypes.WinError(ctypes.get_last_error())
        return None

    def SetBreakPoint(self, address):
        org = self.MemRead(address, 1)[0]
        newBreakPoint = self.dbgutil.Breakpoint(self, address, org)
        self.BreakPoints.append(newBreakPoint)
        self.MemWrite(address, b"\xcc")
        return newBreakPoint

    def GetRegs(self):
        return self.dbgutil.GetContext(self.ThreadHandle)

    def SetReg(self, reg, value):
        currentRegs = self.GetRegs()
        setattr(currentRegs, reg.lower(), value)
        self.dbgutil.SetContext(self.ThreadHandle, currentRegs)

    def SingleStep(self):
        currentRegs = self.GetRegs()
        currentRegs.eflags = currentRegs.eflags | 0x0100
        self.SetReg("eflags", currentRegs.eflags)
        self.Continue()
        currentRegs.eflags = currentRegs.eflags ^ 0x0100
        self.SetReg("eflags", currentRegs.eflags)


