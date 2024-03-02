from .util import *

class Heap:
    def __init__(self, XORMASK, base,lastvalidentry):
        self.XORMASK = XORMASK
        self.base = base
        self.lastvalidentry = lastvalidentry


# Define the bitmasks
HEAP_NO_SERIALIZE = 0x00000001
HEAP_GROWABLE = 0x00000002
HEAP_GENERATE_EXCEPTIONS = 0x00000004
HEAP_ZERO_MEMORY = 0x00000008
HEAP_REALLOC_IN_PLACE_ONLY = 0x00000010
HEAP_TAIL_CHECKING_ENABLED = 0x00000020
HEAP_FREE_CHECKING_ENABLED = 0x00000040
HEAP_DISABLE_COALESCE_ON_FREE = 0x00000080
HEAP_CREATE_ALIGN_16 = 0x00010000
HEAP_CREATE_ENABLE_TRACING = 0x00020000
HEAP_CREATE_ENABLE_EXECUTE = 0x00040000
HEAP_MAXIMUM_TAG = 0x0FFF
HEAP_PSEUDO_TAG_FLAG = 0x8000
HEAP_TAG_SHIFT = 18
HEAP_CREATE_SEGMENT_HEAP = 0x00000100
HEAP_CREATE_HARDENED = 0x00000200

HEAP_ENTRY_BUSY = 0x1
HEAP_ENTRY_EXTRA_PRESENT = 0x2
HEAP_ENTRY_FILL_PATTERN = 0x4
HEAP_ENTRY_VIRTUAL_ALLOC = 0x08
HEAP_ENTRY_LAST_ENTRY = 0x10
HEAP_ENTRY_SETTABLE_FLAG1 = 0x20
HEAP_ENTRY_SETTABLE_FLAG2 = 0x40
HEAP_ENTRY_SETTABLE_FLAG3 = 0x80

# List of all bitmasks for easy iteration
heapBitmasks = [
    ("HEAP_NO_SERIALIZE", HEAP_NO_SERIALIZE),
    ("HEAP_GROWABLE", HEAP_GROWABLE),
    ("HEAP_GENERATE_EXCEPTIONS", HEAP_GENERATE_EXCEPTIONS),
    ("HEAP_ZERO_MEMORY", HEAP_ZERO_MEMORY),
    ("HEAP_REALLOC_IN_PLACE_ONLY", HEAP_REALLOC_IN_PLACE_ONLY),
    ("HEAP_TAIL_CHECKING_ENABLED", HEAP_TAIL_CHECKING_ENABLED),
    ("HEAP_FREE_CHECKING_ENABLED", HEAP_FREE_CHECKING_ENABLED),
    ("HEAP_DISABLE_COALESCE_ON_FREE", HEAP_DISABLE_COALESCE_ON_FREE),
    ("HEAP_CREATE_ALIGN_16", HEAP_CREATE_ALIGN_16),
    ("HEAP_CREATE_ENABLE_TRACING", HEAP_CREATE_ENABLE_TRACING),
    ("HEAP_CREATE_ENABLE_EXECUTE", HEAP_CREATE_ENABLE_EXECUTE),
    ("HEAP_MAXIMUM_TAG", HEAP_MAXIMUM_TAG),
    ("HEAP_PSEUDO_TAG_FLAG", HEAP_PSEUDO_TAG_FLAG),
    ("HEAP_TAG_SHIFT", HEAP_TAG_SHIFT),
    ("HEAP_CREATE_SEGMENT_HEAP", HEAP_CREATE_SEGMENT_HEAP),
    ("HEAP_CREATE_HARDENED", HEAP_CREATE_HARDENED),
]

entryBitMasks = [
    ("HEAP_ENTRY_BUSY",HEAP_ENTRY_BUSY),
    ("HEAP_ENTRY_EXTRA_PRESENT",HEAP_ENTRY_EXTRA_PRESENT),
    ("HEAP_ENTRY_FILL_PATTERN",HEAP_ENTRY_FILL_PATTERN),
    ("HEAP_ENTRY_VIRTUAL_ALLOC",HEAP_ENTRY_VIRTUAL_ALLOC),
    ("HEAP_ENTRY_LAST_ENTRY",HEAP_ENTRY_LAST_ENTRY),
    ("HEAP_ENTRY_SETTABLE_FLAG1",HEAP_ENTRY_SETTABLE_FLAG1),
    ("HEAP_ENTRY_SETTABLE_FLAG2",HEAP_ENTRY_SETTABLE_FLAG2),
    ("HEAP_ENTRY_SETTABLE_FLAG3",HEAP_ENTRY_SETTABLE_FLAG3),

]
def checkHeapSetFlags(value):
    set_flags = []
    for name, bitmask in heapBitmasks:
        if value & bitmask:
            set_flags.append(name)
    return set_flags

def checkEntrySetFlags(value):
    set_flags = []
    for name, bitmask in entryBitMasks:
        if value & bitmask:
            set_flags.append(name)
    return set_flags

def parseChunk(chunkHeader,addr):
    Entryflags = chunkHeader[2]
    setFlags = checkEntrySetFlags(Entryflags)

    if "HEAP_ENTRY_BUSY" not in setFlags:
        print(f"{colorGreen('Free Header')} | ",end="")
    for flag in setFlags:
        print(f"{colorYellow(flag)} | ",end="")

    print("")
    if "HEAP_ENTRY_VIRTUAL_ALLOC" in setFlags:
        size = unpack(chunkHeader[0:2]) *0x10
    else:
        size = unpack(chunkHeader[0:2]) *0x10 #size is right shifted by 4 in the header
    print("Addr: ",colorBlue(hex(addr)))
    print("Size: ",hex(size))
    print("Smalltagindex: ",hex(chunkHeader[3]))
    print("PrevSize: ",hex(unpack(chunkHeader[4:6])*0x10)) #prevsize also bitshifted right 4 in the header
    print("UnusedBytes: ",hex(chunkHeader[7]))

    return size

def isUncommitted(proc,testadr,segment):
    start = unpack(proc.MemRead(segment+0x60,8))
    current = start
    while(current != segment+0x60):
        yeet = unpack(proc.MemRead(current+0x10,8))
        if testadr >= unpack(proc.MemRead(current+0x10,8)) and testadr <= (unpack(proc.MemRead(current+0x10,8)) + unpack(proc.MemRead(current+0x18,8))):
            return True
        current = unpack(proc.MemRead(current,8))
