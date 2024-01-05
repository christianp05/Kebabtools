EXCEPTION_DEBUG_EVENT = 1
CREATE_THREAD_DEBUG_EVENT = 2
CREATE_PROCESS_DEBUG_EVENT = 3
EXIT_THREAD_DEBUG_EVENT = 4
EXIT_PROCESS_DEBUG_EVENT = 5
LOAD_DLL_DEBUG_EVENT = 6
UNLOAD_DLL_DEBUG_EVENT = 7
OUTPUT_DEBUG_STRING_EVENT = 8
RIP_EVENT = 9

EXCEPTION_BREAKPOINT = 0x80000003
EXCEPTION_SINGLE_STEP = 0x80000004


def createProcess(process, dbgevent):
    # print("CREATE_PROCESS_DEBUG_EVENT")
    pass


def createThread(process, dbgevent):
    # print("CREATE_THREAD_DEBUG_EVENT")
    pass


def debugException(process, dbgevent):
    if dbgevent.u.Exception.ExceptionRecord.ExceptionCode == EXCEPTION_BREAKPOINT:
        count = 0
        for i in process.BreakPoints:
            if dbgevent.u.Exception.ExceptionRecord.ExceptionAddress == i.address:
                print(f"Breakpoint {count} at {hex(i.address)} triggered ")
                process.Breaked = True
                process.MemWrite(
                    process.BreakPoints[count].address,
                    process.BreakPoints[count].orgbyte,
                )
                process.LatestBreakpoint = process.BreakPoints[count]

            count += 1
        return -1
    if dbgevent.u.Exception.ExceptionRecord.ExceptionCode == EXCEPTION_SINGLE_STEP:
        return -1


def exitProcess(process, dbgevent):
    # print("EXIT_PROCESS_DEBUG_EVENT")
    exit()


def exitThread(process, dbgevent):
    # print("EXIT_THREAD_DEBUG_EVENT")
    pass


def loadDll(process, dbgevent):
    # print("LOAD_DLL_DEBUG_EVENT")
    pass


def debugStringOut(process, dbgevent):
    # print("OUTPUT_DEBUG_STRING_EVENT")
    pass


def ripEvent(process, dbgevent):
    # print("RIP_EVENT")
    pass


def unLoadDll(process, dbgevent):
    # print("UNLOAD_DLL_DEBUG_EVENT")
    pass


dbghandler = {
    3: createProcess,
    2: createThread,
    1: debugException,
    5: exitProcess,
    4: exitThread,
    6: loadDll,
    8: debugStringOut,
    9: ripEvent,
    7: unLoadDll,
}
