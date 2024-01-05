from ctypes import *
from .libc_funcs import *
from time import sleep

#Functions to run before we execute the file

def get_start_addr(exe_contents):
    E_ENTRY = 0x18
    return int.from_bytes(exe_contents[E_ENTRY:E_ENTRY+8],"little")

#Gets the binary base of the binary (NOT THE SAME AS PIE BASE)
def get_binary_base(exe_contents):
    E_PH = 0x20
    e_ph_off = int.from_bytes(exe_contents[E_PH:E_PH+8],"little")
    e_ph_vmem_addr = int.from_bytes(exe_contents[e_ph_off+0x10:e_ph_off+0x18],"little")
    binary_base = e_ph_vmem_addr & 0xfff000
    return binary_base

#Gets all base addresses
def get_base_addresses(exe_contents):
    start_addr = get_start_addr(exe_contents)
    binary_base = get_binary_base(exe_contents)
    f_start_addr = start_addr - binary_base
    return start_addr, binary_base, f_start_addr

#Gets whether the binary has PIE before running it
def is_pie(exe_contents):
    bin_type = int.from_bytes(exe_contents[0x10:0x10+2],"little")
    if bin_type == 0x3:
        return True
    return False

def get_pie_base(pid):
    memfd_name = "/memfd:Kebaaaaaaaaaaaabbbbbbb"
    with open(f"/proc/{pid}/maps","r") as f:
        maps_content = f.readlines()
    
    pie_base = 0x0
    for item in maps_content:
        if memfd_name in item:
            pie_base = int(item.split("-")[0],16)
            break
    return pie_base



def CreateDebugeeProcess(exe_name):
    with open(exe_name,"rb") as f:
        exe_contents = f.read()
    start_addr,binary_base ,f_start_addr = get_base_addresses(exe_contents)

    vmem_fd = memfd_create("Kebaaaaaaaaaaaabbbbbbb",0)
    
    written = write_fd(vmem_fd, exe_contents, len(exe_contents))
    lseek(vmem_fd,0,SEEK_SET)
    
    HAS_PIE = is_pie(exe_contents)
    PIE_base = 0x0


    pipefd_array = c_int*2
    #Stdout pipe
    stdout_bak = dup(1)
    stdout_pipefd = pipefd_array()
    pipe2(stdout_pipefd, c_int(0))
    dup2(stdout_pipefd[1],1)

    #stdin pipe figure out how to halt process to do this
    # stdin_bak = dup(0)
    # stdin_pipefd = pipefd_array()
    # pipe2(stdin_pipefd,c_int(0))
    # dup2(stdin_pipefd[1],0)

    child = fork()
    if child == 0:
        ptrace(PTRACE_TRACEME, 0, 0, 0)
        #Weird and hacky way to disable buffering, but works almost every time
        #We need to find a way to know where libstdbuf.so is
        #Thinking along the lines of a cfg, where we look for it first run the save it
        fexecve(vmem_fd,["./debug"],["LD_PRELOAD=/usr/libexec/coreutils/libstdbuf.so","_STDBUF_O=0"])
    else:
        close_fd(stdout_pipefd[1])
        dup2(stdout_bak,1)
        # Figure out how to halt process to do this
        # Currently the problem is the program won't halt if you send NO input to it
        # We need to make sure it halts, if it's missing to receive input
        # close_fd(stdin_pipefd[0])
        # dup2(stdin_bak,0)
        #We need to grab the PIE Base first
        stdin_pipefd = 0
        waitpid(child)
        if(HAS_PIE):
            PIE_base = get_pie_base(child)

        return child, binary_base, HAS_PIE, PIE_base, stdin_pipefd, stdout_pipefd

