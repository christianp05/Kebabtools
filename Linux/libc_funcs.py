import ctypes

libc = ctypes.CDLL("libc.so.6")

#ptrace constants
PTRACE_TRACEME = 0
PT_TRACE_ME = PTRACE_TRACEME
PTRACE_PEEKTEXT=1
PTRACE_PEEKDATA=2
PTRACE_PEEKUSER=3
PTRACE_POKETEXT=4
PTRACE_POKEDATA=5
PTRACE_POKEUSER=6
PTRACE_CONT=7
PTRACE_KILL=8
PTRACE_SINGLESTEP=9
PTRACE_GETREGS=12
PTRACE_SETREGS=13
PTRACE_GETFPREGS=14
PTRACE_SETFPREGS=15
PTRACE_ATTACH=16
PTRACE_DETACH=17
PTRACE_GETFPXREGS=18
PTRACE_SETFPXREGS=19
PTRACE_SYSCALL=24
PTRACE_SETOPTIONS=0x4200
PTRACE_GETEVENTMSG=0x4201
PTRACE_GETSIGINFO=0x4202
PTRACE_SETSIGINFO=0x4203
PTRACE_GETREGSET=0x4204
PTRACE_SETREGSET=0x4205
PTRACE_SEIZE=0x4206
PTRACE_INTERRUPT=0x4207
PTRACE_LISTEN=0x4208
PTRACE_PEEKSIGINFO=0x4209
PTRACE_GETSIGMASK=0x420a
PTRACE_SETSIGMASK=0x420b
PTRACE_SECCOMP_GET_FILTER=0x420c
PTRACE_SECCOMP_GET_METADATA=0x420d
PTRACE_GET_SYSCALL_INFO=0x420e
PT_READ_I=PTRACE_PEEKTEXT
PT_READ_D=PTRACE_PEEKDATA
PT_READ_U=PTRACE_PEEKUSER
PT_WRITE_I=PTRACE_POKETEXT
PT_WRITE_D=PTRACE_POKEDATA
PT_WRITE_U=PTRACE_POKEUSER
PT_CONTINUE=PTRACE_CONT
PT_KILL=PTRACE_KILL
PT_STEP=PTRACE_SINGLESTEP
PT_GETREGS=PTRACE_GETREGS
PT_SETREGS=PTRACE_SETREGS
PT_GETFPREGS=PTRACE_GETFPREGS
PT_SETFPREGS=PTRACE_SETFPREGS
PT_ATTACH=PTRACE_ATTACH
PT_DETACH=PTRACE_DETACH
PT_GETFPXREGS=PTRACE_GETFPXREGS
PT_SETFPXREGS=PTRACE_SETFPXREGS
PT_SYSCALL=PTRACE_SYSCALL
PT_SETOPTIONS=PTRACE_SETOPTIONS
PT_GETEVENTMSG=PTRACE_GETEVENTMSG
PT_GETSIGINFO=PTRACE_GETSIGINFO
PT_SETSIGINFO=PTRACE_SETSIGINFO
PTRACE_O_TRACESYSGOOD=0x00000001
PTRACE_O_TRACEFORK=0x00000002
PTRACE_O_TRACEVFORK=0x00000004
PTRACE_O_TRACECLONE=0x00000008
PTRACE_O_TRACEEXEC=0x00000010
PTRACE_O_TRACEVFORKDONE=0x00000020
PTRACE_O_TRACEEXIT=0x00000040
PTRACE_O_TRACESECCOMP=0x00000080
PTRACE_O_EXITKILL=0x00100000
PTRACE_O_SUSPEND_SECCOMP=0x00200000
PTRACE_O_MASK=0x003000ff
PTRACE_EVENT_FORK=1
PTRACE_EVENT_VFORK=2
PTRACE_EVENT_CLONE=3
PTRACE_EVENT_EXEC=4
PTRACE_EVENT_VFORK_DONE=5
PTRACE_EVENT_EXIT=6
PTRACE_EVENT_SECCOMP=7
PTRACE_EVENT_STOP=128
PTRACE_PEEKSIGINFO_SHARED=1
PTRACE_SYSCALL_INFO_NONE=0
PTRACE_SYSCALL_INFO_ENTRY=1
PTRACE_SYSCALL_INFO_EXIT=2
PTRACE_SYSCALL_INFO_SECCOMP=3

#fseek constants
SEEK_SET = 0
SEEK_CUR = 1
SEEK_END = 2

#setvbuf
_IONBF = 2

class user_regs_struct(ctypes.Structure):
	_fields_=[
		("r15",ctypes.c_ulong),
		("r14",ctypes.c_ulong),
		("r13",ctypes.c_ulong),
		("r12",ctypes.c_ulong),
		("rbp",ctypes.c_ulong),
		("rbx",ctypes.c_ulong),
		("r11",ctypes.c_ulong),
		("r10",ctypes.c_ulong),
		("r9",ctypes.c_ulong),
		("r8",ctypes.c_ulong),
		("rax",ctypes.c_ulong),
		("rcx",ctypes.c_ulong),
		("rdx",ctypes.c_ulong),
		("rsi",ctypes.c_ulong),
		("rdi",ctypes.c_ulong),
		("orig_rax",ctypes.c_ulong),
		("rip",ctypes.c_ulong),
		("cs",ctypes.c_ulong),
		("eflags",ctypes.c_ulong),
		("rsp",ctypes.c_ulong),
		("ss",ctypes.c_ulong),
		("fs_base",ctypes.c_ulong),
		("gs_base",ctypes.c_ulong),
		("ds",ctypes.c_ulong),
		("es",ctypes.c_ulong),
		("fs",ctypes.c_ulong),
		("gs",ctypes.c_ulong)
	]



def ptrace(request:int, pid = 0, addr = None, data = None):
	_ptrace = libc.ptrace
	_ptrace.restype = ctypes.c_long
	return _ptrace(request, pid, addr, data)

def fork():
	_fork = libc.fork
	_fork.restype = ctypes.c_uint
	return _fork()

def wait():
	_wait = libc.wait
	_wait.restype = ctypes.c_int
	status_pointer = ctypes.pointer(ctypes.c_int(0))
	result = _wait(status_pointer)
	return (result,status_pointer.contents.value)

def waitpid(pid):
	_waitpid = libc.wait
	_waitpid.restype = ctypes.c_int
	status_pointer = ctypes.pointer(ctypes.c_int(0))
	result = _waitpid(ctypes.c_uint(pid),status_pointer,ctypes.c_uint(0))
	return (result,status_pointer.contents.value)

def disable_buffering(stream):
	setvbuf = libc.setvbuf
	setvbuf.restype = ctypes.c_void_p
	setvbuf(stream, 0, _IONBF, 0)


#We basically read the whole file in, modify the first byte in the entry point and execute it with execvp
def memfd_create(name:str, flags:int):
	_memfd_create = libc.memfd_create
	_memfd_create.restype = ctypes.c_int
	return _memfd_create(name.encode(),ctypes.c_int(flags))



def lseek(fd:int, offset:int, whence:int):
	_lseek = libc.lseek
	return _lseek(ctypes.c_int(fd),ctypes.c_int(offset),ctypes.c_int(whence))


def write_fd(fd:int, buf:bytes, count:int):
	_write_fd = libc.write
	_write_fd.restype = ctypes.c_ssize_t
	return _write_fd(ctypes.c_int(fd), buf, ctypes.c_size_t(count))

def fexecve(fd:int, argv:list, envp:list):
	_fexecve = libc.fexecve
	_fexecve.restype = ctypes.c_int

	argv_len = len(argv)
	envp_len = len(envp)
	
	argv_array_t = ctypes.c_char_p * argv_len
	envp_array_t = ctypes.c_char_p * envp_len
	
	argv_arr = argv_array_t()
	envp_arr = envp_array_t()
	
	for i in range(0,argv_len):
		argv_arr[i] = argv[i].encode()
	for i in range(0,envp_len):
		envp_arr[i] = envp[i].encode()
	
	if argv_len == 0:
		argv_arr = 0
	if envp_len == 0:
		envp_arr = 0

	return _fexecve(ctypes.c_int(fd), argv_arr, envp_arr)

def pipe2(pipefd,flags):
	_pipe2 = libc.pipe2
	_pipe2.restype = ctypes.c_int
	return _pipe2(pipefd,flags)

def dup(oldfd):
	_dup = libc.dup
	_dup.restype = ctypes.c_int
	return _dup(ctypes.c_int(oldfd))

def dup2(oldfd,newfd):
	_dup2 = libc.dup2
	_dup2.restype = ctypes.c_int
	return _dup2(ctypes.c_int(oldfd),ctypes.c_int(newfd))

def close_fd(fd):
	_close_fd = libc.close
	_close_fd.restype = ctypes.c_int
	return _close_fd(ctypes.c_int(fd))

def read_fd(fd,amount):
	_read_fd = libc.read
	_read_fd.restype = ctypes.c_int
	p = ctypes.create_string_buffer(amount)
	readbytes = _read_fd(ctypes.c_int(fd),p,ctypes.c_int(amount))
	return (readbytes,p)

