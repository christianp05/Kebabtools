from ctypes import *
from .libc_funcs import *
from .dbg_util import *
from time import sleep
import os



class Process:
    def __init__(self, exename):
        retvalues = CreateDebugeeProcess(exename)
        self.Exename = exename
        self.Pid = retvalues[0]
        self.BreakPoints = []
        self.BaseAddress = retvalues[3] + retvalues[1]
        self.HasPie = retvalues[2]
        self.StdinPipe = retvalues[4]
        self.StdoutPipe = retvalues[5]
        self.Breaked = False
        self.LatestBreakpoint = None

    def GetRegs(self):
        regs = user_regs_struct()
        ptrace(PTRACE_GETREGS, self.Pid, 0, byref(regs))
        return regs
   
    def SetReg(self, register:str, value:int):
        curr_regs = self.GetRegs()
        setattr(curr_regs, register.lower(), value)
        return ptrace(PTRACE_SETREGS, self.Pid, 0, byref(curr_regs))

    def SingleStep(self):
        ret_val = ptrace(PTRACE_SINGLESTEP, self.Pid, 0, 0)
        waitpid(self.Pid)
        return ret_val

    def MemRead(self, address, numberOfBytes):
        #We can only peek 8 bytes at a time
        buffer = b''
        while numberOfBytes>=8:
            buffer+=(ptrace(PTRACE_PEEKDATA, self.Pid, c_void_p(address))&0xffffffffffffffff).to_bytes(8,"little")
            address+=8
            numberOfBytes-=8
        
        if numberOfBytes == 0:
            return buffer
        
        and_val = 0
        for i in range(0,numberOfBytes):
            and_val = and_val << 8
            and_val+=0xff
            
        buffer+=(ptrace(PTRACE_PEEKDATA,self.Pid,c_void_p(address)) & and_val).to_bytes(numberOfBytes,"little")
        return buffer
    
    def MemWrite(self, address, buffer):
        buffer_len = len(buffer)
        buffer_list = []
        
        #divide the buffer up into 8 byte chunks
        for i in range(0,buffer_len//8):
            buffer_list.append(buffer[i*8:(i+1)*8])

        buffer_list.append(buffer[(i+1)*8:])

        #Write those 8 byte chunks
        for to_write in buffer_list:
            casted = int.from_bytes(to_write,"little") & 0xffffffffffffffff
            ptrace(PTRACE_POKEDATA,self.Pid, c_void_p(address), c_ulong(casted))
            address+=8

    
    def BreakPoint(self,address:int):
        if self.HasPie:
            address += self.BaseAddress

        #Save the old data on the breakpoint
        brkp = {}
        
        brkp["address"] = address
        brkp["orig"] = ptrace(PTRACE_PEEKDATA, self.Pid, c_void_p(address), 0)
        if brkp["orig"] == -1:
            print(f"Failed setting breakpoint at address {address:#x}")
            return None
        self.BreakPoints.append(brkp)
        #Now we change it so we break
        brkp_data = (brkp["orig"] & 0xffffffffffffff00) | 0xcc
        return ptrace(PTRACE_POKEDATA,self.Pid, c_void_p(address), c_ulong(brkp_data))

    def Continue(self):
        regs = self.GetRegs()
        #If we're already breaked we need to restore the state step over it, add the breakpoint, and continue again
        if self.Breaked:
            self.Breaked = False
            new_rip = regs.rip-1
            bp = self.GetBreakPoint(new_rip)
            ptrace(PTRACE_POKEDATA,self.Pid, c_void_p(bp["address"]),c_ulong(bp["orig"]))
            self.SetReg("rip",new_rip)
            self.SingleStep()
            ptrace(PTRACE_POKEDATA,self.Pid,c_void_p(bp["address"]),c_ulong((bp["orig"]&0xffffffffffffff00) | 0xcc))
            ptrace(PTRACE_CONT, self.Pid, 0,0)
            waitpid(self.Pid)
        
        #If we're not already breaked we check if we should be and set things accordingly
        while 1:
            new_rip = self.GetRegs().rip-1
            bp = self.GetBreakPoint(new_rip)
            if bp==None:
                ptrace(PTRACE_CONT,self.Pid,0,0)
                waitpid(self.Pid)
            else:
                self.Breaked = True
                break

    def IsBreakPoint(self, addr):
        for bp in self.BreakPoints:
            if bp["address"] == addr:
                return True
        return False

    def GetBreakPoint(self,addr):
        for bp in self.BreakPoints:
            if bp["address"] == addr:
                return bp
        return None
    
    def vmmap(self):
        
        vmmap_list = []
        
        with open(f"/proc/{self.Pid}/maps","r") as f:
            maps_content = f.readlines()
        
        for mapping in maps_content:
            
            start_addr = int(mapping.split("-")[0],16)
            end_addr = int(mapping.split("-")[1].split(" ")[0],16)
            size = end_addr-start_addr
            description = mapping.split("  ")[-1][:-1]
            if not (description[0] == "/" or description[0] == "[" or description[0:2] == " /"):
                description = "[anon]"

            if "/memfd:Kebaaaaaaaaaaaabbbbbbb" in description:
                description = self.Exename
            
            prots = mapping.split(" ")[1]
            
            vmmap_dict = {
                "start":start_addr,
                "end":end_addr,
                "size":size,
                "prots":prots,
                "description":description
            }
            vmmap_list.append(vmmap_dict)
        return vmmap_list

    def recv(self,amount):
        return read_fd(self.StdoutPipe[0],amount)
    
    def recvuntil(self, until):
        buf = b''
        while 1:
            readBytes, tmpbuf = read_fd(self.StdoutPipe[0],1)
            buf+=tmpbuf
            if until in buf:
                break
        return buf
    
    def recvline(self):
        return self.recvuntil(b'\n')









        

            

            
