# KebabTools

```py
from KebabTools import Process


p = Process("c:/Users/chris/Desktop/KebabTools/KebabTools/Examples/sample.exe")
print(p.Modules["ntdll.dll"].exportedFuncs)
print("BASE: ", hex(p.BaseAdress))
p.SetBreakPoint(p.BaseAdress + 0x1012)
p.Continue()
p.SetReg("rcx", p.BaseAdress)
p.Continue()
p.SetReg("rcx", p.BaseAdress + 1)
p.Continue()
input()
```

```py
from KebabTools import Process
from pwn import *
p = Process("c:/Users/chris/Desktop/KebabTools/KebabTools/Examples/sample32.exe")
print("BASE: ", hex(p.BaseAdress))
p.SetBreakPoint(p.BaseAdress + 0x1045)
p.Continue()
stack = p.GetRegs().esp
print(hex(stack))
p.MemWrite(stack,p32(p.BaseAdress))
p.Continue()
input()
```