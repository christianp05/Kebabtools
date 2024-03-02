import platform
import sys
sys.dont_write_bytecode = True
if platform.system() == "Windows":
    from .Windows.kebabtools import *
elif platform.system() == "Linux":
    from .Linux.kebabtools import *
else:
    print("Unsupported system")