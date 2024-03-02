from colorama import Fore

def unpack(array):
    return int.from_bytes(array,"little")

def colorRed(string):
    return(f"{Fore.RED}{string}{Fore.WHITE}")

def colorYellow(string):
    return(f"{Fore.YELLOW}{string}{Fore.WHITE}")

def colorGreen(string):
    return(f"{Fore.GREEN}{string}{Fore.WHITE}")

def colorBlue(string):
    return(f"{Fore.BLUE}{string}{Fore.WHITE}")