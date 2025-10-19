from colorama import Fore, Style

def warn(text: str, *values: object | None):
    if values: print(f"{Fore.YELLOW}{text}{Style.RESET_ALL}", *values)
    else: print(f"{Fore.YELLOW}{text}{Style.RESET_ALL}")
    
def error(text: str, *values: object | None):
    if values: print(f"{Fore.RED}{text}{Style.RESET_ALL}", *values)
    else: print(f"{Fore.RED}{text}{Style.RESET_ALL}")

def info(text: str, *values: object | None):
    if values: print(f"{Fore.GREEN}{text}{Style.RESET_ALL}", *values)
    else: print(f"{Fore.GREEN}{text}{Style.RESET_ALL}")

def debug(text: str, *values: object | None):
    if values: print(f"{Fore.CYAN}{text}{Style.RESET_ALL}", *values)
    else: print(f"{Fore.CYAN}{text}{Style.RESET_ALL}")
