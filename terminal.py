from colorama import Fore, Style

def print_yellow(text: str, *values: object | None):
    if values: print(f"{Fore.YELLOW}{text}{Style.RESET_ALL}", *values)
    else: print(f"{Fore.YELLOW}{text}{Style.RESET_ALL}")
    
def print_red(text: str, *values: object | None):
    if values: print(f"{Fore.RED}{text}{Style.RESET_ALL}", *values)
    else: print(f"{Fore.RED}{text}{Style.RESET_ALL}")

def print_green(text: str, *values: object | None):
    if values: print(f"{Fore.GREEN}{text}{Style.RESET_ALL}", *values)
    else: print(f"{Fore.GREEN}{text}{Style.RESET_ALL}")

def print_cyan(text: str, *values: object | None):
    if values: print(f"{Fore.CYAN}{text}{Style.RESET_ALL}", *values)
    else: print(f"{Fore.CYAN}{text}{Style.RESET_ALL}")
