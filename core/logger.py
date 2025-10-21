from colorama import Fore, Style


def __print(text: str, color: str, *values: object | None):
    if values:
        print(f"{color}{text}{Style.RESET_ALL}", *values)
    else:
        print(f"{color}{text}{Style.RESET_ALL}")


def warn(text: str, *values: object | None):
    __print(text, Fore.YELLOW, *values)


def error(text: str, *values: object | None):
    __print(text, Fore.RED, *values)


def info(text: str, *values: object | None):
    __print(text, Fore.GREEN, *values)


def debug(text: str, *values: object | None):
    __print(text, Fore.CYAN, *values)
