from client import Client
from back_door import BackDoor
import sys
from typing import Union


def shutdown():
    print("You must specify one argument -> CLIENT or SERVER")
    sys.exit()


def process_arg(arg) -> Union[bool, str]:
    if len(arg) != 1:
        shutdown()
    elif arg[0] == "SERVER":
        return False
    elif arg[0] == "CLIENT":
        return True
    else:
        shutdown()


def run_server() -> None:
    b = BackDoor()
    b.start()


def run_client() -> None:
    c = Client()
    c.start()


def main() -> None:
    if process_arg(sys.argv[1]):
        run_client()
    else:
        run_server()


if __name__ == "__main__":
    main()
