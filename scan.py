import pyshark
import sys


class Main:
    def __init__(self):
        pass


def clear_screen():
    sys.stdout.write("\033[F")
    sys.stdout.write("\033[K")
    sys.stdout.flush()

cap = pyshark.LiveCapture(interface='wlp2s0')

def packet_callback(packet):
    clear_screen()

    if 'IP' in packet:
        sys.stdout.write(f"Destino IP: {packet.ip.dst}\n")
        sys.stdout.flush()

cap.apply_on_packets(packet_callback)
