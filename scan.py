# MIT License
# Copyright (c) 2024 Oliver Ribeiro Calazans Jeronimo
# Repository: https://github.com/olivercalazans/WireSpy
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software...

import pyshark
import os
from aux import Setup

class Main:

    def __init__(self) -> None:
        self._data      = {}
        self._interface = Setup()._get_interface()


    def _continuous_sniff(self) -> None:
        try:
            sniffer = pyshark.LiveCapture(interface=self._interface)
            for packet in sniffer.sniff_continuously():
                if 'IP' in packet:
                    self._process_packet(packet)
        except KeyboardInterrupt:  print('Process interrupted by user')
        except EOFError:           print('EOFError encountered. Tshark process ended.')
        except Exception as error: print(f'Unexpected error: {error}')
        finally: sniffer.close()


    def _process_packet(self, packet) -> None:
        ip   = packet.ip.src
        port = self._get_port(packet)
        self._update_or_add_data(ip, port)
        self._display()


    def _get_port(self, packet) -> str:
        if 'TCP' in packet:
            return packet.tcp.srcport
        if 'UDP' in packet:
            return packet.udp.srcport
        return None


    def _update_or_add_data(self, ip:str, port:str) -> None:
        if ip not in self._data:
            self._data[ip] = {'pkts': 1, 'ports': {port} if port else set()}
        else:
            self._data[ip]['pkts'] += 1
            if port:
                self._data[ip]['ports'].add(port)


    def _display(self) -> None:
        os.system('clear')
        for ip, details in self._data.items():
            pkts_num = details['pkts']
            ports = ', '.join(details['ports'])
            print(f'{self.pink(ip):<23} ({pkts_num})>> {self.yellow("Ports")}: {ports}')


    @staticmethod
    def pink(message: str) -> str:
        return '\033[35m' + message + '\033[0m'

    @staticmethod
    def green(message:str) -> str:
        return '\033[32m' + message + '\033[0m'

    @staticmethod
    def red(message:str) -> str:
        return '\033[31m' + message + '\033[0m'

    @staticmethod
    def yellow(message:str) -> str:
        return '\033[33m' + message + '\033[0m'




if __name__ == '__main__':
    Main()._continuous_sniff()