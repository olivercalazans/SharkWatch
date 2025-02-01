# MIT License
# Copyright (c) 2024 Oliver Ribeiro Calazans Jeronimo
# Repository: https://github.com/olivercalazans/WireSpy
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software...

import pyshark
import os
from interface import Interface

class Main:

    def __init__(self) -> None:
        self._interface = Interface()._get_interface()
        self._data      = dict()
        self._packet    = None
        self._ip        = None
        self._mac       = None
        self._port      = None


    def _continuous_sniff(self) -> None:
        try:
            sniffer = pyshark.LiveCapture(interface=self._interface)
            for packet in sniffer.sniff_continuously():
                self._packet = packet
                self._process_packet()
        except KeyboardInterrupt:  print('Process interrupted by user')
        except EOFError:           print('EOFError encountered. Tshark process ended.')
        except Exception as error: print(f'Unexpected error: {error}')
        finally: sniffer.close()


    def _process_packet(self) -> None:
        self._get_ip()
        self._get_mac()
        self._get_port()
        self._update_or_add_data()
        self._display()


    def _get_ip(self) -> None:
        self._ip = self.pink(self._packet.ip.src) if 'ip' in self._packet else self.red('Unknown')


    def _get_mac(self) -> None:
        self._mac = self.green(self._packet.eth.src) if 'eth' in self._packet else '-'


    def _get_port(self) -> None:
        if   'TCP' in self._packet: self._port = self._packet.tcp.srcport
        elif 'UDP' in self._packet: self._port = self._packet.udp.srcport
        else:                       self._port = None


    def _update_or_add_data(self) -> None:
        if not self._ip in self._data:
            self._add_data()
        else:
            self._update_data()


    def _add_data(self) -> None:
        self._data[self._ip] = {
            'pkts' : 1, 
            'mac'  : self._mac,
            'ports': {self._port} if self._port else set()
            }


    def _update_data(self) -> None:
        self._data[self._ip]['pkts'] += 1
        if self._port: self._data[self._ip]['ports'].add(self._port)


    def _display(self) -> None:
        os.system('clear')
        for ip, details in self._data.items():
            mac      = details['mac'] 
            pkts_num = details['pkts']
            ports    = ', '.join(details['ports'])
            print(f'{ip:<23}, {mac} ({pkts_num})')
            print(f'    - {self.yellow("Ports")}: {ports}')


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