# MIT License
# Copyright (c) 2024 Oliver Ribeiro Calazans Jeronimo
# Repository: https://github.com/olivercalazans/WireSpy
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software...


import pyshark
import sys, os


class Main:

    def __init__(self) -> None:
        self._data     = dict()
        self._packet   = None
        self._new_data = None


    def _continuos_sniff(self) -> None:
        for packet in pyshark.LiveCapture(interface='enp0s8').sniff_continuously():
            if 'IP' in packet:
                self._packet = packet
                self._process_packet()


    def _process_packet(self) -> None:
        self._get_data_from_packet()
        self._update_or_add_data()
        self._display()


    def _get_data_from_packet(self) -> dict:
        self._new_data = { 
            'ip':   self._packet.ip.src,
            'port': self._get_port()
            }


    def _get_port(self) -> int:
        if 'TCP' in self._packet:
            return self._packet.tcp.srcport
        elif 'UDP' in self._packet:
            return self._packet.udp.srcport
        else:
            return None


    def _update_or_add_data(self) -> None:
        ip   = self._new_data['ip']
        port = self._new_data['port']
        if self._new_data['ip'] in self._data:
            self._update_data(ip, port)
        else:
            self._add_data(ip, port)


    def _update_data(self, ip:str, port:str) -> None:
        if port != None:
            self._data[ip]['pkts'] += 1
            self._data[ip]['ports'].add(port)


    def _add_data(self, ip:str, port:str) -> None:
        port = port if port != None else ''
        self._data[ip] = {'pkts': 1, 'ports': {port}}


    def _display(self) -> None:
        os.system('clear')
        for packet in self._data.items():
            ip       = packet[0]
            pkts_num = packet[1]['pkts']
            ports    = ', '.join(packet[1]['ports'])
            sys.stdout.write(f'{ip:<15} ({pkts_num})>> Ports: {ports}\n')
            sys.stdout.flush()


if __name__ == '__main__':
    scan = Main()
    scan._continuos_sniff()
