# MIT License
# Copyright (c) 2024 Oliver Ribeiro Calazans Jeronimo
# Repository: https://github.com/olivercalazans/WireSpy
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software...


import subprocess


class Setup:

    def __init__(self):
        self._interfaces = None

    
    def _get_interface(self) -> str:
        return self._validate_interface()


    def _validate_interface(self) -> str:
        self._get_network_interfaces()
        if isinstance(self._interfaces, str):
            return self._interfaces
        return self._select_an_interface()


    def _select_an_interface(self) -> str: 
        for index, iface in enumerate(self._interfaces):
            print(f'{index} - {iface}')
        
        while True:
            index = input('Select an interface: ')
            index = self._validate_input(index)

            if not index:
                print('Use a number to select')
                continue
            
            if index >= 0 and index < len(self._interfaces):
                return self._interfaces[index]
            
            print(f'Select between 0 and {len(self._interfaces) - 1}')


    @staticmethod
    def _validate_input(index):
        try:    return int(index)
        except: return None 



    def _get_network_interfaces(self) -> None:
        try:
            result           = subprocess.run(['ip', '-o', 'link', 'show'], capture_output=True, text=True, check=True)
            self._interfaces = [line.split(': ')[1] for line in result.stdout.splitlines()]
        except subprocess.CalledProcessError:
            self._interfaces = input(f'Write an interface: ')
