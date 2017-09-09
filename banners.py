# -*- coding: utf-8 -*-
# File from winregmitm project
# Copyright (C) Santiago Hernandez Ramos <shramos@protonmail.com>
# For more information about the project: https://github.com/shramos/winregmitm

from termcolor import colored


winreg = """__        _____ _   _ ____  _____ ____ 
\ \      / /_ _| \ | |  _ \| ____/ ___|
 \ \ /\ / / | ||  \| | |_) |  _|| |  _ 
  \ V  V /  | || |\  |  _ <| |__| |_| |
   \_/\_/  |___|_| \_|_| \_\_____\____|"""

mitm = """                                   
             _ __ ___ (_) |_ _ __ ___  
            | '_ ` _ \| | __| '_ ` _ \ 
            | | | | | | | |_| | | | | |
            |_| |_| |_|_|\__|_| |_| |_|
"""
author = """                   <Santiago Hernandez>

"""


def get_banner():
    return winreg + colored(mitm, 'blue', attrs=['bold']) + author
