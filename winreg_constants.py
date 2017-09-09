# File from winregmitm project
# Copyright (C) Santiago Hernandez Ramos <shramos@protonmail.com>
# For more information about the project: https://github.com/shramos/winregmitm

# General Winreg packet
OPNUM = slice(146, 148)
PACKET_TYPE = slice(118, 119)
NETBIOS_LENGTH = slice(1, 4)
SMB2_DATA_LENGTH = slice(96, 100)
DCE_FRAG_LENGTH = slice(132, 134)
# GetVersion packet
HANDLE = slice(148, 168)
# CreateKey packet
NAME_LEN = slice(168, 170)
CK_ACCESS_MASK = slice(-12, -8)
NAME_SIZE = slice(170, 172)
MAX_COUNT = slice(176, 180)
ACTUAL_COUNT = slice(184, 188)
# SetValue packet
RRS_MAX_COUNT = slice(196, 200)
RRS_SIZE = slice(-4, None)
# OpenKey packet
OPENKEY_ACCESS_MASK = slice(-4, 4)
OPENKEY_HANDLE = slice(140, 160)
ACCESS_MASK = slice(-4, None)
# Negotiate packet
NEG_VERSION = slice(126, 133)
# Challenge packet
CHA_VERSION = slice(107, 114)
CHALLENGE = slice(131, 138)
# Authorization packet
AUTH_VERSION = slice(113, 120)
USERNAME = slice(233, 272)
DOMAIN = slice(201, 232)
NTLM_RESPONSE = slice(327, 343)
TARGET = slice(343, 655)
