# File from winregmitm project
# Copyright (C) Santiago Hernandez Ramos <shramos@protonmail.com>
# For more information about the project: https://github.com/shramos/winregmitm

import binascii
from scapy.layers.inet import Raw
from netfilterqueue import NetfilterQueue
from winreg_constants import *

# ---------------------------------------------------------------------
# WINREG GENERIC PACKAGES CLASS
# ---------------------------------------------------------------------
class WinregPkt(object):

    def __init__(self, pkt):
        self._pkt = pkt
        try:
            self._payload = pkt[Raw].load # Extract payload (if any)
        except IndexError:
            self._payload = None

    @staticmethod
    def _reverse(b):
        return "".join(reversed([b[i:i + 2] for i in range(0, len(b), 2)]))

    def _extract_int(self, field):
        """
        Extracts a integer field from the payload
        :param field: a slice object
        :return: integer value
        """
        if self._payload is not None:
            try:
                return int(self._reverse(binascii.hexlify(self._payload[field])), 16)
            except ValueError:
                return None
        else:
            return None

    def _extract_string(self, field):
        """
        Extracts a String field from the payload
        :param field: A slice object with the position of the field in the payload
        :return:
        """
        if self._payload is not None:
            try:
                return self._payload[field]
            except IndexError:
                return None
        else:
            return None

    def _padding(self, field):
        if field.start is None:
            start = 0
        else:
            start = field.start
        if field.stop is None:
            stop = 0
        else:
            stop = field.stop

        return abs(stop - start)

    def _insert_int(self, field, value, custom_field=None):
        """
        Insert a data value into a specific field
        :param value: hexadecimal value for insert
        :return: bool
        """
        if custom_field is None:
            field = field
        else:
            field = custom_field

        if self._payload is not None:
            # Converting value to hex and padding it with 0
            value = ('%x' % value).zfill((self._padding(field) * 2))
            # Transforming value to be inserted in the payload
            insert_value = list(self._reverse(value).decode('hex'))
            # Inserting the value into the payload
            payload = list(self._payload)

            payload[field] = insert_value

            self._payload = "".join(payload)

        else:
            raise ValueError("ERROR INSERTING: Package without payload")

    @property
    def payload(self):
        """ Return the payload of the packet """
        return self._payload

    @property
    def opnum(self):
        """ Returns the opnum of the package """
        return self._extract_int(OPNUM)

    @property
    def packet_type(self):
        """ Return the packet type (ie, request or response) """
        return self._extract_int(PACKET_TYPE)

    @property
    def netbios_length(self):
        """ Return the netbios length """
        return int(binascii.hexlify(self._payload[NETBIOS_LENGTH]), 16)

    @property
    def smb2_data_length(self):
        """ Obtaining length data field of SMB2 protocol layer """
        return self._extract_int(SMB2_DATA_LENGTH)

    @property
    def dce_frag_length(self):
        """ Obtaining frag length field of DCE/RPC protocol layer """
        return self._extract_int(DCE_FRAG_LENGTH)

    @packet_type.setter
    def packet_type(self, value):
        """ Set the packet type """
        self._insert_int(PACKET_TYPE, value)

    @netbios_length.setter
    def netbios_length(self, value):
        """ Setting the netbios length """

        # Converting value to hex and padding it with 0
        value = ('%x' % value).zfill((self._padding(NETBIOS_LENGTH) * 2))
        # Transforming value to be inserted in the payload
        insert_value = list(value.decode('hex'))
        # Inserting the value into the payload
        payload = list(self._payload)

        payload[NETBIOS_LENGTH] = insert_value

        self._payload = "".join(payload)


    @smb2_data_length.setter
    def smb2_data_length(self, value):
        """ Setting length data field of SMB2 protocol layer """
        self._insert_int(SMB2_DATA_LENGTH, value)

    @dce_frag_length.setter
    def dce_frag_length(self, value):
        """ Setting frag length field of DCE/RPC protocol layer """
        self._insert_int(DCE_FRAG_LENGTH, value)

    def insert(self, attacker_payl, data_start, length):
        """ This function inserts the user payload to the winreg packet """
        pkt_list = list(self._payload)
        c = 0

        for i in xrange(data_start, data_start + length, 1):
            pkt_list[i] = '\x00'

        # NEED A FIX: MORE THAN ONE VALUE FOR THE SAME REGISTER KEY!!
        for i in xrange(data_start, data_start + length, 2):
            if c <= len(attacker_payl) - 1:
                pkt_list[i] = attacker_payl[c]
                c = c+1
            # If the user supplied string is shorter than the
            # actual data, fill with empty chars
            else:
                pkt_list[i] = '\x00'

        self._payload = "".join(pkt_list)

    def addZeros(self, num):
        payload = list(self._payload)
        for i in range(num):
            payload.insert(len(payload), '\x00')

        self._payload = "".join(payload)


# ---------------------------------------------------------------------
# GET VERSION PACKAGES CLASS
# ---------------------------------------------------------------------
class GetVersion(WinregPkt):

    def __init__(self, pkt):
        WinregPkt.__init__(self, pkt)

    @property
    def handle(self):
        return self._extract_string(HANDLE)

    def prettyprint(self, value):
        """ pretty printing of the handle """
        if value is not None:
            return "".join("{:02x}".format(ord(c)) for c in value)
        return None

# ---------------------------------------------------------------------
# CREATE KEY PACKAGE CLASS
# ---------------------------------------------------------------------
class CreateKey(WinregPkt):

    def __init__(self, pkt):
        WinregPkt.__init__(self, pkt)


    def getname(self):
        KEY_NAME = slice(188, 188 + self.actual_count * 2)
        return self._extract_string(KEY_NAME)

    @property
    def name_len(self):
        """ Extracts the name length form the open key package """
        return self._extract_int(NAME_LEN)


    def get_access_mask(self):
        """ Return the access mask """
        return self._extract_int(CK_ACCESS_MASK)

    @property
    def name_size(self):
        """ Extracts the name size form the open key package """
        self._extract_int(NAME_SIZE)

    @property
    def max_count(self):
        """ Extracts max count field (maximun number of elements in the array) """
        return self._extract_int(MAX_COUNT)

    @property
    def actual_count(self):
        """ Extracts actual count field (actual number of elements in the array) """
        return self._extract_int(ACTUAL_COUNT)

    @name_len.setter
    def name_len(self, value):
        self._insert_int(NAME_LEN, value)


    def set_access_mask(self, value, custom_field=None):
        if custom_field is None:
            self._insert_int(CK_ACCESS_MASK, value)
        else:
            self._insert_int(None, value, custom_field)

    @name_size.setter
    def name_size(self, value):
        self._insert_int(NAME_SIZE, value)

    @max_count.setter
    def max_count(self, value):
        self._insert_int(MAX_COUNT, value)

    @actual_count.setter
    def actual_count(self, value):
        self._insert_int(ACTUAL_COUNT, value)

    def prettyprint(self, value):
        """ pretty printing of the handle """
        return "".join("{:02x}".format(ord(c)) for c in value)


# ---------------------------------------------------------------------
# SET VALUE PACKAGES CLASS
# ---------------------------------------------------------------------
class SetValue(WinregPkt):

    def __init__(self, pkt):
        WinregPkt.__init__(self, pkt)


    @property
    def rrs_max_count(self):
        """ Obtaining max_count field of RRS protocol layer """
        return self._extract_int(RRS_MAX_COUNT)

    @property
    def rrs_size(self):
        """ Obtaining size field of RRS protocol layer """
        return self._extract_int(RRS_SIZE)

    @rrs_max_count.setter
    def rrs_max_count(self, value):
        """ Setting max_count field of RRS protocol layer """
        self._insert_int(RRS_MAX_COUNT, value)

    @rrs_size.setter
    def rrs_size(self, value):
        """ Setting size field of RRS protocol layer """
        self._insert_int(RRS_SIZE, value)


# ---------------------------------------------------------------------
# OPEN KEY PACKAGES CLASS
# ---------------------------------------------------------------------
class OpenKey(WinregPkt):

    def __init__(self, pkt):
        WinregPkt.__init__(self, pkt)

    @property
    def name_len(self):
        """ Extracts the name length form the open key package """
        return self._extract_int(NAME_LEN)

    @property
    def name_size(self):
        """ Extracts the name size form the open key package """
        return self._extract_int(NAME_SIZE)

    @property
    def max_count(self):
        """ Extracts max count field (maximun number of elements in the array) """
        return self._extract_int(MAX_COUNT)

    @property
    def actual_count(self):
        """ Extracts actual count field (actual number of elements in the array) """
        return self._extract_int(ACTUAL_COUNT)

    @property
    def key_name(self):
        """ Return the name of the register key, not all winreg packets have this value! """
        KEY_NAME = slice(188, 188 + self.actual_count * 2)
        s = self._extract_string(KEY_NAME)
        l = [s[e] for e in xrange(0, len(list(s)), 2)] # Retrieving the zeros
        return "".join(l)

    def get_access_mask(self):
        """ Return the access mask """
        return self._extract_int(ACCESS_MASK)

    @property
    def handle(self):
        """ Return the handle that represents the key """
        return self._extract_string(OPENKEY_HANDLE)

    @handle.setter
    def handle(self, value):
        self.insert(value, 148, 20)

    @name_len.setter
    def name_len(self, value):
        self._insert_int(NAME_LEN, value)

    @name_size.setter
    def name_size(self, value):
        self._insert_int(NAME_SIZE, value)

    @max_count.setter
    def max_count(self, value):
        self._insert_int(MAX_COUNT, value)

    @actual_count.setter
    def actual_count(self, value):
        self._insert_int(ACTUAL_COUNT, value)

    def set_access_mask(self, value, custom_field=None):
        if custom_field is None:
            self._insert_int(ACCESS_MASK, value)
        else:
            self._insert_int(None, value, custom_field)
