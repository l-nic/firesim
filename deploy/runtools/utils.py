""" Miscellaneous utils used by other buildtools pieces. """

import socket
import struct

class MacAddress():
    """ This class allows globally allocating/assigning MAC addresses.
    It also wraps up the code necessary to get a string version of a mac
    address. The MAC prefix we use here is 00:26:E1, which is assigned to the
    OpenFlow group.

    >>> MacAddress.reset_allocator()
    >>> mac = MacAddress()
    >>> str(mac)
    '00:26:E1:00:00:02'
    >>> mac.as_int_no_prefix()
    2
    >>> mac = MacAddress()
    >>> mac.as_int_no_prefix()
    3
    """
    next_mac_alloc = 2
    openflow_mac_prefix = 0x0026e1000000

    def __init__(self):
        """ Allocate a new mac address, store it, then increment nextmacalloc."""
        assert MacAddress.next_mac_alloc < 2**24, "Too many MAC addresses allocated"
        self.mac_without_prefix_as_int = MacAddress.next_mac_alloc
        self.mac_as_int = MacAddress.openflow_mac_prefix + MacAddress.next_mac_alloc

        # increment for next call
        MacAddress.next_mac_alloc += 1

    def as_int_no_prefix(self):
        """ Return the MAC address as an int. WITHOUT THE PREFIX!
        Used by the MAC tables in switch models."""
        return self.mac_without_prefix_as_int

    def __str__(self):
        """ Return the MAC address in the "regular format": colon separated,
        show all leading zeroes."""
        # format as 12 char hex with leading zeroes
        str_ver = format(self.mac_as_int, '012X')
        # split into two hex char chunks
        import re
        split_str_ver = re.findall('..?', str_ver)
        # insert colons
        return ":".join(split_str_ver)

    @classmethod
    def reset_allocator(cls):
        """ Reset allocator back to default value. """
        cls.next_mac_alloc = 2

    @classmethod
    def next_mac_to_allocate(cls):
        """ Return the next mac that will be allocated. This basically tells you
        how many entries you need in your switching tables. """
        return cls.next_mac_alloc

class IpAddress():
    """
    IP Addresses will start at 10.0.0.1
    """
    next_ip_alloc = 2
    orig_ip_alloc = 2
    lnic_ip_prefix = 0x0A000000

    def __init__(self):
        """ Allocate a new ip address, store it, then increment nextipalloc."""
        assert IpAddress.next_ip_alloc < 2**24, "Too many IP addresses allocated"
        self.ip_without_prefix_as_int = IpAddress.next_ip_alloc
        self.ip_as_int = IpAddress.lnic_ip_prefix + IpAddress.next_ip_alloc

        # increment for next call
        IpAddress.next_ip_alloc += 1

    def as_int_no_prefix(self):
        """ Return the IP address as an int. WITHOUT THE PREFIX!
        Used by the IP tables in switch models."""
        return self.ip_without_prefix_as_int

    def __str__(self):
        """ Return the IP address in the "regular format": dot separated.
        """
        # format as 12 char hex with leading zeroes
        return socket.inet_ntoa(struct.pack('!L', self.ip_as_int))

    @classmethod
    def reset_allocator(cls):
        """ Reset allocator back to default value. """
        cls.next_ip_alloc = 2

    @classmethod
    def next_ip_to_allocate(cls):
        """ Return the next mac that will be allocated. This basically tells you
        how many entries you need in your switching tables. """
        return cls.next_ip_alloc