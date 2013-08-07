package de.rub.nds.virtualnetworklayer.packet;

/**
 * Registry of all headers.
 * {@link Enum#ordinal()} is used as id.
 *
 * @author Marco Faltermeier <faltermeier@me.com>
 */
public enum Headers {
    Ethernet,
    Null,
    Radiotap,
    Prism,
    IEEE802_11,
    IEEE802_1Q,
    IEEE802_2,
    IEEE802_3,
    Snap,
    Sll,
    PfLog,
    Arp,
    PPP,
    PPPoE,
    Gre,
    Ip4,
    Ip6,
    Udp,
    Tcp,
    Tls,
    Http,
    Sip,
    Dhcp,
    Smtp;

    public int getId() {
        return this.ordinal();
    }
}
