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
    IEEE802_11,
    Sll,
    PfLog,
    PPP,
    PPPoE,
    Ip4,
    Ip6,
    Udp,
    Tcp,
    Tls,
    Http,
    Dhcp;

    public int getId() {
        return this.ordinal();
    }
}
