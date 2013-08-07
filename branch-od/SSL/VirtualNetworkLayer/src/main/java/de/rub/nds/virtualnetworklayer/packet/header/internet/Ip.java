package de.rub.nds.virtualnetworklayer.packet.header.internet;

import de.rub.nds.virtualnetworklayer.packet.header.Header;

/**
 * This is the common base class for both Ip protocols.
 *
 * @author Marco Faltermeier <faltermeier@me.com>
 */
public abstract class Ip extends Header {

    public static enum Protocol {
        Icmp(1),
        Igmp(2),
        Tcp(6),
        Udp(17),
        Gre(47);

        private int id;

        private Protocol(int id) {
            this.id = id;
        }

        public int getId() {
            return this.id;
        }

        public static Protocol valueOf(int type) {
            for (Protocol protocol : values()) {
                if (protocol.id == type) {
                    return protocol;
                }
            }

            return null;
        }

    }

    public int getVersion() {
        return getFirstNibble(0);
    }

    public abstract byte[] getSourceAddress();

    public abstract byte[] getDestinationAddress();

    public abstract Protocol getNextHeader();

    public abstract int getHopLimit();

}
