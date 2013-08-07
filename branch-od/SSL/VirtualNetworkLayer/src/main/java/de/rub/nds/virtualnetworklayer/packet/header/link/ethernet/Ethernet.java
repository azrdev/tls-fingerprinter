package de.rub.nds.virtualnetworklayer.packet.header.link.ethernet;

/**
 * A {@link de.rub.nds.virtualnetworklayer.packet.header.Header} class implements the Ethernet interface to indicate that it
 * contains a {@link Ethernet.Type} field.
 *
 * @author Marco Faltermeier <faltermeier@me.com>
 */
public interface Ethernet {

    /**
     * @see <a href="http://en.wikipedia.org/wiki/Ethertype">en.wikipedia.org/wiki/Ethertype</a>
     */
    public static enum Type {
        Ip4(0x800),
        Ip6(0x86DD),
        Arp(0x0806),
        PPPoE_Discovery(0x8863),
        PPPoE_Session(0x8864),
        IEEE802_1Q(0x8100);

        private int id;

        private Type(int id) {
            this.id = id;
        }

        public int getId() {
            return this.id;
        }

        public static Type valueOf(int type) {
            for (Type t : values()) {
                if (t.id == type) {
                    return t;
                }
            }

            return null;
        }

    }

    public Type getType();

}