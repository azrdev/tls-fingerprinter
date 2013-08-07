package de.rub.nds.virtualnetworklayer.packet.header.link.ppp;

/**
 * A {@link de.rub.nds.virtualnetworklayer.packet.header.Header} class implements the PPP interface to indicate that it
 * contains a {@link PPP.Protocol} field.
 *
 * @author Marco Faltermeier <faltermeier@me.com>
 */
public interface PPP {

    /**
     * @see <a href="http://www.iana.org/assignments/ppp-numbers">iana.org/assignments/ppp-numbers</a>
     */
    public static enum Protocol {
        IP(0x0021),
        IPv6(0x0057),
        CCP(0x80fd),
        IPCP(0x8021),
        LCP(0xc021),
        PAP(0xc023),
        CHAP(0xc223);

        private int id;

        private Protocol(int id) {
            this.id = id;
        }

        public int getId() {
            return this.id;
        }

        public static Protocol valueOf(int value) {
            for (Protocol p : values()) {
                if (p.id == value) {
                    return p;
                }
            }

            return null;
        }

    }

    public Protocol getProtocol();
}
