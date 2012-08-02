package de.rub.nds.virtualnetworklayer.packet.header.link.family;

/**
 * A {@link de.rub.nds.virtualnetworklayer.packet.header.Header} class implements the Family interface to indicate that it
 * contains a {@link AddressFamily} field.
 *
 * @author Marco Faltermeier <faltermeier@me.com>
 */
public interface Family {
    public static enum Category {
        Ip4,
        Ip6
    }

    public static enum AddressFamily {
        INET(2),
        APPLETALK(16),
        INET6OpenBSD(24),
        INET6FreeBSD(28),
        INET6OSX(30);

        private int id;

        private AddressFamily(int id) {
            this.id = id;
        }

        public static AddressFamily valueOf(int type) {
            for (AddressFamily t : values()) {
                if (t.id == type) {
                    return t;
                }
            }

            return null;
        }

        public boolean isCategory(Category category) {
            switch (category) {
                case Ip4:
                    return isINet4();
                case Ip6:
                    return isINet6();
            }

            return false;
        }

        public boolean isINet6() {
            return this == INET6OSX || this == INET6FreeBSD || this == INET6OpenBSD;
        }


        public boolean isINet4() {
            return this == INET || this == APPLETALK;
        }

    }

    public AddressFamily getAddressFamily();

}
