package de.rub.nds.virtualnetworklayer.p0f.signature.tcp;

/**
 * Quirks with @Deprecated are not used in p0f.fp but in c code
 * (not used any more or not yet).
 *
 * @author Marco Faltermeier <faltermeier@me.com>
 */
public enum Quirk {
    /**
     * "don't fragment" set (probably PMTUD); ignored for IPv6
     */
    DF("df"),

    /**
     * DF set but IPID non-zero; ignored for IPv6
     */
    NZ_ID("id+"),

    /**
     * explicit congestion notification support
     */
    ECN("ecn"),

    /**
     * ACK number is non-zero, but ACK flag not set
     */
    NZ_ACK("ack+"),

    /**
     * URG pointer is non-zero, but URG flag not set
     */
    NZ_URG("uptr+"),

    /**
     * own timestamp specified as zero
     */
    OPT_ZERO_TS1("ts1-"),

    /**
     * excessive window scaling factor (> 14)
     */
    @Deprecated
    OPT_EXWS("exws"),

    /**
     * trailing non-zero data in options segment
     */
    @Deprecated
    OPT_EOL_NZ("opt+"),

    /**
     * non-zero peer timestamp on initial SYN
     */
    @Deprecated
    OPT_NZ_TS2("ts2+"),

    /**
     * PUSH flag used
     */
    @Deprecated
    PUSH("pushf+"),

    /**
     * URG flag used
     */
    @Deprecated
    URG("urgf+"),

    /**
     * ACK number is zero, but ACK flag set
     */
    @Deprecated
    ZERO_ACK("ack-"),

    /**
     * non-zero IPv6 flow ID; ignored for IPv4
     */
    @Deprecated
    FLOW("flow"),

    /**
     * sequence number is zero
     */
    @Deprecated
    ZERO_SEQ("seq-"),

    /**
     * "must be zero" field not zero; ignored for IPv6
     */
    @Deprecated
    NZ_MBZ("0+"),

    /**
     * malformed TCP options
     */
    @Deprecated
    OPT_BAD("bad"),

    /**
     * DF not set but IPID is zero; ignored for IPv6
     */
    @Deprecated
    ZERO_ID("id-");

    private String value;

    private Quirk(String value) {
        this.value = value;
    }

    @Override
    public String toString() {
        return value;
    }
}
