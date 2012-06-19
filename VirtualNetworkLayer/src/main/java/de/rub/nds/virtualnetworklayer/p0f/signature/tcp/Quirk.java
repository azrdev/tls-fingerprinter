package de.rub.nds.virtualnetworklayer.p0f.signature.tcp;

/**
 * Quirks with @Deprecated are not used in p0f.fp but in c code
 * (not used any more or not yet)
 */
public enum Quirk {
    DF("df"),
    NZ_ID("id+"),
    ECN("ecn"),
    NZ_ACK("ack+"),
    NZ_URG("uptr+"),
    OPT_ZERO_TS1("ts1-"),
    DEFAULT("NULL"),

    @Deprecated
    OPT_EXWS("exws"),
    @Deprecated
    OPT_EOL_NZ("opt+"),
    @Deprecated
    OPT_NZ_TS2("ts2+"),
    @Deprecated
    PUSH("pushf+"),
    @Deprecated
    URG("urgf+"),
    @Deprecated
    ZERO_ACK("ack-"),
    @Deprecated
    FLOW("flow"),
    @Deprecated
    ZERO_SEQ("seq-"),
    @Deprecated
    NZ_MBZ("0+"),
    @Deprecated
    OPT_BAD("bad"),
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
