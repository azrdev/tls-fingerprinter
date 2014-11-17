package de.rub.nds.virtualnetworklayer.pcap.structs;

import org.bridj.Pointer;
import org.bridj.StructObject;
import org.bridj.TimeT;
import org.bridj.ann.Field;

/**
 * @author Marco Faltermeier <faltermeier@me.com>
 */
public class pcap_pkthdr extends StructObject {
    public pcap_pkthdr() {
        super();
    }

    @Field(0)
    public TimeT.timeval ts() {
        return this.io.getNativeObjectField(this, 0);
    }

    @Field(0)
    public pcap_pkthdr ts(TimeT.timeval ts) {
        this.io.setNativeObjectField(this, 0, ts);
        return this;
    }

    /**
     * @return Timestamp in nanoseconds
     * @see #ts()
     */
    public long getTimeStamp() {
        return (ts().seconds() * 1000 * 1000 + ts().milliseconds()) * 1000;
    }

    @Field(1)
    public int caplen() {
        return this.io.getIntField(this, 1);
    }

    @Field(1)
    public pcap_pkthdr caplen(int caplen) {
        this.io.setIntField(this, 1, caplen);
        return this;
    }

    @Field(2)
    public int len() {
        return this.io.getIntField(this, 2);
    }

    @Field(2)
    public pcap_pkthdr len(int len) {
        this.io.setIntField(this, 2, len);
        return this;
    }

    public pcap_pkthdr(Pointer pointer) {
        super(pointer);
    }
}
