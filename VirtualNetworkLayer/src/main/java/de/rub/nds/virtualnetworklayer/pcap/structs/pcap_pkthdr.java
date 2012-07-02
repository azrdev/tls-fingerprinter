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

    @Field(1)
    public int caplen() {
        return this.io.getIntField(this, 1);
    }

    @Field(2)
    public int len() {
        return this.io.getIntField(this, 2);
    }

    public pcap_pkthdr(Pointer pointer) {
        super(pointer);
    }
}
