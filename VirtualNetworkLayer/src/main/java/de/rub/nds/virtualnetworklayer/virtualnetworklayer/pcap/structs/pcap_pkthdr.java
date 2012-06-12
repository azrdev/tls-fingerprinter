package de.rub.nds.virtualnetworklayer.pcap.structs;

import org.bridj.Pointer;
import org.bridj.StructObject;
import org.bridj.TimeT;
import org.bridj.ann.Field;

public class pcap_pkthdr extends StructObject {

    @Field(0)
    public TimeT.timeval ts;

    @Field(1)
    public int caplen;

    @Field(2)
    public int len;

    public pcap_pkthdr() {
        super();
    }

    public pcap_pkthdr(Pointer<? extends StructObject> ptr) {
        super(ptr);
    }
}
