package de.rub.nds.virtualnetworklayer.pcap.structs;

import org.bridj.Pointer;
import org.bridj.StructObject;
import org.bridj.ann.Field;

public class pcap_addr extends StructObject {

    @Field(0)
    public Pointer<pcap_addr> next;

    @Field(1)
    public Pointer<sockaddr> addr;

    @Field(2)
    public Pointer<sockaddr> netmask;

    @Field(3)
    public Pointer<sockaddr> broadaddr;

    @Field(4)
    public Pointer<sockaddr> dstaddr;

    public pcap_addr() {
        super();
    }

    public pcap_addr(Pointer<? extends StructObject> ptr) {
        super(ptr);
    }
}
