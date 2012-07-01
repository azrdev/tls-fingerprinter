package de.rub.nds.virtualnetworklayer.pcap.structs;

import org.bridj.Pointer;
import org.bridj.StructObject;
import org.bridj.ann.Field;

public class pcap_addr extends StructObject {
    public pcap_addr() {
        super();
    }

    @Field(0)
    public Pointer<pcap_addr> next() {
        return this.io.getPointerField(this, 0);
    }

    @Field(1)
    public Pointer<sockaddr> addr() {
        return this.io.getPointerField(this, 1);
    }

    @Field(2)
    public Pointer<sockaddr> netmask() {
        return this.io.getPointerField(this, 2);
    }

    @Field(3)
    public Pointer<sockaddr> broadaddr() {
        return this.io.getPointerField(this, 3);
    }

    @Field(4)
    public Pointer<sockaddr> dstaddr() {
        return this.io.getPointerField(this, 4);
    }

    public pcap_addr(Pointer pointer) {
        super(pointer);
    }
}
