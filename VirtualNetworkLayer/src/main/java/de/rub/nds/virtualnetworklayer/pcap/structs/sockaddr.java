package de.rub.nds.virtualnetworklayer.pcap.structs;

import org.bridj.Pointer;
import org.bridj.StructObject;
import org.bridj.ann.Array;
import org.bridj.ann.Field;

public class sockaddr extends StructObject {

    @Field(0)
    public int sa_family;

    @Field(1)
    @Array(16)
    public Pointer<Byte> sa_data;

    public sockaddr() {
        super();
    }

    public sockaddr(Pointer<? extends StructObject> ptr) {
        super(ptr);
    }
}