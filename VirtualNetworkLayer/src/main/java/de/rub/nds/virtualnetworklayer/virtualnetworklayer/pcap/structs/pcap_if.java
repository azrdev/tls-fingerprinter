package de.rub.nds.virtualnetworklayer.pcap.structs;

import org.bridj.Pointer;
import org.bridj.StructObject;
import org.bridj.ann.Field;

public class pcap_if extends StructObject {

    @Field(0)
    public Pointer<pcap_if> next;

    @Field(1)
    public Pointer<?> name;

    @Field(2)
    public Pointer<?> description;

    @Field(3)
    public Pointer<pcap_addr> addresses;

    @Field(4)
    public int flags;

    public pcap_if() {
        super();
    }

    public pcap_if(Pointer<? extends StructObject> ptr) {
        super(ptr);
    }
}
