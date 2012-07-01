package de.rub.nds.virtualnetworklayer.pcap.structs;

import org.bridj.Pointer;
import org.bridj.StructObject;
import org.bridj.ann.Field;

public class bpf_program extends StructObject {
    public bpf_program() {
        super();
    }

    @Field(0)
    public int bf_len() {
        return this.io.getIntField(this, 0);
    }

    public bpf_program(Pointer pointer) {
        super(pointer);
    }
}