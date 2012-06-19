package de.rub.nds.virtualnetworklayer.pcap.structs;

import org.bridj.Pointer;
import org.bridj.StructObject;
import org.bridj.ann.Field;

public class bpf_program extends StructObject {

    @Field(0)
    public int bf_len;

    @Field(1)
    public Pointer<?> bf_insns;


    public bpf_program() {
    }

    public bpf_program(Pointer<? extends StructObject> ptr) {
        super(ptr);
    }
}