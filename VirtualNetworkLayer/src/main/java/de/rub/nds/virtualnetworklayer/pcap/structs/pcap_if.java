package de.rub.nds.virtualnetworklayer.pcap.structs;

import org.bridj.Pointer;
import org.bridj.StructObject;
import org.bridj.ann.Field;

/**
 * @author Marco Faltermeier <faltermeier@me.com>
 */
public class pcap_if extends StructObject {
    public pcap_if() {
        super();
    }

    @Field(0)
    public Pointer<pcap_if> next() {
        return this.io.getPointerField(this, 0);
    }

    @Field(1)
    public Pointer<Byte> name() {
        return this.io.getPointerField(this, 1);
    }

    @Field(2)
    public Pointer<Byte> description() {
        return this.io.getPointerField(this, 2);
    }

    @Field(3)
    public Pointer<pcap_addr> addresses() {
        return this.io.getPointerField(this, 3);
    }

    public pcap_if(Pointer pointer) {
        super(pointer);
    }
}
