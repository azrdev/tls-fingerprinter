package de.rub.nds.virtualnetworklayer.pcap.structs;

import org.bridj.Pointer;
import org.bridj.StructObject;
import org.bridj.ann.Array;
import org.bridj.ann.Field;

/**
 * @author Marco Faltermeier <faltermeier@me.com>
 */
public class sockaddr extends StructObject {
    public sockaddr() {
        super();
    }

    @Field(0)
    public int sa_family() {
        return this.io.getByteField(this, 0);
    }

    @Field(1)
    @Array(16)
    public Pointer<Byte> sa_data() {
        return this.io.getPointerField(this, 1);
    }

    public sockaddr(Pointer pointer) {
        super(pointer);
    }
}