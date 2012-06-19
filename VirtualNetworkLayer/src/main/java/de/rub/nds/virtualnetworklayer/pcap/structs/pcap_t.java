package de.rub.nds.virtualnetworklayer.pcap.structs;

import org.bridj.Pointer;
import org.bridj.TypedPointer;

public class pcap_t extends TypedPointer {

    public pcap_t(long address) {
        super(address);
    }

    public pcap_t(Pointer<?> ptr) {
        super(ptr);
    }
}