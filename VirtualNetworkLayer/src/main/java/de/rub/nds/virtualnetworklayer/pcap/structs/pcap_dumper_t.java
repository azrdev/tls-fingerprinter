package de.rub.nds.virtualnetworklayer.pcap.structs;

import org.bridj.Pointer;
import org.bridj.TypedPointer;

/**
 * @author jBiegert azrdev@qrdn.de
 */
public class pcap_dumper_t extends TypedPointer {
    public pcap_dumper_t(long address) {
        super(address);
    }

    public pcap_dumper_t(Pointer pointer) {
        super(pointer);
    }
}
