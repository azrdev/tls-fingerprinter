package de.rub.nds.virtualnetworklayer.pcap.structs;


import org.bridj.Callback;
import org.bridj.Pointer;

public abstract class pcap_handler extends Callback {

    public abstract void callback(final Pointer<?> user, final Pointer<pcap_pkthdr> pkt_header, final Pointer<?> pkt_data);
}