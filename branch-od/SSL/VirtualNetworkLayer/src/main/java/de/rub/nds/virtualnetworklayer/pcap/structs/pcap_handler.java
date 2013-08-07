package de.rub.nds.virtualnetworklayer.pcap.structs;


import org.bridj.Callback;
import org.bridj.Pointer;

/**
 * @author Marco Faltermeier <faltermeier@me.com>
 */
public abstract class pcap_handler extends Callback {

    protected abstract void callback(final Pointer user, final Pointer<pcap_pkthdr> pkt_header, final Pointer<Byte> pkt_data);

}