package de.rub.nds.virtualnetworklayer.pcap;

import de.rub.nds.virtualnetworklayer.pcap.structs.bpf_program;
import de.rub.nds.virtualnetworklayer.pcap.structs.pcap_if;
import de.rub.nds.virtualnetworklayer.pcap.structs.pcap_t;
import org.bridj.BridJ;
import org.bridj.CRuntime;
import org.bridj.Platform;
import org.bridj.Pointer;
import org.bridj.ann.Library;
import org.bridj.ann.Runtime;

@Library("pcap")
@Runtime(CRuntime.class)
public class PcapLibrary {
    static {
        if (Platform.isWindows()) {
            BridJ.addNativeLibraryAlias("pcap", "wpcap");
        }

        BridJ.register();
    }

    public static native Pointer<Byte> pcap_lib_version();

    public static native pcap_t pcap_open_live(Pointer<?> device, int snaplen, int promisc, int to_ms, Pointer<Byte> errbuf);

    public static native pcap_t pcap_open_offline(Pointer<Byte> fname, Pointer<Byte> errbuf);

    public static native int pcap_loop(pcap_t p, final int cnt, Pointer<?> callback, Pointer<?> user);

    public static native void pcap_breakloop(pcap_t p);

    public static native int pcap_findalldevs(Pointer<Pointer<pcap_if>> alldevsp, Pointer<Byte> errbuf);

    public static native int pcap_lookupnet(Pointer<?> device, Pointer<Integer> netp, Pointer<Integer> maskp, Pointer<Byte> errbuf);

    public static native void pcap_freealldevs(Pointer<pcap_if> alldevsp);

    public static native int pcap_datalink(pcap_t p);

    public static native int pcap_compile(pcap_t p, Pointer<bpf_program> fp, Pointer<Byte> str, int optimize, int netmask);

    public static native int pcap_setfilter(pcap_t p, Pointer<bpf_program> fp);

    public static native void pcap_close(pcap_t p);

}
