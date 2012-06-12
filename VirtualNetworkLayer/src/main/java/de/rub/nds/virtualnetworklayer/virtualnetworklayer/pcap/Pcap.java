package de.rub.nds.virtualnetworklayer.pcap;

import de.rub.nds.virtualnetworklayer.pcap.structs.bpf_program;
import de.rub.nds.virtualnetworklayer.pcap.structs.pcap_if;
import de.rub.nds.virtualnetworklayer.pcap.structs.pcap_t;
import org.bridj.Pointer;

import java.io.File;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

public class Pcap {
    private static Pointer<Byte> errbuf = Pointer.allocateBytes(256);
    private Pointer<Integer> pcap_datalink = Pointer.allocateInt();
    private pcap_t pcap_t;
    private static int snaplen = 65535;
    private static int mode = 0;
    private static int timeout = 250;

    public enum OpenFlag {
        Promiscuous(1),
        DataxUdp(2),
        NoCaptureRPcap(4),
        NoCaptureLocal(8),
        MaxResponsiveness(16);

        private int position;

        private OpenFlag(int position) {
            this.position = position;
        }
    }

    /**
     * @see http://www.tcpdump.org/linktypes.html
     */
    public enum DataLinkType {
        Null(0),
        Ethernet(1),
        IEEE802_5(6);

        private int id;

        private DataLinkType(int id) {
            this.id = id;
        }

        public static DataLinkType valueOf(int id) {
            for (DataLinkType dlt : values()) {
                if (dlt.id == id) {
                    return dlt;
                }
            }

            return null;
        }
    }

    private Pcap(pcap_t pcap_t) {
        this.pcap_t = pcap_t;
    }

    public static String getVersion() {
        return PcapLibrary.pcap_lib_version().getCString();
    }

    public static Pcap openLive(Device device, Set<OpenFlag> flags) {
        for (OpenFlag flag : flags) {
            mode += 1 << (flag.position - 1);
        }

        return openLive(device);
    }

    public static Pcap openLive(Device device) {
        pcap_t pcap_t = PcapLibrary.pcap_open_live(Pointer.pointerToCString(device.getName()), snaplen, mode, timeout, errbuf);

        if (pcap_t == null) {
            throw new IllegalArgumentException();
        }

        return new Pcap(pcap_t);
    }

    public void filter(String filter) {
        Pointer<bpf_program> bpf_program = Pointer.allocate(bpf_program.class);

        if (PcapLibrary.pcap_compile(pcap_t, bpf_program, Pointer.pointerToCString(filter), 0, 0) != -1) {
            PcapLibrary.pcap_setfilter(pcap_t, bpf_program);
        } else {
            throw new IllegalArgumentException("error while parsing " + filter);
        }
    }

    public static Pcap openOffline(File file) {
        pcap_t pcap_t = PcapLibrary.pcap_open_offline(Pointer.pointerToCString(file.getAbsolutePath()), errbuf);

        if (pcap_t == null) {
            throw new IllegalArgumentException();
        }

        return new Pcap(pcap_t);
    }

    public void breakloop() {
        PcapLibrary.pcap_breakloop(pcap_t);
    }

    public int loop(PcapHandler handler) {
        pcap_datalink.set(PcapLibrary.pcap_datalink(pcap_t));
        return PcapLibrary.pcap_loop(pcap_t, 0, Pointer.pointerTo(handler), pcap_datalink);
    }

    public static List<Device> getDevices() {
        Pointer<Pointer<pcap_if>> pcap_if = Pointer.allocatePointer(pcap_if.class);
        List<Device> devices = new ArrayList<Device>();

        if (PcapLibrary.pcap_findalldevs(pcap_if, errbuf) != -1) {
            Pointer<pcap_if> device = pcap_if.get();

            while (device != Pointer.NULL) {
                Pointer<Integer> netp = Pointer.allocateInt();
                Pointer<Integer> maskp = Pointer.allocateInt();

                int net = 0;
                int mask = 0;

                if (PcapLibrary.pcap_lookupnet(device.get().name, netp, maskp, errbuf) != -1) {
                    net = netp.getInt();
                    mask = maskp.getInt();
                }

                netp.release();
                maskp.release();

                devices.add(new Device(device.get(), net, mask));

                device = device.get().next;
            }

        }

        PcapLibrary.pcap_freealldevs(pcap_if.get());

        return devices;
    }

    @Override
    protected void finalize() throws Throwable {
        PcapLibrary.pcap_close(pcap_t);
    }
}
