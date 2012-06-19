package de.rub.nds.virtualnetworklayer.pcap;

import de.rub.nds.virtualnetworklayer.pcap.structs.bpf_program;
import de.rub.nds.virtualnetworklayer.pcap.structs.pcap_if;
import de.rub.nds.virtualnetworklayer.pcap.structs.pcap_t;
import de.rub.nds.virtualnetworklayer.util.Util;
import org.bridj.Pointer;

import java.io.File;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;

public class Pcap {
    private static Pointer<Byte> errbuf = Pointer.allocateBytes(256);
    private Pointer<Integer> pcap_datalink = Pointer.allocateInt();
    private pcap_t pcap_t;
    private Status status = Status.Success;
    private Loop loop;
    private File file;
    private Device device;

    private static int snaplen = 65535;
    private static int mode = 0;
    private static int timeout = 250;
    private static List<Pcap> instances = new LinkedList<Pcap>();

    private class Loop implements Runnable {
        private PcapHandler handler;

        private Loop(PcapHandler handler) {
            this.handler = handler;
        }

        @Override
        public void run() {
            setStatus(PcapLibrary.pcap_loop(pcap_t, 0, Pointer.pointerTo(handler), pcap_datalink));
        }

        public PcapHandler getHandler() {
            return handler;
        }
    }

    public enum Status {
        Success(0),
        Failure(-1),
        Terminated(-2);

        private int code;

        private Status(int code) {
            this.code = code;
        }

        public static Status valueOf(int code) {
            for (Status status : values()) {
                if (status.code == code) {
                    return status;
                }
            }

            return null;
        }
    }

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
        pcap_datalink.set(PcapLibrary.pcap_datalink(pcap_t));

        instances.add(this);
    }

    private Pcap(pcap_t pcap_t, Device device) {
        this(pcap_t);

        this.device = device;
    }

    private Pcap(pcap_t pcap_t, File file) {
        this(pcap_t);

        this.file = file;
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

        return new Pcap(pcap_t, device);
    }

    public static Pcap openLive() {
        return openLive(getLiveDevice());
    }

    public Status filter(String filter) {
        Pointer<bpf_program> bpf_program = Pointer.allocate(bpf_program.class);

        if (Status.valueOf(PcapLibrary.pcap_compile(pcap_t, bpf_program, Pointer.pointerToCString(filter), 0, 0)) == Status.Success) {
            return setStatus(PcapLibrary.pcap_setfilter(pcap_t, bpf_program));
        } else {
            throw new IllegalArgumentException("error while parsing " + filter);
        }
    }

    public static Pcap openOffline(File file) {
        pcap_t pcap_t = PcapLibrary.pcap_open_offline(Pointer.pointerToCString(file.getAbsolutePath()), errbuf);

        if (pcap_t == null) {
            throw new IllegalArgumentException();
        }

        return new Pcap(pcap_t, file);
    }

    public void breakloop() {
        PcapLibrary.pcap_breakloop(pcap_t);

        while (status != Status.Terminated) {
            try {
                Thread.sleep(50);
            } catch (InterruptedException e) {
                break;
            }
        }
    }

    public Status loop(PcapHandler handler) {
        return loop(handler, false);
    }

    public Status loop(final PcapHandler handler, boolean asynchronous) {
        loop = new Loop(handler);

        if (!asynchronous) {
            loop.run();
        } else {
            new Thread(loop).start();
        }

        return status;
    }

    public static Device getLiveDevice() {
        try {
            byte[] address = Util.toAddress(InetAddress.getLocalHost());

            for (Device device : Pcap.getDevices()) {
                if (device.isBound(address)) {
                    return device;
                }
            }
        } catch (UnknownHostException e) {
            return null;
        }

        return null;
    }

    public static Device getDefaultDevice() {
        String name = PcapLibrary.pcap_lookupdev(errbuf).getCString();

        for (Device device : getDevices()) {
            if (device.getName().equals(name)) {
                return device;
            }
        }

        return null;
    }

    public static List<Device> getDevices() {
        Pointer<Pointer<pcap_if>> pcap_if = Pointer.allocatePointer(pcap_if.class);
        List<Device> devices = new ArrayList<Device>();

        if (Status.valueOf(PcapLibrary.pcap_findalldevs(pcap_if, errbuf)) == Status.Success) {
            Pointer<pcap_if> device = pcap_if.get();

            while (device != Pointer.NULL) {
                Pointer<Integer> netp = Pointer.allocateInt();
                Pointer<Integer> maskp = Pointer.allocateInt();

                int net = 0;
                int mask = 0;

                if (Status.valueOf(PcapLibrary.pcap_lookupnet(device.get().name, netp, maskp, errbuf)) == Status.Success) {
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

    private Status setStatus(int code) {
        this.status = Status.valueOf(code);
        return this.status;
    }

    public Status getStatus() {
        return status;
    }

    public PcapHandler getHandler() {
        return loop.getHandler();
    }

    public File getFile() {
        return file;
    }

    public static Iterable<Pcap> getInstances() {
        return instances;
    }

    public Device getDevice() {
        return device;
    }

    @Override
    protected void finalize() throws Throwable {
        PcapLibrary.pcap_close(pcap_t);
        instances.remove(this);
    }
}
