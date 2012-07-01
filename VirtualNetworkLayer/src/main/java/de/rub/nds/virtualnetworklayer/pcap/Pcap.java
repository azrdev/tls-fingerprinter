package de.rub.nds.virtualnetworklayer.pcap;

import de.rub.nds.virtualnetworklayer.connection.pcap.ConnectionHandler;
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

/**
 * Pcap wrapper
 * </p>
 * To create a new instance, use one of the following factory methods:
 * <ul>
 * <li>live capturing: {@link #openLive()}, {@link #openLive(Device)}, {@link #openLive(Device, java.util.Set)}</li>
 * <li>opening an pcap dump: {@link #openOffline(java.io.File)}</li>
 * <li>radio frequence monitoring: {@link #openRadioFrequencyMonitor()}, {@link #openRadioFrequencyMonitor(Device)}</li>
 * </ul>
 * The wrapper does reference counting, so a instance might be also looked up by address {@link #getInstance(byte[])}.
 * If a instance was not closed, when the Java virtual machine is shutting down,
 * a {@link Pcap.GarbageCollector} kicks in.
 * </p>
 * Then register a callback {@link PcapHandler} with {@link #loopAsynchronous(PcapHandler)} or {@link #loop(PcapHandler)}.
 *
 * @author Marco Faltermeier <faltermeier@me.com>
 * @see Runtime#addShutdownHook(Thread)
 */
public class Pcap {
    private static Pointer<Byte> errbuf = Pointer.allocateBytes(256);
    private Pointer<Integer> pcap_datalink = Pointer.allocateInt();
    private pcap_t pcap_t;
    private Status status = Status.Success;
    private Loop loop;
    private File file;
    private Device device;
    private int referenceCount = 0;

    private static int snaplen = 65535;
    private static int mode = 0;
    private static int timeout = 250;
    private static List<Pcap> instances = new LinkedList<Pcap>();

    private class Loop implements Runnable {
        private PcapHandler handler;
        private boolean asynchronous;

        private Loop(PcapHandler handler, boolean asynchronous) {
            this.handler = handler;
            this.asynchronous = asynchronous;
        }

        @Override
        public void run() {
            setStatus(PcapLibrary.pcap_loop(pcap_t, 0, Pointer.pointerTo(handler), pcap_datalink));
        }

        public PcapHandler getHandler() {
            return handler;
        }
    }

    private static class GarbageCollector implements Runnable {
        @Override
        public void run() {
            for (Pcap instance : instances) {
                instance.referenceCount = 0;
                instance.close();
            }
        }
    }

    static {
        Runtime.getRuntime().addShutdownHook(new Thread(new GarbageCollector()));
    }

    public enum Status {
        Success(0),
        Failure(-1),
        Terminated(-2),
        NotActivated(-3),
        AlreadyActivated(-4),
        NoSuchDevice(-5),
        RFMonNotSupported(-6);

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
     * @see <a href="http://www.tcpdump.org/linktypes.html">tcpdump.org/linktypes.html</a>
     */
    public enum DataLinkType {
        Null(0),
        Ethernet(1),
        PPP(9),
        PPPoE(51),
        Raw(101),
        IEEE802_11(105),
        Sll(113),
        PfLog(117),
        Radiotap(127);

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

    /**
     * Creates a pcap instance in radio frequency mode with {@link #getLiveDevice()} and
     * default {@link OpenFlag} (all false).
     *
     * @return instance of {@link Pcap}
     * @throws IllegalArgumentException if device was not found or device does not support rf mode.
     */
    public static Pcap openRadioFrequencyMonitor() {
        Device liveDevice = getLiveDevice();

        if (liveDevice == null) {
            throw new IllegalArgumentException("no live device found");
        }

        return openRadioFrequencyMonitor(liveDevice);
    }

    /**
     * Creates a pcap instance in radio frequency mode with specified {@link Device} and
     * default {@link OpenFlag} (all false).
     *
     * @param device
     * @return instance of {@link Pcap}
     * @throws IllegalArgumentException if device was not found or device does not support rf mode.
     */
    public static Pcap openRadioFrequencyMonitor(Device device) {
        pcap_t pcap_t = PcapLibrary.pcap_create(Pointer.pointerToCString(device.getName()), errbuf);

        if (pcap_t == null) {
            throw new IllegalArgumentException();
        }

        if (Status.valueOf(PcapLibrary.pcap_set_rfmon(pcap_t, 1)) != Status.Success) {
            throw new IllegalArgumentException();
        }
        ;

        PcapLibrary.pcap_set_snaplen(pcap_t, snaplen);
        PcapLibrary.pcap_set_promisc(pcap_t, mode);
        PcapLibrary.pcap_set_timeout(pcap_t, timeout);

        PcapLibrary.pcap_activate(pcap_t);

        return new Pcap(pcap_t, device);
    }

    /**
     * Creates a pcap instance in live mode with specified {@link Device}
     * and {@link OpenFlag}.
     *
     * @param device
     * @param flags
     * @return instance of {@link Pcap}
     * @throws IllegalArgumentException if device was not found
     */
    public static Pcap openLive(Device device, Set<OpenFlag> flags) {
        for (OpenFlag flag : flags) {
            mode += 1 << (flag.position - 1);
        }

        return openLive(device);
    }

    /**
     * Creates a pcap instance in live mode with specified {@link Device} and
     * default {@link OpenFlag} (all false).
     *
     * @param device
     * @return instance of {@link Pcap}
     * @throws IllegalArgumentException if device was not found
     */
    public static Pcap openLive(Device device) {
        pcap_t pcap_t = PcapLibrary.pcap_open_live(Pointer.pointerToCString(device.getName()), snaplen, mode, timeout, errbuf);

        if (pcap_t == null) {
            throw new IllegalArgumentException();
        }

        return new Pcap(pcap_t, device);
    }

    /**
     * Creates a pcap instance in live mode with {@link #getLiveDevice()} device and
     * default {@link OpenFlag} (all false).
     *
     * @return instance of {@link Pcap}
     * @throws IllegalArgumentException if device was not found
     */
    public static Pcap openLive() {
        Device liveDevice = getLiveDevice();

        if (liveDevice == null) {
            throw new IllegalArgumentException("no live device found");
        }

        return openLive(liveDevice);
    }

    /**
     * Creates a pcap instance in offline mode with specified {@link File}.
     *
     * @param file pcap dump
     * @return instance of {@link Pcap}
     * @throws IllegalArgumentException if file could not be opened
     */
    public static Pcap openOffline(File file) {
        pcap_t pcap_t = PcapLibrary.pcap_open_offline(Pointer.pointerToCString(file.getAbsolutePath()), errbuf);

        if (pcap_t == null) {
            throw new IllegalArgumentException();
        }

        return new Pcap(pcap_t, file);
    }

    /**
     * Looks up a pcap instance by address,
     * if none was found a new pcap instance is created.
     *
     * @param address device address
     * @return pcap instance
     * @throws IllegalArgumentException if none device is bound to address
     */
    public static Pcap getInstance(byte[] address) {
        for (Pcap pcap : instances) {
            if (pcap.getDevice() != null && pcap.getDevice().isBound(address) && pcap.getHandler() instanceof ConnectionHandler) {
                pcap.referenceCount++;

                return pcap;
            }
        }

        for (Device device : Pcap.getDevices()) {
            if (device.isBound(address)) {
                return Pcap.openLive(device);
            }
        }


        throw new IllegalArgumentException();
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

    /**
     * example: {@code libpcap version 1.1.1}
     *
     * @return version string
     */
    public static String getVersion() {
        return PcapLibrary.pcap_lib_version().getCString();
    }

    /**
     * Sets and activates a packet filter
     *
     * @param filter
     * @return {@link Status}
     * @see <a href="http://www.cs.ucr.edu/~marios/ethereal-tcpdump.pdf">cs.ucr.edu/~marios/ethereal-tcpdump.pdf</a>
     */
    public Status filter(String filter) {
        Pointer<bpf_program> bpf_program = Pointer.allocate(bpf_program.class);

        if (Status.valueOf(PcapLibrary.pcap_compile(pcap_t, bpf_program, Pointer.pointerToCString(filter), 0, 0)) == Status.Success) {
            return setStatus(PcapLibrary.pcap_setfilter(pcap_t, bpf_program));
        } else {
            throw new IllegalArgumentException("error while parsing " + filter);
        }
    }

    public void breakloop() {
        if (loop != null) {
            PcapLibrary.pcap_breakloop(pcap_t);

            while (loop.asynchronous && status != Status.Terminated) {
                try {
                    Thread.sleep(50);
                } catch (InterruptedException e) {
                    break;
                }
            }
        }

        loop = null;
    }

    /**
     * Convenient method for {@link #loop(PcapHandler, boolean)}
     * {@code asynchronous = false}.
     *
     * @param handler
     * @return {@link Status}
     */
    public Status loop(PcapHandler handler) {
        return loop(handler, false);
    }

    /**
     * Convenient method for {@link #loop(PcapHandler, boolean)} with
     * {@code asynchronous = true}.
     *
     * @param handler
     * @return {@link Status}
     */
    public Status loopAsynchronous(PcapHandler handler) {
        return loop(handler, true);
    }

    public Status loop(final PcapHandler handler, boolean asynchronous) {
        if (loop != null) {
            return Status.AlreadyActivated;
        }

        loop = new Loop(handler, asynchronous);

        if (!asynchronous) {
            loop.run();
        } else {
            Thread thread = new Thread(loop);
            thread.setName("Pcap");
            thread.start();
        }

        referenceCount++;

        return status;
    }

    /**
     * Returns the local host device (if any).
     *
     * @return device otherwise null
     * @see InetAddress#getLocalHost()
     */
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

    /**
     * Returns the first device pcap can find (if any) except the loopback device.
     *
     * @return device otherwise null
     */
    public static Device getDefaultDevice() {
        String name = PcapLibrary.pcap_lookupdev(errbuf).getCString();

        for (Device device : getDevices()) {
            if (device.getName().equals(name)) {
                return device;
            }
        }

        return null;
    }

    /**
     * @return a list of all {@link Device} from this host
     */
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

                if (Status.valueOf(PcapLibrary.pcap_lookupnet(device.get().name(), netp, maskp, errbuf)) == Status.Success) {
                    net = netp.getInt();
                    mask = maskp.getInt();
                }

                netp.release();
                maskp.release();

                devices.add(new Device(device.get(), net, mask));

                device = device.get().next();
            }

        }

        PcapLibrary.pcap_freealldevs(pcap_if.get());

        return devices;
    }

    private Status setStatus(int code) {
        this.status = Status.valueOf(code);
        return this.status;
    }

    /**
     * Returns last pcap status.
     *
     * @return status
     * @see Status
     */
    public Status getStatus() {
        return status;
    }

    public PcapHandler getHandler() {
        return loop.getHandler();
    }

    public File getFile() {
        return file;
    }

    public Device getDevice() {
        return device;
    }

    public static void setSnaplen(int snaplen) {
        Pcap.snaplen = snaplen;
    }

    public static void setTimeout(int timeout) {
        Pcap.timeout = timeout;
    }

    public void close() {
        referenceCount--;

        if (referenceCount <= 0) {
            if (loop != null) {
                breakloop();
            }

            PcapLibrary.pcap_close(pcap_t);
            instances.remove(this);
        }
    }

    @Override
    protected void finalize() {
        close();
    }

    @Override
    public String toString() {
        return getVersion();
    }
}
