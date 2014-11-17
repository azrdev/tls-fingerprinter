package de.rub.nds.virtualnetworklayer.pcap;

import de.rub.nds.virtualnetworklayer.pcap.structs.pcap_dumper_t;
import de.rub.nds.virtualnetworklayer.pcap.structs.pcap_pkthdr;
import org.bridj.Pointer;

import java.io.File;

/**
 * A "savefile" to which to write packets.
 * <br>
 * Get an instance by using {@link Pcap#openDump(java.io.File)}
 *
 * @author jBiegert azrdev@qrdn.de
 */
public class PcapDumper {
    private pcap_dumper_t pcap_dumper_t;

    private void checkDumper() throws IllegalStateException {
        if(pcap_dumper_t == null)
            throw new IllegalStateException("pcap_dumper_t == NULL");
    }

    /**
     * @see Pcap#openDump(java.io.File)
     */
    public static PcapDumper openFile(Pcap pcap, File pathname) {
        return pcap.openDump(pathname);
    }

    PcapDumper(pcap_dumper_t pcap_dumper_t) {
        this.pcap_dumper_t = pcap_dumper_t;
    }

    /**
     * Write a packet to the "savefile".
     * <br>
     * Parameters are identical to those of {@link
     * PcapHandler#callback(Pointer, Pointer, Pointer)}
     */
    void dump(Pointer<pcap_pkthdr> header, Pointer<Byte> bytes) {
        PcapLibrary.pcap_dump(pcap_dumper_t, header, bytes);
    }

    public void dump(PcapHandler.RawPacket packet) {
        dump(packet.getHeaderNative(), packet.getBytesNative());
    }

    /**
     * @return The current position in the "savefile"
     */
    public long position() {
        return PcapLibrary.pcap_dump_ftell(pcap_dumper_t);
    }

    /**
     * Flushes the output buffer to the "savefile"
     */
    public boolean flush() {
        return PcapLibrary.pcap_dump_flush(pcap_dumper_t) == 0;
    }

    public void close() {
        checkDumper();
        PcapLibrary.pcap_dump_close(pcap_dumper_t);
        pcap_dumper_t = null;
    }

    @Override
    protected void finalize() throws Throwable {
        close();
        super.finalize();
    }
}
