package de.rub.nds.ssl.stack.workflows.response.fecther;

import de.rub.nds.virtualnetworklayer.connection.pcap.PcapTrace;
import de.rub.nds.virtualnetworklayer.packet.PcapPacket;

/**
 * Response object as created by a fetcher.
 *
 * @author Christopher Meyer - christopher.meyer@rub.de
 * @version 0.1
 *
 * Sep 4, 2012
 */
public class Response {
    private PcapTrace trace;
    private byte[] responseBytes;
    private long timestamp;
    
    Response(final PcapTrace trace) {
        this.trace = trace;
        this.responseBytes = getBytesFromTrace(trace);
        if(this.trace.size() > 0) {
            this.timestamp = this.trace.get(0).getTimeStamp();
        }
    }

    Response(final byte[] bytes, final long timestamp) {
        this.responseBytes = new byte[bytes.length];
        System.arraycopy(bytes, 0, this.responseBytes, 0, bytes.length);
        this.timestamp = timestamp;
    }
    
    public static byte[] getBytesFromTrace(final PcapTrace trace) {
        int capacity = 0;
        for (PcapPacket packet : trace) {
            capacity += packet.getLength();
        }

        byte[] answerBytes = new byte[capacity];
        int pointer = 0;
        for (PcapPacket packet : trace) {
            System.arraycopy(packet.getContent(), 0, answerBytes, pointer,
                    packet.getLength());
            pointer += packet.getLength();
        }
        
        return answerBytes;
    }

    /**
     * Get the packet trace, if available.
     * NO DEEP COPY!
     * @return Packet trace
     */
    public PcapTrace getTrace() {
        return trace;
    }

    /**
     * Get the response bytes.
     * NO DEEP COPY!
     * @return Response bytes
     */
    public byte[] getBytes() {
        return responseBytes;
    }

    /**
     * Get the timestamp of the first packet that reached the device.
     * @return Timestamp
     */
    public long getTimestamp() {
        return timestamp;
    }
    
    
}
