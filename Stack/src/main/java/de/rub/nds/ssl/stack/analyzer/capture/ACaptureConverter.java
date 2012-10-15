package de.rub.nds.ssl.stack.analyzer.capture;

import de.rub.nds.ssl.stack.protocols.ARecordFrame;
import de.rub.nds.ssl.stack.protocols.alert.Alert;
import de.rub.nds.ssl.stack.protocols.commons.EContentType;
import de.rub.nds.ssl.stack.protocols.handshake.HandshakeEnumeration;
import de.rub.nds.ssl.stack.protocols.msgs.ChangeCipherSpec;
import de.rub.nds.ssl.stack.protocols.msgs.TLSCiphertext;
import de.rub.nds.ssl.stack.protocols.msgs.TLSPlaintext;
import de.rub.nds.ssl.stack.trace.MessageContainer;
import de.rub.nds.virtualnetworklayer.connection.pcap.PcapTrace;
import java.util.ArrayList;
import java.util.List;

/**
 * Utility class to handle captured data.
 *
 * @author Christopher Meyer - christopher.meyer@rub.de
 * @version 0.1
 *
 * Oct 15, 2012
 */
public abstract class ACaptureConverter {

    /**
     * Slices the next record frame out of a given message.
     * @param bytes Byte array representing record frame(s).
     * @param offset Offset where to start with record slicing.
     * @return Next record in the byte[].
     */
    public static byte[] sliceOfNextRecord(final byte[] bytes,
            final int offset) {
        int pointer = 0;
        //Determine the length of the frame
        int length = (bytes[3 + offset] & 0xff) << 8
                | (bytes[4 + offset] & 0xff);
        byte[] record = new byte[ARecordFrame.LENGTH_MINIMUM_ENCODED + length];
        // copy header
        System.arraycopy(bytes, offset, record, 0,
                ARecordFrame.LENGTH_MINIMUM_ENCODED);
        pointer += ARecordFrame.LENGTH_MINIMUM_ENCODED;
        // copy payload
        System.arraycopy(bytes, offset + pointer, record, pointer, length);

        return record;
    }

    /**
     * Converts a PcapTrace into a MessageContainer[].
     * @param trace Trace to convert.
     * @return Converted trace including the original trace.
     */
    public static MessageContainer[] convertTrace(final PcapTrace trace) {
        byte[] capturedBytes = MessageContainer.getBytesFromTrace(trace);
        ARecordFrame[] recordFrames = extractRecords(capturedBytes);
        MessageContainer[] container = new MessageContainer[recordFrames.length];
        for(int i=0; i< recordFrames.length; i++) {
            container[i] = new MessageContainer(recordFrames[i], 
                    trace.get(0).getTimeStamp());
            container[i].setPcapTrace(trace);
        }
        
        return container;
    }
    
    /**
     * Extracts records of given capture Pcap trace.
     * @param trace Record capture.
     * @return Decoded messages included in the captured PcapTrace.
     */
    public static ARecordFrame[] extractRecords(final PcapTrace trace) {
        byte[] capturedBytes = MessageContainer.getBytesFromTrace(trace);
        return extractRecords(capturedBytes);
    }
    
    /**
     * Extracts records of given capture byte[].
     * @param capture Record capture.
     * @return Decoded messages included in the captured byte[].
     */
    public static ARecordFrame[] extractRecords(final byte[] capture) {
        List<ARecordFrame> recordFrames = new ArrayList<ARecordFrame>(10);

        int offset = 0;
        byte[] encodedRecord;
        ARecordFrame[] decodedFrames;
        while (offset < capture.length) {
            // extract next record frame from byte[]
            encodedRecord = sliceOfNextRecord(capture, offset);
            offset += encodedRecord.length;

            // decode frame
            decodedFrames = decodeRecordFrames(encodedRecord);
            // add frame(s)
            for (ARecordFrame frame : decodedFrames) {
                recordFrames.add(frame);
            }
        }

        return recordFrames.toArray(new ARecordFrame[recordFrames.size()]);
    }

    /**
     * Decodes an encoded record.
     * @param record Encoded record
     * @return Decoded record frames
     */
    public static ARecordFrame[] decodeRecordFrames(final byte[] record) {
        ARecordFrame[] decodedFrames = new ARecordFrame[1];
        switch (EContentType.getContentType(record[0])) {
            case CHANGE_CIPHER_SPEC:
                decodedFrames[0] = new ChangeCipherSpec(record, true);
                break;
            case ALERT:
                decodedFrames[0] = new Alert(record, true);
                break;
            case HANDSHAKE:
                // first try
                decodedFrames = new HandshakeEnumeration(record, true).
                        getMessages();
                // look for an encrypted finished message
                if (decodedFrames == null || decodedFrames[0] == null
                        || decodedFrames.length <= 1) {
                    // second try
                    decodedFrames = new ARecordFrame[1];
                    decodedFrames[0] = new TLSCiphertext(record, true);
                }
                break;
            case APPLICATION:
                decodedFrames[0] = new TLSPlaintext(record, true);
                break;
            default:
                break;
        }

        return decodedFrames;
    }

    /**
     * Utility class - private constructor.
     */
    private ACaptureConverter() {
    }
}
