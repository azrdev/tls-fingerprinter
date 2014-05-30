package de.rub.nds.ssl.analyzer.vnl;

import de.rub.nds.ssl.stack.Utility;
import de.rub.nds.ssl.stack.protocols.ARecordFrame;
import de.rub.nds.ssl.stack.protocols.alert.Alert;
import de.rub.nds.ssl.stack.protocols.commons.EContentType;
import de.rub.nds.ssl.stack.protocols.handshake.HandshakeEnumeration;
import de.rub.nds.ssl.stack.protocols.handshake.datatypes.EKeyExchangeAlgorithm;
import de.rub.nds.ssl.stack.protocols.msgs.ChangeCipherSpec;
import de.rub.nds.ssl.stack.protocols.msgs.TLSPlaintext;
import de.rub.nds.virtualnetworklayer.connection.pcap.PcapTrace;
import de.rub.nds.virtualnetworklayer.packet.PcapPacket;
import java.util.ArrayList;
import java.util.Arrays;
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
     * Converts a PcapTrace to a MessageContainer.
     *
     * @param trace PcapTrace containing record frames.
     * @return Message container of all included record frames and additional
     * information.
     */
    public static MessageContainer[] convertToMessageContainer(
            final PcapTrace trace) {
        List<MessageContainer> container = new ArrayList<MessageContainer>(10);
        List<Integer> offsets = new ArrayList<Integer>(10);

        int pointer = 0;
        // determine overall byte length
        for (PcapPacket packet : trace) {
            pointer += packet.getLength();
        }

        byte[] traceBytes = new byte[pointer];
        pointer = 0;
        // extract bytes from trace and keep track of associated packets
        for (PcapPacket packet : trace) {
            System.arraycopy(packet.getContent(), 0, traceBytes, pointer,
                    packet.getLength());
            pointer += packet.getLength();
            offsets.add(pointer);
        }

        pointer = 0;
        byte[] encodedRecord;
        ARecordFrame[] frames;
        // extract all record frames and add them to the message container
        while (pointer < traceBytes.length) {
            // extract next record frame from byte[]
            encodedRecord = sliceOfNextRecord(traceBytes, pointer);
            pointer += encodedRecord.length;

            // decode frame
            frames = decodeRecordFrames(encodedRecord, null);
            // add frame(s)
            for (ARecordFrame frame : frames) {
                // look up trace packet
                int offset;
                for (int i = 0; i < offsets.size(); i++) {
                    offset = offsets.get(i);
                    if (!(pointer > offset)) {
                        // packet found
                        container.add(new MessageContainer(frame,
                                trace.get(i)));
                        break;
                    }
                }

            }
        }

        return container.toArray(new MessageContainer[container.size()]);
    }

    /**
     * Extracts a byte[] from a Pcap trace.
     *
     * @param trace Pcap trace including the bytes.
     * @return Bytes of the Pcap trace.
     */
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
     * Slices the next record frame out of a given message.
     *
     * @param bytes Byte array representing record frame(s).
     * @param offset Offset where to start with record slicing.
     * @return Next record in the byte[].
     */
    public static byte[] sliceOfNextRecord(final byte[] bytes,
            final int offset) {
        int pointer = 0;
        //Determine the length of the frame
        int length = (bytes[3 + offset] & 0xff) << Utility.BITS_IN_BYTE
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
     * Extracts records of given capture PcapTrace.
     *
     * @param trace Record capture.
     * @return Decoded messages included in the captured PcapTrace.
     */
    public static ARecordFrame[] extractRecords(final PcapTrace trace) {
        byte[] capturedBytes = getBytesFromTrace(trace);
        return extractRecords(capturedBytes);
    }

    /**
     * Extracts records of given capture byte[].
     *
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
            decodedFrames = decodeRecordFrames(encodedRecord, null);
            recordFrames.addAll(Arrays.asList(decodedFrames));
        }

        return recordFrames.toArray(new ARecordFrame[recordFrames.size()]);
    }

    /**
     * Decodes an encoded record.
     *
     * @param record Encoded record
     * @return Decoded record frames
     */
    public static ARecordFrame[] decodeRecordFrames(final byte[] record, EKeyExchangeAlgorithm keyExchangeAlgorithm) {
        ARecordFrame[] decodedFrames = new ARecordFrame[1];
        switch (EContentType.getContentType(record[0])) {
            case CHANGE_CIPHER_SPEC:
                decodedFrames[0] = new ChangeCipherSpec(record, true);
                break;
            case ALERT:
                decodedFrames[0] = new Alert(record, true);
                break;
            case HANDSHAKE:
                // try to decode the message
                decodedFrames = new HandshakeEnumeration(record, true, keyExchangeAlgorithm).
                        getMessages();
                // very likely to deal with an encrypted message
                if (decodedFrames == null
                        || decodedFrames.length < 1
                        || decodedFrames[0] == null) {
                    System.err.println("decoding handshake messages failed! " + Arrays.toString(decodedFrames));
                }
                break;
            case APPLICATION:
                decodedFrames[0] = new TLSPlaintext(record, true);
                break;
            default:
                System.err.println("default case, should not happen: "
                        + EContentType.getContentType(record[0]));
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
