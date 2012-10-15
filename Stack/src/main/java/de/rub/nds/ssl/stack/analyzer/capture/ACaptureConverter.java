package de.rub.nds.ssl.stack.analyzer.capture;

import de.rub.nds.ssl.stack.protocols.ARecordFrame;
import de.rub.nds.ssl.stack.protocols.alert.Alert;
import de.rub.nds.ssl.stack.protocols.alert.datatypes.EAlertLevel;
import de.rub.nds.ssl.stack.protocols.commons.EContentType;
import de.rub.nds.ssl.stack.protocols.handshake.HandshakeEnumeration;
import de.rub.nds.ssl.stack.protocols.msgs.ChangeCipherSpec;
import de.rub.nds.ssl.stack.protocols.msgs.TLSCiphertext;
import de.rub.nds.ssl.stack.protocols.msgs.TLSPlaintext;
import de.rub.nds.ssl.stack.trace.MessageContainer;
import de.rub.nds.ssl.stack.workflows.TLS10HandshakeWorkflow;
import de.rub.nds.virtualnetworklayer.connection.pcap.PcapTrace;
import java.util.ArrayList;
import java.util.List;

/**
 * Loads a captured byte[] and extracts the included messages.
 *
 * @author Christopher Meyer - christopher.meyer@rub.de
 * @version 0.1
 *
 * Oct 15, 2012
 */
public abstract class ACaptureConverter {

    public byte[] sliceOfNextRecord(final byte[] message,
            final int offset) {
        int pointer = 0;
        //Determine the length of the frame
        int length = (message[3 + offset] & 0xff) << 8
                | (message[4 + offset] & 0xff);
        byte[] record = new byte[ARecordFrame.LENGTH_MINIMUM_ENCODED + length];
        // copy header
        System.arraycopy(message, offset, record, 0,
                ARecordFrame.LENGTH_MINIMUM_ENCODED);
        pointer += ARecordFrame.LENGTH_MINIMUM_ENCODED;
        // copy payload
        System.arraycopy(message, offset + pointer, record, pointer, length);

        return record;
    }

    public MessageContainer[] trace2MessageContainer(final PcapTrace trace) {
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
    
    public ARecordFrame[] extractRecords(final PcapTrace trace) {
        byte[] capturedBytes = MessageContainer.getBytesFromTrace(trace);
        return extractRecords(capturedBytes);
    }
    
    public ARecordFrame[] extractRecords(final byte[] capture) {
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

    public ARecordFrame[] decodeRecordFrames(final byte[] record) {
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
}
