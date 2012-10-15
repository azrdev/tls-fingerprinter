package de.rub.nds.ssl.stack.analyzer.capture;

import de.rub.nds.ssl.stack.protocols.ARecordFrame;
import de.rub.nds.ssl.stack.trace.Message;
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

    public ARecordFrame extractMessage(final byte[] message, 
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

        return null;
    }

    public ARecordFrame[] extractMessageTrace(final byte[] capture) {
        List<ARecordFrame> recordFrames = new ArrayList<ARecordFrame>(10);

        int offset = 0;
        while (offset < capture.length) {
            recordFrames.add(extractMessage(capture, offset));
        }

        return recordFrames.toArray(new ARecordFrame[recordFrames.size()]);
    }
}
