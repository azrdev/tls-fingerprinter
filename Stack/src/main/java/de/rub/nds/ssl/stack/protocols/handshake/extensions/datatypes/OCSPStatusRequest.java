package de.rub.nds.ssl.stack.protocols.handshake.extensions.datatypes;

import de.rub.nds.ssl.stack.protocols.handshake.datatypes.ECertificateStatusType;
import org.apache.log4j.Logger;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.*;

/**
 * OCSP Status Request as in RFC 6066 section 8
 *
 * @author jBiegert azrdev@qrdn.de
 */
public class OCSPStatusRequest extends ACertificateStatusRequest {
    private static Logger logger = Logger.getLogger(OCSPStatusRequest.class);

    /**
     * Length of the length field of the responderId List
     */
    private static final int LENGTH_RESPONDER_ID_LIST_LENGTH = 2;

    /**
     * Length of the length field of the requestExtensions field
     */
    private static final int LENGTH_REQUEST_EXTENSIONS_LENGTH = 2;

    private static final int LENGTH_MINIMUM_ENCODED =
            LENGTH_RESPONDER_ID_LIST_LENGTH + LENGTH_REQUEST_EXTENSIONS_LENGTH;

    /**
     * Length of the length field of one responderId
     */
    private static final int LENGTH_RESPONDER_ID_LENGTH = 2;

    private List<byte[]> responderIdList = Collections.EMPTY_LIST;
    private byte[] requestExtensions = new byte[0];

    /**
     * Initialize an OCSPStatusRequest with empty responderIdList and requestExtensions.
     */
    public OCSPStatusRequest() {
        setType(ECertificateStatusType.OCSP);
    }

    /**
     * Initialize from encoded message
     */
    public OCSPStatusRequest(byte[] encoded) {
        setType(ECertificateStatusType.OCSP);
        decode(encoded, true);
    }

    public List<byte[]> getResponderIdList() {
        return responderIdList;
    }

    public void setResponderIdList(final List<byte[]> responderIdList) {
        if(requestExtensions == null)
            throw new IllegalArgumentException("responderId List must not be null");

        this.responderIdList = new ArrayList<>(responderIdList);
    }

    public byte[] getRequestExtensions() {
        return requestExtensions;
    }

    public void setRequestExtensions(final byte[] requestExtensions) {
        if(requestExtensions == null)
            throw new IllegalArgumentException("requestExtensions must not be null");

        this.requestExtensions = requestExtensions;
    }

    /**
     * @param chained <b>ignored</b>
     */
    @Override
    public byte[] encode(boolean chained) {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        try {

            // responder_id_list
            for(final byte[] responderId : responderIdList) {
                bytes.write(buildLength(responderId.length, LENGTH_RESPONDER_ID_LENGTH));
                bytes.write(responderId);
            }

            // request_extensions
            bytes.write(requestExtensions.length);
            bytes.write(requestExtensions);

        } catch (IOException e) {
            logger.warn("ByteArrayOutputStream throws but should never: " + e);
        }

        return bytes.toByteArray();
    }

    /**
     * @param chained <b>ignored</b>
     */
    @Override
    public void decode(final byte[] message, boolean chained) {
        byte[] messageCopy = Arrays.copyOf(message, message.length);
        int pointer = 0;

        if(LENGTH_MINIMUM_ENCODED >  messageCopy.length)
            throw new IllegalArgumentException("OCSPStatusRequest too short");

        // responder_id_list length
        final int responderIdListLength = extractLength(messageCopy, pointer,
                LENGTH_RESPONDER_ID_LIST_LENGTH);
        pointer += LENGTH_RESPONDER_ID_LIST_LENGTH;
        if(pointer + responderIdListLength > messageCopy.length)
            throw new IllegalArgumentException("Responder Id List length field invalid");

        // responder_id_list
        List<byte[]> responderIdList = new LinkedList<>();
        int listPtr = 0;
        while(listPtr + LENGTH_RESPONDER_ID_LENGTH < responderIdListLength) {
            // responder_id length
            final int responderIdLength = extractLength(messageCopy, listPtr,
                    LENGTH_RESPONDER_ID_LENGTH);
            listPtr += LENGTH_RESPONDER_ID_LENGTH;
            if(listPtr + responderIdLength > responderIdListLength)
                throw new IllegalArgumentException("Responder Id length field invalid");

            // responder_id data
            responderIdList.add(
                    Arrays.copyOfRange(messageCopy, listPtr,
                            listPtr + responderIdLength));
            listPtr += responderIdLength;
        }
        setResponderIdList(responderIdList);

        // request_extensions
        final int requestExtensionsLength = extractLength(messageCopy, pointer,
                LENGTH_REQUEST_EXTENSIONS_LENGTH);
        pointer += LENGTH_REQUEST_EXTENSIONS_LENGTH;
        if(pointer + requestExtensionsLength > messageCopy.length)
            throw new IllegalArgumentException("Request Extensions length field invalid");

        byte[] tmp = Arrays.copyOfRange(messageCopy, pointer,
                pointer + requestExtensionsLength);
        setRequestExtensions(tmp);
    }
}
