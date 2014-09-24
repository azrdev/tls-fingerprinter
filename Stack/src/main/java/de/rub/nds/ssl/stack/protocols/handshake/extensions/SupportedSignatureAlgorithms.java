package de.rub.nds.ssl.stack.protocols.handshake.extensions;

import de.rub.nds.ssl.stack.protocols.handshake.extensions.datatypes.EExtensionType;
import de.rub.nds.ssl.stack.protocols.handshake.extensions.datatypes.SignatureAndHashAlgorithm;
import org.apache.log4j.Logger;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;

/**
 * Supported Signature Algorithms extensions as in RFC 5246
 *
 * @author jBiegert azrdev@qrdn.de
 */
public class SupportedSignatureAlgorithms extends AExtension {
    private static Logger logger = Logger.getLogger(SupportedSignatureAlgorithms.class);

    /**
     * Length of the Length field of the List
     */
    private static final int LENGTH_LIST_LENGTH = 2;

    private List<SignatureAndHashAlgorithm> supportedSignatureAlgorithms
            = new ArrayList<>(0);

    public SupportedSignatureAlgorithms() {
        super();
        setExtensionType(EExtensionType.SIGNATURE_ALGORITHMS);
    }

    public SupportedSignatureAlgorithms(byte[] message) {
        this(message, true);
    }

    public SupportedSignatureAlgorithms(byte[] message, boolean chained) {
        super();
        setExtensionType(EExtensionType.SIGNATURE_ALGORITHMS);
        decode(message, chained);
    }

    public List<SignatureAndHashAlgorithm> getSupportedSignatureAlgorithms() {
        return supportedSignatureAlgorithms;
    }

    public void setSupportedSignatureAlgorithms(List<SignatureAndHashAlgorithm> algs) {
        if(algs == null)
            throw new IllegalArgumentException(
                    "SupportedSignatureAlgorithms must not be null");

        this.supportedSignatureAlgorithms = new ArrayList<>(algs);
    }

    @Override
    public byte[] encode(boolean chained) {
        byte[] bytes = new byte[supportedSignatureAlgorithms.size() *
                SignatureAndHashAlgorithm.LENGTH_ENCODED];
        int i = 0;

        for(SignatureAndHashAlgorithm sha : supportedSignatureAlgorithms) {
            final byte[] se = sha.encode(chained);
            bytes[i] = se[0];
            bytes[i+1] = se[1];
            i += SignatureAndHashAlgorithm.LENGTH_ENCODED; // == 2
        }

        setExtensionData(bytes);
        if(chained)
            return super.encode(chained);
        else
            return bytes;
    }

    @Override
    public void decode(byte[] message, boolean chained) {
        if(chained)
            super.decode(message, chained);
        else
            setExtensionData(message);

        int pointer = 0;
        final byte[] extensionData = getExtensionData();

        if(extensionData.length == 0) {
            setSupportedSignatureAlgorithms(Collections.EMPTY_LIST);
            return;
        }

        if(pointer + LENGTH_LIST_LENGTH > extensionData.length) {
            throw new IllegalArgumentException(
                    "Supported Signature Algorithms too short");
        }

        // get list length
        int extractedLength = extractLength(extensionData, pointer, LENGTH_LIST_LENGTH);
        pointer += LENGTH_LIST_LENGTH;

        // get list
        List<SignatureAndHashAlgorithm> shaList = new LinkedList<>();
        while(pointer + SignatureAndHashAlgorithm.LENGTH_ENCODED < extensionData.length) {
            byte[] tmp = new byte[SignatureAndHashAlgorithm.LENGTH_ENCODED];
            System.arraycopy(extensionData, pointer, tmp, 0, tmp.length);
            pointer += SignatureAndHashAlgorithm.LENGTH_ENCODED;

            try {
                shaList.add(new SignatureAndHashAlgorithm(tmp));
            } catch (IllegalArgumentException ex) {
                logger.debug(ex);
                continue;
            }
        }
        setSupportedSignatureAlgorithms(shaList);
    }
}
