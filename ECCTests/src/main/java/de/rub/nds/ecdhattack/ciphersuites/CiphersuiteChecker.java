/*
 * 
 */
package de.rub.nds.ecdhattack.ciphersuites;

import de.rub.nds.ssl.stack.protocols.commons.ECipherSuite;
import de.rub.nds.ssl.stack.protocols.handshake.ClientHello;
import de.rub.nds.ssl.stack.protocols.handshake.datatypes.CipherSuites;
import de.rub.nds.ssl.stack.protocols.handshake.datatypes.Extensions;
import de.rub.nds.ssl.stack.protocols.handshake.extensions.EllipticCurves;
import de.rub.nds.ssl.stack.protocols.handshake.extensions.SupportedPointFormats;
import de.rub.nds.ssl.stack.protocols.handshake.extensions.datatypes.EECPointFormat;
import de.rub.nds.ssl.stack.protocols.handshake.extensions.datatypes.ENamedCurve;
import de.rub.nds.ssl.stack.trace.MessageContainer;
import de.rub.nds.ssl.stack.workflows.TLS10HandshakeWorkflow;
import de.rub.nds.ssl.stack.workflows.commons.ObservableBridge;
import java.net.SocketException;
import java.util.Observable;
import java.util.Observer;

/**
 *
 * @author Juraj Somorovsky - juraj.somorovsky@rub.de
 * @version 0.1
 */
public class CiphersuiteChecker implements Observer {

    private int port;
    private String host;
    private TLS10HandshakeWorkflow workflow;
    private boolean accepted;
    private ECipherSuite ciphersuite;

    CiphersuiteChecker(final String passedHost, final int passedPort) {
        host = passedHost;
        port = passedPort;
    }

    public synchronized boolean isCiphersuiteAccepted(ECipherSuite ciphersuite)
            throws SocketException, InterruptedException {

        this.ciphersuite = ciphersuite;
        workflow = new TLS10HandshakeWorkflow(false);
        workflow.connectToTestServer(host, port);
        workflow.addObserver(this,
                TLS10HandshakeWorkflow.EStates.CLIENT_HELLO);
        workflow.addObserver(this,
                TLS10HandshakeWorkflow.EStates.SERVER_HELLO_DONE);
        workflow.start();
        workflow.closeSocket();

        if (workflow.getMessages() == null || workflow.getMessages().isEmpty()) {
            accepted = false;
        } else {
            accepted = true;
            System.out.println(workflow.getMessages().get(0));
        }
        return accepted;
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
                    suites.setSuites(new ECipherSuite[]{ciphersuite});
                    clientHello.setCipherSuites(suites);

                    Extensions extensions = new Extensions();
                    EllipticCurves curves = new EllipticCurves();
                    curves.setSupportedCurves(new ENamedCurve[]{
                                ENamedCurve.SECP_256_R1, ENamedCurve.SECP_192_R1,
                                ENamedCurve.SECP_160_R1
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
                case SERVER_HELLO_DONE:
                    accepted = true;
                    return;
            }
        }
    }

    public boolean isAccepted() {
        return accepted;
    }

    public void setAccepted(boolean accepted) {
        this.accepted = accepted;
    }
}