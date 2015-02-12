package de.rub.nds.ssl.analyzer.vnl.fingerprint.serialization;

import com.google.common.collect.HashMultimap;
import com.google.common.collect.SetMultimap;
import de.rub.nds.ssl.analyzer.vnl.SessionIdentifier;
import de.rub.nds.ssl.analyzer.vnl.fingerprint.ClientHelloFingerprint;
import de.rub.nds.ssl.analyzer.vnl.fingerprint.HandshakeFingerprint;
import de.rub.nds.ssl.analyzer.vnl.fingerprint.ServerHelloFingerprint;
import de.rub.nds.ssl.analyzer.vnl.fingerprint.TLSFingerprint;
import de.rub.nds.virtualnetworklayer.p0f.Module;
import de.rub.nds.virtualnetworklayer.p0f.signature.MTUSignature;
import de.rub.nds.virtualnetworklayer.p0f.signature.TCPSignature;
import org.antlr.v4.runtime.Parser;
import org.antlr.v4.runtime.misc.NotNull;
import org.antlr.v4.runtime.tree.TerminalNode;
import org.apache.log4j.Logger;

import java.util.LinkedList;
import java.util.List;

/**
 * Listener to the ANTLR4 parser, extracting the parsed fingerprints
 *
 * @author jBiegert azrdev@qrdn.de
 */
public class FingerprintSaveFileReader extends FingerprintSaveFileParserBaseListener {
    private static final Logger logger = Logger.getLogger(FingerprintSaveFileReader.class);

    private final Parser parser;

    /**
     * Ctor
     * @param parser Must be the parser used to create the walked tree
     */
    public FingerprintSaveFileReader(final Parser parser) {
        this.parser = parser;
    }

    // fields managing state & result while parsing

    private final SetMultimap<SessionIdentifier, TLSFingerprint> fingerprints =
            HashMultimap.create();

    private SessionIdentifier sessionIdentifier = null;
    private ClientHelloFingerprint clientHelloSignature = null;
    private ServerHelloFingerprint serverHelloSignature = null;
    private HandshakeFingerprint handshakeSignature = null;
    private TCPSignature serverTcpSignature = null;
    private MTUSignature serverMtuSignature = null;

    private final List<String> signs = new LinkedList<>();

    public SetMultimap<SessionIdentifier, TLSFingerprint> getFingerprints() {
        return fingerprints;
    }

    // parsing listener functions

    @Override
    public void exitRecord(@NotNull FingerprintSaveFileParser.RecordContext ctx) {
        final TLSFingerprint fingerprint = new TLSFingerprint(handshakeSignature,
                serverHelloSignature, serverTcpSignature, serverMtuSignature);
        try {
            if (sessionIdentifier == null || fingerprint == null) {
                logger.debug("invalid record at position " + ctx.toInfoString(parser) +
                        " - SessionId: " + sessionIdentifier +
                        " TlsFingerprint: " + fingerprint);
                return;
            }
            sessionIdentifier.setClientHelloSignature(clientHelloSignature);

            if (fingerprints.containsEntry(sessionIdentifier, fingerprint)) {
                logger.warn("Duplicate fingerprint at position " + ctx.toInfoString(parser) +
                        " SessionId: " + sessionIdentifier);
                logger.trace("fingerprint: " + fingerprint);
            } else {
                fingerprints.put(sessionIdentifier, fingerprint);
            }
        } finally {
            sessionIdentifier = null;
            clientHelloSignature = null;
            serverHelloSignature = null;
            handshakeSignature = null;
            serverTcpSignature = null;
            serverMtuSignature = null;
        }
    }


    @Override
    public void exitSessionId(@NotNull FingerprintSaveFileParser.SessionIdContext ctx) {
        try {
            sessionIdentifier = new SessionIdentifier(ctx.host().Word().getText());
        } catch(IllegalArgumentException|NullPointerException e) {
            logger.warn("Error reading SessionIdentifier at position " +
                    ctx.toInfoString(parser) + " - " + e, e);
        }
    }

    @Override
    public void exitSignatureCH(@NotNull FingerprintSaveFileParser.SignatureCHContext ctx) {
        if(clientHelloSignature != null)
            logger.warn("Signature at position " + ctx.toInfoString(parser) +
                    " overriding previous: " + clientHelloSignature);
        try {
            clientHelloSignature = ClientHelloFingerprint.deserializeFingerprint(signs);
        } catch(IllegalArgumentException e) {
            logger.warn("Error reading ClientHelloSignature at position " +
                    ctx.toInfoString(parser) + " - " + e, e);
        }
    }

    @Override
    public void exitSignatureSH(@NotNull FingerprintSaveFileParser.SignatureSHContext ctx) {
        if(serverHelloSignature != null)
            logger.warn("Signature at position " + ctx.toInfoString(parser) +
                    " overriding previous: " + serverHelloSignature);
        try {
            serverHelloSignature = ServerHelloFingerprint.deserializeFingerprint(signs);
        } catch(IllegalArgumentException e) {
            logger.warn("Error reading ServerHelloSignature at position " +
                    ctx.toInfoString(parser) + " - " + e, e);
        }
    }

    @Override
    public void exitSignatureHS(@NotNull FingerprintSaveFileParser.SignatureHSContext ctx) {
        if(handshakeSignature != null)
            logger.warn("Signature at position " + ctx.toInfoString(parser) +
                    " overriding previous: " + handshakeSignature);
        try {
            handshakeSignature = HandshakeFingerprint.deserializeHandshake(signs);
        } catch(IllegalArgumentException e) {
            logger.warn("Error reading HandshakeSignature at position " +
                    ctx.toInfoString(parser) + " - " + e, e);
        }
    }

    @Override
    public void exitSignatureTCP(@NotNull FingerprintSaveFileParser.SignatureTCPContext ctx) {
        if(serverTcpSignature != null)
            logger.warn("Signature at position " + ctx.toInfoString(parser) +
                    " overriding previous: " + serverTcpSignature);
        try {
            serverTcpSignature = new TCPSignature(signs, Module.Direction.Response);
        } catch(IllegalArgumentException e) {
            logger.warn("Error reading ServerTCPSignature at position " +
                    ctx.toInfoString(parser) + " - " + e, e);
        }
    }

    @Override
    public void exitSignatureMTU(@NotNull FingerprintSaveFileParser.SignatureMTUContext ctx) {
        if(serverMtuSignature != null)
            logger.warn("Signature at position " + ctx.toInfoString(parser) +
                    " overriding previous: " + serverMtuSignature);
        try {
            serverMtuSignature = new MTUSignature(signs);
        } catch(IllegalArgumentException e) {
            logger.warn("Error reading ServerMTUSignature at position " +
                    ctx.toInfoString(parser) + " - " + e, e);
        }
    }


    @Override
    public void enterSignatureLine(@NotNull FingerprintSaveFileParser.SignatureLineContext ctx) {
        signs.clear();
    }

    @Override
    public void exitSign(@NotNull FingerprintSaveFileParser.SignContext ctx) {
        final TerminalNode word = ctx.Word();
        if(word == null)
            signs.add(""); //empty
        else
            signs.add(word.getText());
    }
}
