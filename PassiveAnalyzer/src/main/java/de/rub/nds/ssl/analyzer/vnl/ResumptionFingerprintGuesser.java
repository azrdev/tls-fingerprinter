package de.rub.nds.ssl.analyzer.vnl;

import de.rub.nds.ssl.analyzer.vnl.fingerprint.HandshakeFingerprint;
import de.rub.nds.ssl.analyzer.vnl.fingerprint.ServerHelloFingerprint;
import de.rub.nds.ssl.analyzer.vnl.fingerprint.TLSFingerprint;
import de.rub.nds.ssl.stack.protocols.commons.Id;
import de.rub.nds.virtualnetworklayer.fingerprint.Fingerprint;
import org.apache.log4j.Logger;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static de.rub.nds.ssl.analyzer.vnl.FingerprintReporter.*;

/**
 * Listens for fingerprints of "normal" handshakes and guesses how the fingerprints of
 * the corresponding session resumption(s) may look like. Can inject the guess back to
 * the {@link FingerprintListener}, so they become part of the "already seen"
 * fingerprints.
 * @author jBiegert azrdev@qrdn.de
 */
public class ResumptionFingerprintGuesser extends FingerprintReporterAdapter {
    private static final Logger logger = Logger.getLogger(ResumptionFingerprintGuesser.class);

    private FingerprintListener listener;

    /**
     * @param listener Used to inject guessed fingerprints. Pass null to disable injection.
     */
    public ResumptionFingerprintGuesser(FingerprintListener listener) {
        this.listener = listener;
    }

    @Override
    public void reportNew(SessionIdentifier sessionIdentifier, TLSFingerprint tlsFingerprint) {
        if(tlsFingerprint instanceof GuessedResumptionFingerprint) {
            //shouldn't happen
            logger.warn("guessed fingerprint seen in reportNew(). sessionId: " +
                    sessionIdentifier);
            return;
        }

        final TLSFingerprint resumptionGuess = GuessedResumptionFingerprint.create(tlsFingerprint);

        if(listener != null) {
            logger.debug("now reporting guessed fingerprint");
            listener.insertFingerprint(sessionIdentifier, resumptionGuess);
        }
    }

    public static class GuessedResumptionFingerprint extends TLSFingerprint {

        private GuessedResumptionFingerprint(
                @Nullable HandshakeFingerprint handshake,
                @Nullable ServerHelloFingerprint serverHello,
                @Nullable Fingerprint.Signature serverTcp,
                @Nullable Fingerprint.Signature serverMtu) {
            super(handshake, serverHello, serverTcp, serverMtu);
        }

        public static GuessedResumptionFingerprint create(@Nonnull TLSFingerprint original) {

            GuessedHandshakeFingerprint handshakeFingerprint = null;
            if(original.getHandshakeSignature() != null)
                handshakeFingerprint =
                        GuessedHandshakeFingerprint.create(original.getHandshakeSignature());

            GuessedServerHelloFingerprint serverHelloFingerprint = null;
            if (original.getServerHelloSignature() != null)
                serverHelloFingerprint =
                        GuessedServerHelloFingerprint.create(original.getServerHelloSignature());

            return new GuessedResumptionFingerprint(
                    handshakeFingerprint,
                    serverHelloFingerprint,
                    original.getServerTcpSignature(),
                    original.getServerMtuSignature());
        }
    }

    public static class GuessedHandshakeFingerprint extends HandshakeFingerprint {
        /** the "message-types" sign contents to be assumed for every resumption */
        private static final List<MessageTypes> MESSAGE_TYPES =
                Arrays.asList(new MessageTypes[]{
                    new MessageTypeSubtype(new Id((byte) 0x16), new Id((byte) 0x01)),
                    new MessageTypeSubtype(new Id((byte) 0x16), new Id((byte) 0x02)),
                    new MessageType(new Id((byte) 0x14)),
                    new MessageType(new Id((byte) 0x14))
                });

        private GuessedHandshakeFingerprint(@Nonnull HandshakeFingerprint original) {
            super(original); // copy

            // overwrite signs
            signs.put("message-types", MESSAGE_TYPES);
            signs.put("session-ids-match", true);
        }

        public static GuessedHandshakeFingerprint create(@Nonnull HandshakeFingerprint original) {
            return new GuessedHandshakeFingerprint(original);
        }
    }

    public static class GuessedServerHelloFingerprint extends ServerHelloFingerprint {
        private GuessedServerHelloFingerprint(@Nonnull ServerHelloFingerprint original) {
            super(original); // copy

            // overwrite signs
            signs.put("session-id-empty", false);

            //FIXME: ServerHello.extensionsLayout - multiple variants, dep. on original?
            Object sign = signs.get("extensions-layout");
            if(sign instanceof List) {
                final List<Id> extensionsLayout = new ArrayList<>((List<Id>) sign);
                List<Id> newExtensionsLayout = Arrays.asList(
                        new Id(new byte[]{(byte) 0xff, 0x01}));
                signs.put("extensions-layout", newExtensionsLayout);
            } else if(sign != null) {
                logger.warn("ServerHello.extensions-layout not a list: " + sign);
            }
        }

        public static GuessedServerHelloFingerprint create(@Nonnull ServerHelloFingerprint original) {
            return new GuessedServerHelloFingerprint(original);
        }
    }
}
