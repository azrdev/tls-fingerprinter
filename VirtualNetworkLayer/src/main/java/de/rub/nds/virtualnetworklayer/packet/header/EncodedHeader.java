package de.rub.nds.virtualnetworklayer.packet.header;

import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.Charset;
import java.nio.charset.CharsetDecoder;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * This class extends a header with decoding capabilities.
 * {@link #getCharset()} has to return the charset used for decoding.
 *
 * @author Marco Faltermeier <faltermeier@me.com>
 */
public abstract class EncodedHeader extends Header {
    private CharBuffer decodedPayload;

    protected final Matcher getMatcher(Pattern pattern) {
        return pattern.matcher(decodedPayload);
    }

    protected final String getString(int offset, int length) {
        CharSequence sequence = getSequence(offset, length);
        if (sequence != null) {
            return sequence.toString();
        }

        return "";
    }

    protected final CharSequence getSequence(int offset, int length) {
        if (decodedPayload.limit() >= offset + length) {
            return decodedPayload.subSequence(offset, offset + length);
        }

        return null;
    }

    @Override
    protected final ByteBuffer decode(ByteBuffer payload) {
        CharsetDecoder decoder = getCharset().newDecoder();

        try {
            decodedPayload = decoder.decode(payload);
        } catch (CharacterCodingException e) {
            return payload;
        }

        return payload;
    }

    public String getContent() {
        return getString(getLength(), getPayloadLength());
    }

    /**
     * @return charset of encoded header
     */
    protected abstract Charset getCharset();
}
