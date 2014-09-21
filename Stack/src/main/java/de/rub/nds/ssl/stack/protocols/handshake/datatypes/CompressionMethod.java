package de.rub.nds.ssl.stack.protocols.handshake.datatypes;

import de.rub.nds.ssl.stack.Utility;
import de.rub.nds.ssl.stack.protocols.commons.APubliclySerializable;
import de.rub.nds.ssl.stack.protocols.commons.ECompressionMethod;
import de.rub.nds.ssl.stack.protocols.commons.Id;
import org.apache.log4j.Logger;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Compression method message part - as defined in RFC-2246.
 *
 * @author Christopher Meyer - christopher.meyer@rub.de
 * @version 0.1
 *
 * Nov 15, 2011
 */
public final class CompressionMethod extends APubliclySerializable {

    private Logger logger = Logger.getLogger(getClass());

    /**
     * Length of the length field.
     */
    private static final int LENGTH_LENGTH_FIELD = 1;
    /**
     * Minimum length of the encoded form.
     */
    public static final int LENGTH_MINIMUM_ENCODED = LENGTH_LENGTH_FIELD;

    /**
     * Compression methods.
     */
    private List<ECompressionMethod> methods = new ArrayList<>();

    /**
     * Compression methods - raw "id" bytes
     */
    private List<Id> rawMethods = new ArrayList<>(0);

    @Override
    public String toString() {
        return methods.toString();
    }

    /**
     * Initializes as defined in RFC 2246. By default contain only ECompressionMethod.NULL
     */
    public CompressionMethod() {
        setMethods(new ECompressionMethod[]{ECompressionMethod.NULL});
    }

    /**
     * Initializes with the given methods
     */
    public CompressionMethod(List<ECompressionMethod> methods) {
        setMethods(methods);
    }

    /**
     * Initializes a compression method object as defined in RFC-2246.
     *
     * @param message Compression method in encoded form
     */
    public CompressionMethod(final byte[] message) {
        this.decode(message, false);
    }

    /*
     * @return The compression method of this message
     */
    public List<ECompressionMethod> getCompressionMethods() {
        return methods;
    }

    /**
     * @return the raw method "id" bytes, irrespective of whether a corresponding
     * ECompressionMethod exists
     */
    public List<Id> getRawMethods() {
        return rawMethods;
    }

    /**
     * Set the compression methods of this message.
     *
     * @param methods The compression methods to be used for this message
     */
    public final void setMethods(final ECompressionMethod[] methods) {
        setMethods(Arrays.asList(methods));
    }

    /**
     * Set the compression methods of this message.
     *
     * @param methods The compression methods to be used for this message
     */
    public final void setMethods(final List<ECompressionMethod> methods) {
        setMethods(methods, true);
    }

    /**
     * @param setRaw Iff false, don't overwrite the rawMethods field
     */
    private void setMethods(final List<ECompressionMethod> methods, boolean setRaw) {
        if (methods == null) {
            throw new IllegalArgumentException("Compression methods must not be null!");
        }

        this.methods = new ArrayList<>(methods);
        if(setRaw) {
            this.rawMethods = new ArrayList<>(methods.size());
            for (ECompressionMethod method : methods) {
                rawMethods.add(new Id(method.getId()));
            }
        }
    }

    /**
     * {@inheritDoc}
     *
     * Method parameter will be ignored - no support for chained encoding.
     */
    @Override
    public byte[] encode(final boolean chained) {
        byte[] tmp = new byte[LENGTH_LENGTH_FIELD + methods.size()];
        int index = 0;
        tmp[0] = ((Integer) methods.size()).byteValue();

        // since ECompressionMethod is not encoded as array, don't do encode() or such
        for(ECompressionMethod method : methods) {
            ++index;
            tmp[index] = method.getId();
        }

        return tmp;
    }

    /**
     * {@inheritDoc}
     *
     * Method parameter will be ignored - no support for chained decoding.
     */
    public void decode(final byte[] message, final boolean chained) {
        this.rawMethods.clear();
        final int methodsLength;
        List<ECompressionMethod> newMethods;

        // deep copy
        final byte[] methods = new byte[message.length];
        System.arraycopy(message, 0, methods, 0, methods.length);

        // check size
        if (methods.length < LENGTH_MINIMUM_ENCODED) {
            throw new IllegalArgumentException("Compression methods record too short.");
        }

        methodsLength = extractLength(methods, 0, LENGTH_LENGTH_FIELD);

        newMethods = new ArrayList<>();
        for(int i = LENGTH_LENGTH_FIELD; i < methods.length; ++i) {
            ECompressionMethod method = null;
            rawMethods.add(new Id(methods[i]));
            try {
                method = ECompressionMethod.getCompressionMethod(methods[i]);
            } catch(IllegalArgumentException e) {
                logger.debug(e);
            }
            newMethods.add(method);
        }
        setMethods(newMethods, false);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o)
            return true;
        if (o == null || getClass() != o.getClass())
            return false;

        CompressionMethod that = (CompressionMethod) o;

        if (methods != null ?
                !methods.equals(that.methods) :
                that.methods != null)
            return false;

        return true;
    }

    @Override
    public int hashCode() {
        return methods != null ? methods.hashCode() : 0;
    }

}
