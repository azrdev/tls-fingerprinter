package de.rub.nds.ssl.stack.protocols.handshake.datatypes;

import de.rub.nds.ssl.stack.Utility;
import de.rub.nds.ssl.stack.exceptions.UnknownTLSExtensionException;
import de.rub.nds.ssl.stack.protocols.commons.APubliclySerializable;
import de.rub.nds.ssl.stack.protocols.commons.Id;
import de.rub.nds.ssl.stack.protocols.handshake.extensions.AExtension;
import de.rub.nds.ssl.stack.protocols.handshake.extensions.datatypes.EExtensionType;
import org.apache.log4j.Logger;

import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.List;

/**
 * Extensions part - as defined in RFC-3546.
 *
 * @author Christopher Meyer - christopher.meyer@rub.de
 * @version 0.1
 *
 * Feb 4, 2013
 */
public final class Extensions extends APubliclySerializable {

    private Logger logger = Logger.getLogger(getClass());

    /**
     * Length of the length field.
     */
    private static final int LENGTH_LENGTH_FIELD = 2;
    /**
     * Minimum length of the encoded form.
     */
    public static final int LENGTH_MINIMUM_ENCODED = LENGTH_LENGTH_FIELD;
    /**
     * List of all extensions of this object.
     */
    private List<AExtension> extensions = new ArrayList<>(5);

    /**
     * "type" bytes of each extension, irrespective of whether the corresponding
     * {@link EExtensionType} exists or is implemented
     */
    private List<Id> rawExtensionTypes = new ArrayList<>(5);

    /**
     * Initializes an extensions object as defined in RFC-2246. No extensions
     * are added by default at construction time.
     */
    public Extensions() {
    }

    /**
     * Initializes an extension object as defined in RFC-2246.
     *
     * @param extensionsValue Extensions in encoded form
     */
    public Extensions(final byte[] extensionsValue) {
        this.decode(extensionsValue, false);
    }

    /**
     * Get the extensions.
     *
     * @return The extensions of this message
     */
    public AExtension[] getExtensions() {
        // deep copy
        AExtension[] tmp = new AExtension[extensions.size()];
        extensions.toArray(tmp);

        return tmp;
    }

    /**
     * @return The raw "type" bytes of all extensions
     */
    public List<Id> getRawExtensionTypes() {
        return rawExtensionTypes;
    }

    /**
     * Set the extensions.
     *
     * @param extensionsValue The extensions to be used
     */
    public void setExtensions(final List<AExtension> extensionsValue) {
        if (extensionsValue == null) {
            throw new IllegalArgumentException("Extensions must not be null!");
        }

        // new objects keep the array clean and small, Mr. Proper will be proud!
        this.extensions = new ArrayList<>(extensionsValue.size());
        this.rawExtensionTypes = new ArrayList<>(extensionsValue.size());
        // refill, deep copy list, but not extensions itself!
        this.extensions.addAll(extensionsValue);

        for(AExtension ex : extensionsValue) {
            rawExtensionTypes.add(new Id(ex.getExtensionType().getId()));
        }
    }

    /**
     * Add an extension to the extension list.
     *
     * @param extension Extension to be added
     */
    public void addExtension(final AExtension extension) {
        this.extensions.add(extension);
        rawExtensionTypes.add(new Id(extension.getExtensionType().getId()));
    }

    /**
     * {@inheritDoc} Extensions representation 2 + x*2 bytes for x extensions
     * suites.
     *
     * Method parameter will be ignored - no support for chained encoding.
     */
    @Override
    public byte[] encode(final boolean chained) {
        int pointer = 0;
        List<byte[]> encodedExtensions = new ArrayList<>(extensions.size());
        byte[] tmp;
        for (AExtension tmpExtension : extensions) {
            tmp = tmpExtension.encode(false);
            encodedExtensions.add(tmp);
            pointer += tmp.length;
        }

        byte[] extensionBytes = new byte[LENGTH_LENGTH_FIELD + pointer];

        // length
        tmp = buildLength(pointer, LENGTH_LENGTH_FIELD);
        pointer = 0;
        System.arraycopy(tmp, 0, extensionBytes, pointer, tmp.length);
        pointer += tmp.length;

        for (byte[] tmpBytes : encodedExtensions) {
            System.arraycopy(tmpBytes, 0, extensionBytes, pointer, tmpBytes.length);
            pointer += tmpBytes.length;
        }

        return extensionBytes;
    }

    /**
     * {@inheritDoc}
     *
     * Method parameter will be ignored - no support for chained decoding.
     */
    @Override
    public void decode(final byte[] message, final boolean chained) {
        int pointer;
        extensions.clear();
        rawExtensionTypes.clear();

        // deep copy
        final byte[] payloadCopy = new byte[message.length];
        System.arraycopy(message, 0, payloadCopy, 0, payloadCopy.length);

        // check size
        if (payloadCopy.length < LENGTH_MINIMUM_ENCODED) {
            throw new IllegalArgumentException("Extensions record too short.");
        }

        pointer = LENGTH_LENGTH_FIELD;
        while (payloadCopy.length >= pointer + AExtension.LENGTH_MINIMUM_ENCODED) {

            //TODO: this duplicates AExtension.decode()
	        int extractedLength;
	        EExtensionType extensionType = null;

            // 1. extract extension type
            byte[] typeBytes = new byte[EExtensionType.LENGTH_ENCODED];
            System.arraycopy(payloadCopy, pointer, typeBytes, 0, typeBytes.length);
            rawExtensionTypes.add(new Id(typeBytes));
	        try {
		        extensionType = EExtensionType.getExtension(typeBytes);
	        } catch (UnknownTLSExtensionException ex) {
		        logger.debug("Unknown extension: " + Utility.bytesIdToHex(typeBytes));
	        }

            // 2. determine extension length
            extractedLength = extractLength(payloadCopy,
                    pointer + EExtensionType.LENGTH_ENCODED,
                    AExtension.LENGTH_BYTES);

            // 3. extract message
            if (payloadCopy.length < pointer + extractedLength) {
                throw new IllegalArgumentException("Extensions payload too short.");
            }
            byte[] tmp = new byte[extractedLength + AExtension.LENGTH_MINIMUM_ENCODED];
            System.arraycopy(payloadCopy, pointer, tmp, 0, tmp.length);
            pointer += tmp.length;

            // 4. add message to message list
            if(extensionType != null) {
                try {
                    extensions.add(delegateDecoding(extensionType, tmp));
                } catch (IllegalArgumentException ex) {
                    logger.debug(ex);
                }
            }
        }
    }

    /**
     * Delegates decoding process to the implementing class.
     *
     * @param type Extension type
     * @param message Extension to decode
     * @return A decoded extension object
     */
    private AExtension delegateDecoding(final EExtensionType type,
            final byte[] message) {
        AExtension result = null;

        // invoke decode
        Class<AExtension> implClass = type.getImplementingClass();
        if (implClass == null) {
            throw new IllegalArgumentException("No suitable implementing class. "
                    + "Unsupported " + type);
        }

        try {
            Class[] parameter = new Class[1];
            parameter[0] = byte[].class;
            Constructor<AExtension> constructor = implClass.getConstructor(parameter);
            result = constructor.newInstance(message);

            // set extension type
            Method setExtensionType = AExtension.class
                    .getDeclaredMethod("setExtensionType",
                    EExtensionType.class);
            setExtensionType.setAccessible(true);
            setExtensionType.invoke(result, type);
        } catch (SecurityException |
                NoSuchMethodException |
                InstantiationException |
                IllegalArgumentException |
                IllegalAccessException ex) {
            throw new IllegalArgumentException("Could not decode extension: " + ex, ex);
        } catch(InvocationTargetException ex) {
            throw new IllegalArgumentException(ex.getCause());
        }
        return result;
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("Handshake extensions: {");
        sb.append("\nRaw types: ").append(rawExtensionTypes);
        for(AExtension ext : extensions) {
            sb.append("\n  ").append(ext.toString());
        }
        sb.append("\n}");

        return sb.toString();
    }

    @Override
    public int hashCode() {
        return extensions.hashCode();
    }
}
