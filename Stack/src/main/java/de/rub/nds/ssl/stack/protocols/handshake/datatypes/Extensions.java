package de.rub.nds.ssl.stack.protocols.handshake.datatypes;

import de.rub.nds.ssl.stack.Utility;
import de.rub.nds.ssl.stack.exceptions.UnknownTLSExtensionException;
import de.rub.nds.ssl.stack.protocols.commons.APubliclySerializable;
import de.rub.nds.ssl.stack.protocols.handshake.extensions.AExtension;
import de.rub.nds.ssl.stack.protocols.handshake.extensions.datatypes.EExtensionType;
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
    private List<AExtension> extensions;

    /**
     * Initializes an extensions object as defined in RFC-2246. No extensions
     * are added by default at construction time.
     */
    public Extensions() {
        this.extensions = new ArrayList<>(5);
    }

    /**
     * Initializes an extension object as defined in RFC-2246.
     *
     * @param extensionsValue Extensions in encoded form
     */
    public Extensions(final byte[] extensionsValue) {
        this.extensions = new ArrayList<>(5);
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
        // refill, deep copy list, but not extensions itself!
        this.extensions.addAll(this.extensions);
    }

    /**
     * Add an extension to the extension list.
     *
     * @param extension Extension to be added
     */
    public void addExtension(final AExtension extension) {
        this.extensions.add(extension);
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
            System.arraycopy(tmpBytes, 0, extensionBytes, pointer,
                    tmpBytes.length);
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
	        AExtension tmpExtension;
	        byte[] tmp;

            // 1. extract extension type
            tmp = new byte[EExtensionType.LENGTH_ENCODED];
            System.arraycopy(payloadCopy, pointer, tmp, 0, tmp.length);
	        try {
		        extensionType = EExtensionType.getExtension(tmp);
	        } catch (UnknownTLSExtensionException ex) {
		        System.out.println("Unknown extension: " + Utility.bytesIdToHex(tmp));
		        //XXX: log
	        }

            // 2. determine extension length
            extractedLength = extractLength(payloadCopy,
                    pointer + EExtensionType.LENGTH_ENCODED,
                    AExtension.LENGTH_BYTES);

            // 3. extract message
            if (payloadCopy.length < pointer + extractedLength) {
                throw new IllegalArgumentException("Extensions payload too short.");
            }
            tmp = new byte[extractedLength + AExtension.LENGTH_MINIMUM_ENCODED];
            System.arraycopy(payloadCopy, pointer, tmp, 0, tmp.length);
            pointer += tmp.length;

            // 4. add message to message list
	        if(extensionType == null) {
	            //XXX: logging?
		        continue;
	        }
            try {
                tmpExtension = delegateDecoding(extensionType, tmp);
                extensions.add(tmpExtension);
            } catch(IllegalArgumentException ex) {
                System.out.println("Could not decode extension: " + ex);
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
        } catch (InvocationTargetException |
                SecurityException |
                NoSuchMethodException |
                InstantiationException |
                IllegalArgumentException |
                IllegalAccessException ex) {
            throw new IllegalArgumentException(
                    "Problems during decoding delegation for "
                    + type + " and class " + implClass.getCanonicalName(), ex); //XXX: hides details of ex
        }
        return result;
    }
}
