package de.rub.nds.virtualnetworklayer.p0f;

import de.rub.nds.virtualnetworklayer.fingerprint.Fingerprint;
import de.rub.nds.virtualnetworklayer.util.IniTokenizer;
import org.apache.log4j.Logger;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.InputStream;
import java.util.*;

/**
 * p0f.fp layout:
 * <pre>
 * classes              allowed classes in label
 *
 * modules              n modules
 *  - mtu
 *      group
 *      label
 *      signature       single signature only
 *
 *  - tcp:request
 *      group
 *          label
 *          signature   n signatures
 *
 *  - tcp:response
 *      group
 *          label
 *          signature   n signatures
 * </pre>
 *
 * @author Marco Faltermeier <faltermeier@me.com>
 * @see Module
 * @see Group
 * @see Label
 * @see de.rub.nds.virtualnetworklayer.p0f.signature.MTUSignature
 * @see de.rub.nds.virtualnetworklayer.p0f.signature.TCPSignature
 * @see IniTokenizer
 */
public class P0fFile {
    public final static InputStream Embedded = P0fFile.class.getResourceAsStream("p0f.fp");

    private final static Logger logger = Logger.getLogger(P0fFile.class.getName());

    private Set<String> classes;
    private String filePath;
    private Map<String, Group> groups = new LinkedHashMap<String, Group>();

    private Module actualModule;
    private Group actualGroup;
    private int signatureCount;

    public P0fFile(File file) throws FileNotFoundException {
        this(new FileInputStream(file));
    }

    public P0fFile(InputStream inputStream) {
        actualGroup = new Group();
        IniTokenizer tokenizer = new IniTokenizer(inputStream);

        IniTokenizer.Token token;
        while ((token = tokenizer.next()) != null) {
            if (token instanceof IniTokenizer.Token.Property) {
                readProperty((IniTokenizer.Token.Property) token);

            } else if (token instanceof IniTokenizer.Token.Section) {
                actualModule = new Module((IniTokenizer.Token.Section) token);
            }
        }

        logger.info(getSignatureCount() + " signatures read.");
    }

    private void readProperty(IniTokenizer.Token.Property property) {
        String key = property.getKey();

        if (key.equals("classes")) {
            String[] parts = property.getValue().split(",");
            classes = new HashSet<String>(Arrays.asList(parts));
        } else if (key.equals("label")) {
            if (actualGroup.getSignatureCount() > 0) {
                addGroup(actualGroup);
            }

            actualGroup = new Group();
            Label label = actualGroup.setLabel(property.getValue());
            if (label.isOSSpecific() && !classes.contains(label.getLabelClass())) {
                logger.warn("label class " + label.getLabelClass() + " not registered");
            }

        } else if (key.equals("sig")) {
            Fingerprint.Signature signature = actualGroup.addSignature(property.getValue(), actualModule);

            signatureCount++;
        }
    }

    private void addGroup(Group group) {
        if (groups.containsKey(group.getLabel().toString())) {
            Group existingGroup = groups.get(group.getLabel().toString());
            existingGroup.merge(group);
        } else {
            groups.put(actualGroup.getLabel().toString(), actualGroup);
        }
    }

    public Collection<Group> getGroups() {
        return groups.values();
    }

    public Set<String> getClasses() {
        return classes;
    }

    public int getSignatureCount() {
        return signatureCount;
    }

}
