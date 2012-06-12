package de.rub.nds.virtualnetworklayer.p0f;

import de.rub.nds.virtualnetworklayer.util.IniTokenizer;

import java.io.FileNotFoundException;
import java.util.*;
import java.util.logging.Logger;

/**
 * p0f.fp layout:
 * <p/>
 * classes              allowed classes in label
 * modules              n modules
 * - mtu
 * group
 * label
 * signature   single signature only
 * - tcp:request
 * group
 * label
 * signature   n signatures
 * ...
 * - tcp:response
 * group
 * label
 * signature   n signatures
 * ...
 *
 * @see Module
 * @see Group
 * @see Label
 * @see de.rub.nds.virtualnetworklayer.p0f.signature.MTUSignature
 * @see de.rub.nds.virtualnetworklayer.p0f.signature.TCPSignature
 */
public class P0fFile {
    private final static Logger logger = Logger.getLogger(P0fFile.class.getName());

    private Set<String> classes;
    private String filePath;
    private HashMap<String, Group> groups = new HashMap<String, Group>();

    private Module actualModule;
    private Group actualGroup;
    private int signatureCount;

    public P0fFile(String filePath) throws FileNotFoundException {
        this.filePath = filePath;
        actualGroup = new Group();
        IniTokenizer tokenizer = new IniTokenizer(filePath);

        IniTokenizer.Token token;
        while ((token = tokenizer.next()) != null) {
            if (token instanceof IniTokenizer.Property) {
                readProperty((IniTokenizer.Property) token);

            } else if (token instanceof IniTokenizer.Section) {
                actualModule = new Module((IniTokenizer.Section) token);
            }
        }
    }

    private void readProperty(IniTokenizer.Property property) {
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
                logger.warning("label class " + label.getLabelClass() + " not registered");
            }

        } else if (key.equals("sig")) {

            actualGroup.addSignature(property.getValue(), actualModule);
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
