package de.rub.nds.virtualnetworklayer.p0f;

import de.rub.nds.virtualnetworklayer.fingerprint.Fingerprint;
import de.rub.nds.virtualnetworklayer.p0f.signature.MTUSignature;
import de.rub.nds.virtualnetworklayer.p0f.signature.TCPSignature;
import de.rub.nds.virtualnetworklayer.util.Signature;

import java.util.ArrayList;
import java.util.List;

public class Group {
    private Label label;
    private List<Signature> signatures;

    public Group() {
        signatures = new ArrayList<Signature>();
    }

    public Label getLabel() {
        return label;
    }

    public Label setLabel(String line) {
        this.label = new Label(line);

        return label;
    }

    public List<Signature> getSignatures() {
        return signatures;
    }

    public int getSignatureCount() {
        return signatures.size();
    }

    public Fingerprint.Signature addSignature(String line, Module module) {
        Fingerprint.Signature signature;

        if (line.contains(":")) {
            signature = new TCPSignature(line, module.getDirection());
        } else {
            signature = new MTUSignature(line);
        }

        signatures.add(signature);

        return signature;
    }

    public void merge(Group group) {
        for (Signature signature : group.getSignatures()) {
            signatures.add(signature);
        }
    }
}
