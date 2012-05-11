package de.rub.nds.research.ssl.stack.protocols.handshake;

import java.util.Observable;

public class MessageObservable extends Observable {

    private static volatile MessageObservable observable;

    private MessageObservable() {
    }

    public static MessageObservable getInstance() {
        if (observable == null) {
            observable = new MessageObservable();
        }
        return observable;
    }

    public void statusChanged(AHandshakeRecord message) {
        setChanged();
        notifyObservers(message);
    }
}
