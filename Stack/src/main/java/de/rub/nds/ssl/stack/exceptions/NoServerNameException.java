package de.rub.nds.ssl.stack.exceptions;

/**
 * @author jBiegert azrdev@qrdn.de
 */
public class NoServerNameException extends Exception {
    public NoServerNameException() {
        super("The ClientHello did not contain a ServerName");
    }
}
