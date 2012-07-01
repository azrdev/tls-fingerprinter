package de.rub.nds.virtualnetworklayer.util.formatter;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.TYPE)
public @interface Protocol {
    public static enum Osi {
        Physical,
        DataLink,
        Network,
        Transport,
        Session,
        Presentation,
        Application
    }

    public Osi layer();
}
