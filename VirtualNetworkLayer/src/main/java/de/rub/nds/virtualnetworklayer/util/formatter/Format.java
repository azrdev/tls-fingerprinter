package de.rub.nds.virtualnetworklayer.util.formatter;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Identifies formattable header fields.
 *
 * @author Marco Faltermeier <faltermeier@me.com>
 * @see de.rub.nds.virtualnetworklayer.packet.header.Header
 */
@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.METHOD)
public @interface Format {
    public Class<? extends StringFormatter> with();
}
