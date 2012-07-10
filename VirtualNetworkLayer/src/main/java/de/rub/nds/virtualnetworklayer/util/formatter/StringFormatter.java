package de.rub.nds.virtualnetworklayer.util.formatter;

import java.lang.reflect.Method;
import java.lang.reflect.Modifier;

/**
 * String formatter uses {@link sun.reflect.Reflection} for printing all <i>getters</i> of an {@link Object}.
 * Annotate with {@link Format} for custom formatting.
 * A Formatter has to subclass {@link StringFormatter} and provide a
 * static {@code toString()} method, whose signature is the same as the return value type of the annotated <i>getter</i>.
 *
 * @author Marco Faltermeier <faltermeier@me.com>
 * @see Format
 */
public abstract class StringFormatter {

    public static String toString(Object object) {
        return toString(object, object.toString() + ":\n");
    }

    public static String toString(Object object, String prepend) {
        Class clazz = object.getClass();
        StringBuffer buffer = new StringBuffer(prepend);

        for (Method method : clazz.getDeclaredMethods()) {
            if (method.getName().startsWith("get") && method.getParameterTypes().length == 0
                    && Modifier.isPublic(method.getModifiers())) {
                try {
                    Object field = method.invoke(object, null);

                    if (field != null) {
                        if (method.isAnnotationPresent(Format.class)) {
                            Format format = method.getAnnotation(Format.class);

                            if (format.with() == StringFormatter.class) {
                                String nestedObject = StringFormatter.toString(field, "\n");
                                buffer.append("+ ").append(method.getName().substring(3) + ":");
                                buffer.append(StringFormatter.toString(field, "\n"));
                                continue;

                            } else {
                                Method formatter = format.with().getMethod("toString", method.getReturnType());
                                field = formatter.invoke(null, field);
                            }
                        }

                        buffer.append("- " + method.getName().substring(3) + ": " + field + "\n");
                    }

                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
        }

        return buffer.toString();
    }

    public static String firstToUppercase(String string) {
        return string.substring(0, 1).toUpperCase() + string.substring(1);
    }
}
