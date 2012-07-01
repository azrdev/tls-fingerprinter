package de.rub.nds.virtualnetworklayer.util.formatter;

import java.lang.reflect.Method;
import java.lang.reflect.Modifier;

/**
 * @author Marco Faltermeier <faltermeier@me.com>
 */
public abstract class StringFormatter {

    public static String toString(Object object) {
        Class clazz = object.getClass();
        StringBuffer buffer = new StringBuffer(object.toString() + ":\n");

        for (Method method : clazz.getDeclaredMethods()) {
            if (method.getName().startsWith("get") && method.getParameterTypes().length == 0
                    && Modifier.isPublic(method.getModifiers())) {
                try {
                    Object field = method.invoke(object, null);

                    if (method.isAnnotationPresent(Format.class)) {
                        Format format = method.getAnnotation(Format.class);
                        Method formatter = format.with().getMethod("toString", method.getReturnType());
                        field = formatter.invoke(null, field);
                    }

                    if (field.equals("")) {
                        field = "<empty>";
                    }

                    buffer.append("- " + method.getName().substring(3) + ": " + field + "\n");
                } catch (Exception e) {

                }
            }
        }

        return buffer.toString();
    }

    public static String firstToUppercase(String string) {
        return string.substring(0, 1).toUpperCase() + string.substring(1);
    }
}
