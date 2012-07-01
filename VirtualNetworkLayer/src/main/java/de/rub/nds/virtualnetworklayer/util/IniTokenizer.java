package de.rub.nds.virtualnetworklayer.util;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;

/**
 * @author Marco Faltermeier <faltermeier@me.com>
 */
public class IniTokenizer {

    public interface Token {

    }

    public class Property implements Token {
        private String key;
        private String value;

        public Property(String line) {
            String[] array = line.split("=");
            key = array[0].trim();
            value = array[1].trim();
        }

        public String getKey() {
            return key;
        }

        public String getValue() {
            return value;
        }

    }

    public class Section implements Token {
        private String name;

        public Section(String line) {
            name = line.replace("[", "").replace("]", "");
        }

        public String getName() {
            return name;
        }
    }

    private InputStream inputStream;
    private BufferedReader reader;


    public IniTokenizer(InputStream inputStream) {
        reader = new BufferedReader(new InputStreamReader(inputStream));
    }


    public Token next() {
        String line = "";
        try {
            while ((line = reader.readLine()) != null) {
                if (!line.startsWith(";") || line.isEmpty()) {
                    Token token = readLine(line);
                    if (token != null) {
                        return token;
                    }
                }
            }

        } catch (IOException e) {
        }

        return null;
    }

    private Token readLine(String line) {
        if (line.startsWith("[")) {
            return new Section(line);
        } else if (line.contains("=")) {
            return new Property(line);
        }

        return null;
    }
}
