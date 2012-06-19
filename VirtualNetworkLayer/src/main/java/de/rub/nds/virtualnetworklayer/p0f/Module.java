package de.rub.nds.virtualnetworklayer.p0f;

import de.rub.nds.virtualnetworklayer.packet.Packet;
import de.rub.nds.virtualnetworklayer.util.IniTokenizer;
import de.rub.nds.virtualnetworklayer.util.Util;

/**
 * Section format: [module:direction]
 *
 * @see de.rub.nds.virtualnetworklayer.util.IniTokenizer.Section
 */
public class Module {
    public enum Direction {
        Request("request", Packet.Direction.Request),
        Response("response", Packet.Direction.Response);

        private String value;
        private Packet.Direction mapping;

        private Direction(String value, Packet.Direction mapping) {
            this.value = value;
            this.mapping = mapping;
        }

        public Packet.Direction getMapping() {
            return mapping;
        }

        @Override
        public String toString() {
            return value;
        }
    }

    private String name;
    private Direction direction;

    public Module(IniTokenizer.Section section) {
        if (section.getName().contains(":")) {
            String[] parts = section.getName().split(":");
            name = parts[0];
            direction = Util.readEnum(Direction.class, parts[1]);
        } else {
            name = section.getName();
        }
    }

    public Direction getDirection() {
        return direction;
    }
}