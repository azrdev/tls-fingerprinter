package de.rub.nds.ssl.analyzer.vnl.gui;

import com.google.common.html.HtmlEscapers;

import javax.swing.*;
import java.awt.Point;
import java.awt.event.MouseEvent;
import java.util.Objects;

/**
 * A {@link JTable} with a tooltip that shows the (full) content of the hovered cell,
 * also honoring line breaks
 *
 * @author jBiegert azrdev@qrdn.de
 */
public class ToolTippingTable extends JTable {
    @Override
    public String getToolTipText(MouseEvent event) {
        final Point p = event.getPoint();
        final int rowIndex = rowAtPoint(p);
        final int colIndex = columnAtPoint(p);
        try {
            final String raw = Objects.toString(getValueAt(rowIndex, colIndex));
            // honor newlines: make the tooltip display as html & use <br>
            return "<html>" +
                    HtmlEscapers.htmlEscaper().escape(raw).replace("\n", "<br>") +
                    "</html>";
        } catch(ArrayIndexOutOfBoundsException|NullPointerException e) {
            return "";
        }
    }
}
