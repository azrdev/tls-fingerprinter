package de.rub.nds.ssl.analyzer.vnl.gui.components;

import com.google.common.html.HtmlEscapers;

import javax.swing.*;
import javax.swing.tree.DefaultTreeCellRenderer;
import java.awt.*;
import java.util.Objects;

/**
 * A {@link DefaultTreeCellRenderer} showing tooltips with the currently hovered node,
 * also honoring newlines.
 *
 * @author jBiegert azrdev@qrdn.de
 */
public class TooltippingTreeRenderer extends DefaultTreeCellRenderer {
    @Override
    public Component getTreeCellRendererComponent(JTree tree, Object value, boolean sel, boolean expanded, boolean leaf, int row, boolean hasFocus) {
        super.getTreeCellRendererComponent(tree, value, sel, expanded, leaf, row, hasFocus);

        try {
            final String raw = Objects.toString(value);
            // honor newlines: make the tooltip display as html & use <br>
            setToolTipText("<html>" +
                    HtmlEscapers.htmlEscaper().escape(raw).replace("\n", "<br>") +
                    "</html>");
        } catch(IndexOutOfBoundsException|NullPointerException ignored) {}

        return this;
    }
}
