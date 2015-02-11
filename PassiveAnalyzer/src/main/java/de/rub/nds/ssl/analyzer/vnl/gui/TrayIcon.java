package de.rub.nds.ssl.analyzer.vnl.gui;

import org.apache.log4j.Logger;

import javax.imageio.ImageIO;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.image.BufferedImage;
import java.io.IOException;

/**
 * @author jBiegert azrdev@qrdn.de
 */
public class TrayIcon {
    private static final Logger logger = Logger.getLogger(TrayIcon.class);

    private java.awt.TrayIcon icon;

    private BufferedImage image;

    public TrayIcon() {
        try {
            image = ImageIO.read(TrayIcon.class.getResourceAsStream("logo.png"));
        } catch (IOException|IllegalArgumentException e) {
            logger.warn("logo.png not found: " + e);
            image = new BufferedImage(32, 32, BufferedImage.TYPE_INT_RGB);
        }

        icon = new java.awt.TrayIcon(image);
        icon.setImageAutoSize(true);
        icon.setPopupMenu(createMenu());

        try {
            SystemTray.getSystemTray().add(icon);
        } catch (UnsupportedOperationException e) {
            logger.warn("Error getting SystemTray: " + e);
        } catch (AWTException e) {
            logger.warn("Error adding TrayIcon: " + e);
        }
    }

    private static PopupMenu createMenu() {
        final PopupMenu menu = new PopupMenu();

        final MenuItem item = new MenuItem("Quit");
        item.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
                logger.info("Request to Quit application.");
                System.exit(0);
            }
        });
        menu.add(item);

        return menu;
    }

    public void displayChangedAlert(final String host) {
        icon.displayMessage(
                "Fingerprint changed for " + host,
                host + " changed its fingerprint",
                java.awt.TrayIcon.MessageType.WARNING);
    }
}
