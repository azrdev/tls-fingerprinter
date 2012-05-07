/*
 * Copyright 2011 Sec2 Consortium
 * 
 * This source code is part of the "Sec2" project and as this remains property
 * of the project partners. Content and concepts have to be treated as
 * CONFIDENTIAL. Publication or partly disclosure without explicit written
 * permission is prohibited.
 * For details on "Sec2" and its contributors visit
 * 
 *        http://www.sec2.org
 */

package de.rub.nds.research.ssl.stack.protocols.handshake.datatypes;

/**
 * ExchangeKeys Interface as used in the ClientKeyExchange message of SSL/TLS
 * @author  Christopher Meyer - christopher.meyer@rub.de
 * @version 0.1
 * Jan 17, 2012
 */
public interface IExchangeKeys {
    // a marker interface to support generics for the ClientKeyExchange message
    
    /**
     * {@inheritDoc}
     */
    void decode(final byte[] message, final boolean chained);
    
    /**
     * {@inheritDoc}
     */
    byte[] encode(final boolean chained);
}
