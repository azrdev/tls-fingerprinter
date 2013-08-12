package de.rub.nds.ssl.stack.workflows.response;

import de.rub.nds.ssl.stack.ECUtility;
import de.rub.nds.ssl.stack.Utility;
import de.rub.nds.ssl.stack.protocols.commons.KeyExchangeParams;
import de.rub.nds.ssl.stack.protocols.handshake.AHandshakeRecord;
import de.rub.nds.ssl.stack.protocols.handshake.Certificate;
import de.rub.nds.ssl.stack.protocols.handshake.datatypes.ASN1Certificate;
import de.rub.nds.ssl.stack.protocols.handshake.extensions.datatypes.ECCurve;
import de.rub.nds.ssl.stack.protocols.handshake.extensions.datatypes.ECParameters;
import de.rub.nds.ssl.stack.protocols.handshake.extensions.datatypes.ECPoint;
import de.rub.nds.ssl.stack.protocols.handshake.extensions.datatypes.EECCurveType;
import de.rub.nds.ssl.stack.protocols.handshake.extensions.datatypes.EECPointFormat;
import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECField;
import java.security.spec.ECFieldF2m;
import java.security.spec.ECFieldFp;
import java.security.spec.ECParameterSpec;
import java.security.spec.EllipticCurve;

public class CertificateHandler implements IHandshakeStates {

    private Certificate certificate;

    public CertificateHandler() {
    }

    @Override
    public void handleResponse(AHandshakeRecord handRecord) {
        certificate = (Certificate) handRecord;
        this.extractPublicKey();
    }

    /**
     * Extracts the public key from the Certificate.
     *
     * @return Public key of the server certificate
     */
    public void extractPublicKey() {
        PublicKey pk = null;
        KeyExchangeParams keyParams = KeyExchangeParams.getInstance();
        for (ASN1Certificate certs : certificate.getCertificates().
                getCertificates()) {
            ByteArrayInputStream inCert = new ByteArrayInputStream(certs.
                    getCertificate());
            try {
                CertificateFactory cf = CertificateFactory.getInstance("X.509");
                java.security.cert.Certificate cert = cf.generateCertificate(
                        inCert);
                pk = cert.getPublicKey();
                keyParams.setPublicKey(pk);

// TODO extract curve parameters                
                if (pk instanceof ECPublicKey) {
                    ECPublicKey ecPK = (ECPublicKey) pk;
                    ECParameterSpec paramSpec = ecPK.getParams();
                    if (paramSpec != null) {
                        ECParameters curveParameters = new ECParameters();
                        byte[] co = Utility.intToBytes(paramSpec.getCofactor());
                        curveParameters.setCofactor(co);
                        curveParameters.setOrder(
                                paramSpec.getOrder().toByteArray());

                        java.security.spec.ECPoint generator = paramSpec.
                                getGenerator();
                        byte[] encodedGenerator = ECUtility.encodeX9_62(
                                generator.getAffineX().toByteArray(), 
                                generator.getAffineY().toByteArray(),
                                EECPointFormat.UNCOMPRESSED);
                                
                        ECPoint generatorPoint = new ECPoint();
                        generatorPoint.setPoint(encodedGenerator);
                        curveParameters.setBase(generatorPoint);

                        EllipticCurve curve = paramSpec.getCurve();
                        ECCurve ecCurve = new ECCurve();
                        byte[] a = curve.getA().toByteArray();
                        byte[] b = curve.getB().toByteArray();
                        ecCurve.setA(a);
                        ecCurve.setB(b);
                        curveParameters.setCurve(ecCurve);
                        
                        ECField field = curve.getField();
                        if (field != null) {
                            if (field instanceof ECFieldF2m) {
                                int m = ((ECFieldF2m) field).getM();
                                curveParameters.setCurveType(
                                        EECCurveType.EXPLICIT_CHAR2);
                                curveParameters.setM((short) m);
                                
                                // TODO extract K | K1,K2,K3
                            } else {
                                BigInteger p = ((ECFieldFp) field).getP();
                                curveParameters.setCurveType(
                                        EECCurveType.EXPLICIT_PRIME);
                                curveParameters.setPrimeP(p.toByteArray());
                            }
                        }
                        
                        // TODO named curve identifizieren!

                        keyParams.setECDHParameters(curveParameters);
                    }
                }
            } catch (CertificateException e) {
                e.printStackTrace();
            }
        }
    }
}
