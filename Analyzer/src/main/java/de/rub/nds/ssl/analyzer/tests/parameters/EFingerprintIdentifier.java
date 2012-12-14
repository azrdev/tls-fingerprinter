package de.rub.nds.ssl.analyzer.tests.parameters;

/**
 * Identifiers for tests.
 * @author Eugen Weiss - eugen.weiss@ruhr-uni-bochum.de
 * @version 0.1
 * Aug 2, 2012
 */
public enum EFingerprintIdentifier {	
	ClientHello,
	CHRecordHeader,
	CHHandshakeHeader,
	ClientKeyExchange,
	CKERecordHeader,
	CKEHandshakeHeader,
	ChangeCipherSpec,
	CCSRecordHeader,
	Finished,
	FinRecordHeader,
	FinHandshakeHeader,
	CheckHandEnum,
	BleichenbacherAttack
}
