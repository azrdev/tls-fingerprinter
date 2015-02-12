parser grammar FingerprintSaveFileParser ;
options {
  tokenVocab=FingerprintSaveFileLexer;
}

file : CRLF* ( record CRLF+ )* record? ;

record : sessionIdLine signatureLine+ ;
sessionIdLine : sessionId CRLF ;
signatureLine : (signatureCH | signatureSH | signatureHS | signatureTCP | signatureMTU) WS* CRLF ;

signatureCH : TypeCH signs ;
signatureSH : TypeSH signs ;
signatureHS : TypeHS signs ;
signatureTCP : TypeTCP signs ;
signatureMTU : TypeMTU signs ;

sessionId : host WS* ;

signs : sign ( COLON sign )* ;
sign : Word | ;
host : Word ;
