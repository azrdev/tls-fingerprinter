lexer grammar FingerprintSaveFileLexer ;

TAB : [\t] ;

CRLF : '\r'? '\n' | '\r' ;

COLON : ':' ;

fragment TypePrefix : TAB ;
fragment TypeSuffix : 'Fingerprint'? ':'? WS* ;
TypeCH : TypePrefix 'ClientHello' TypeSuffix ;
TypeSH : TypePrefix 'ServerHello' TypeSuffix ;
TypeHS : TypePrefix 'Handshake' TypeSuffix ;
TypeTCP : TypePrefix 'Server' ('TCP' | 'Tcp') TypeSuffix ;
TypeMTU : TypePrefix 'Server' ('MTU' | 'Mtu') TypeSuffix ;

WS : [ \t]+  ;

fragment WordChar : ~[\t\n :] ;
Word : WordChar+ ;

COMMENT : '#' ~[\n]* CRLF  -> skip ;
