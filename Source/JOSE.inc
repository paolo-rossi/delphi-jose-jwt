{$DEFINE RSA_SIGNING}

{$IF CompilerVersion >= 24}
  {$LEGACYIFEND ON}
{$IFEND}

// disable RSA_Signing for XE6 version and lower
{$IF CompilerVersion <= 27}
  {$UNDEF RSA_SIGNING}
{$IFEND}

// disable RSA_Signing for iOSDevice
{$IFDEF IOS}
  {$UNDEF RSA_SIGNING}
{$ENDIF}

{$IF CompilerVersion >= 27} // XE6
  {$DEFINE HAS_SYSTEM_JSON}       // New System.JSON unit
{$IFEND}

{$IF CompilerVersion >= 28} // XE8
  {$DEFINE HAS_NEW_ARRAY}         // New dynamic array syntax
  {$DEFINE HAS_NET_ENCODING}      // System.NetEncoding unit introduced
  {$DEFINE HAS_SYSTEM_THREADING}  // System.Threading unit introduced
{$IFEND}

{$IF CompilerVersion >= 30} // Delphi 10.0 Seattle
  {$DEFINE HAS_JSON_BOOL}         // TJSONBool class introduced
  {$DEFINE HAS_HMAC_HASH}         // Unit Hashing introduced
  {$DEFINE HAS_GENERIC_CREATE}    // Generic constraint
{$IFEND}

{$IF CompilerVersion >= 31} // Delphi 10.1 Berlin
  {$DEFINE HAS_UTF8CHAR}
  {$DEFINE NO_ARRAY_HELPER_BUG}
{$IFEND}

{$IF CompilerVersion >= 33} // Delphi 10.3 Rio
  {$DEFINE HAS_NEW_PIDS}
  {$DEFINE HAS_NEW_JSON}
  {$DEFINE HAS_VAR_INLINE}
{$IFEND}

{$IF CompilerVersion >= 34} // Delphi 10.4 Sydney
  {$DEFINE HAS_MRECORDS}
{$IFEND}



