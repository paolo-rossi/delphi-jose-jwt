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

