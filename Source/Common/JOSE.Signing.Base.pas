{******************************************************************************}
{                                                                              }
{  Delphi JOSE-JWT Library                                                     }
{  Copyright (c) 2015 Paolo Rossi                                              }
{  https://github.com/paolo-rossi/delphi-jose-jwt                              }
{                                                                              }
{  Licensed under the MIT license                                              }
{                                                                              }
{******************************************************************************}

unit JOSE.Signing.Base;

{$I ..\JOSE.inc}

interface

{$IFDEF RSA_SIGNING}

uses
  System.SysUtils,
  JOSE.Crypto.Algorithms;

type
  ESignException = class(Exception);

  TSigningBase = class
  public
    class function PublicKeyFromCertificate(const ACertificate: TBytes): TBytes;
    class function VerifyCertificate(const ACertificate: TBytes; AExpected: TJOSECertificatePublicKey): Boolean;
  end;

{$ENDIF}

implementation

{$IFDEF RSA_SIGNING}

uses
  JOSE.Providers;

class function TSigningBase.PublicKeyFromCertificate(const ACertificate: TBytes): TBytes;
begin
  Result := TJOSEProviders.Certificate.PublicKeyFromCertificate(ACertificate);
end;

class function TSigningBase.VerifyCertificate(const ACertificate: TBytes; AExpected: TJOSECertificatePublicKey): Boolean;
begin
  Result := TJOSEProviders.Certificate.VerifyCertificate(ACertificate, AExpected);
end;

{$ENDIF}

end.
