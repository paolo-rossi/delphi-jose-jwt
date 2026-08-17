{******************************************************************************}
{                                                                              }
{  Delphi JOSE-JWT Library                                                     }
{  Copyright (c) 2015 Paolo Rossi                                              }
{  https://github.com/paolo-rossi/delphi-jose-jwt                              }
{                                                                              }
{  Licensed under the MIT license                                              }
{                                                                              }
{******************************************************************************}

unit JOSE.Signing.RSA;

{$I ..\JOSE.inc}

interface

{$IFDEF RSA_SIGNING}

uses
  System.SysUtils,
  JOSE.Crypto.Algorithms,
  JOSE.Signing.Base;

type
  TRSAAlgorithm = JOSE.Crypto.Algorithms.TRSAAlgorithm;
  TRSAAlgorithmHelper = JOSE.Crypto.Algorithms.TRSAAlgorithmHelper;

  TRSA = class(TSigningBase)
  public
    class function Sign(const AInput, AKey: TBytes; AAlg: TRSAAlgorithm): TBytes;
    class function Verify(const AInput, ASignature, AKey: TBytes; AAlg: TRSAAlgorithm): Boolean;
    /// <summary>
    ///   Verifies against the public key carried by ACertificate. The
    ///   certificate is only a key container: its chain, validity dates,
    ///   revocation status and key usage are not checked
    /// </summary>
    class function VerifyWithCertificate(const AInput, ASignature, ACertificate: TBytes; AAlg: TRSAAlgorithm): Boolean;

    class function VerifyPublicKey(const AKey: TBytes): Boolean;
    class function VerifyPrivateKey(const AKey: TBytes): Boolean;
  end;

{$ENDIF}

implementation

{$IFDEF RSA_SIGNING}

uses
  JOSE.Providers;

{ TRSA }

class function TRSA.Sign(const AInput, AKey: TBytes; AAlg: TRSAAlgorithm): TBytes;
begin
  Result := TJOSEProviders.RSA.Sign(AInput, AKey, AAlg);
end;

class function TRSA.Verify(const AInput, ASignature, AKey: TBytes; AAlg: TRSAAlgorithm): Boolean;
begin
  Result := TJOSEProviders.RSA.Verify(AInput, ASignature, AKey, AAlg);
end;

class function TRSA.VerifyPrivateKey(const AKey: TBytes): Boolean;
begin
  Result := TJOSEProviders.RSA.VerifyPrivateKey(AKey);
end;

class function TRSA.VerifyPublicKey(const AKey: TBytes): Boolean;
begin
  Result := TJOSEProviders.RSA.VerifyPublicKey(AKey);
end;

class function TRSA.VerifyWithCertificate(const AInput, ASignature, ACertificate: TBytes; AAlg: TRSAAlgorithm): Boolean;
begin
  Result := TJOSEProviders.RSA.VerifyWithCertificate(AInput, ASignature, ACertificate, AAlg);
end;

{$ENDIF}

end.
