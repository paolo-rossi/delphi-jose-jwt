{******************************************************************************}
{                                                                              }
{  Delphi JOSE-JWT Library                                                     }
{  Copyright (c) 2015 Paolo Rossi                                              }
{  https://github.com/paolo-rossi/delphi-jose-jwt                              }
{                                                                              }
{  Licensed under the MIT license                                              }
{                                                                              }
{******************************************************************************}

unit JOSE.Providers.Interfaces;

{$I ..\JOSE.inc}

interface

uses
  System.SysUtils,
  JOSE.Types.Bytes,
  JOSE.Crypto.Algorithms;

type
  IJOSEBase64Provider = interface
    ['{8F2E9C1D-4A3B-4E5F-9D8C-7B6A50413210}']
    function Encode(const ASource: TJOSEBytes): TJOSEBytes;
    function Decode(const ASource: TJOSEBytes): TJOSEBytes;
    function TryDecode(const ASource: TJOSEBytes): TJOSEBytes;
    function URLEncode(const ASource: TJOSEBytes): TJOSEBytes;
    function URLDecode(const ASource: TJOSEBytes): TJOSEBytes;
    function TryURLDecode(const ASource: TJOSEBytes): TJOSEBytes;
  end;

  IJOSEHmacProvider = interface
    ['{7D1C8B2E-5F4A-4D3C-8E9F-1029384756AB}']
    function Sign(const AInput, AKey: TBytes; AAlg: THMACAlgorithm): TBytes;
  end;

{$IFDEF RSA_SIGNING}

  IJOSECertificateProvider = interface
    ['{6E0B7A3D-2C1F-4E5D-9A8B-7C6D5E4F3021}']
    function PublicKeyFromCertificate(const ACertificate: TBytes): TBytes;
    function VerifyCertificate(const ACertificate: TBytes; AExpected: TJOSECertificatePublicKey): Boolean;
  end;

  IJOSESignerRSA = interface
    ['{5D9C8B1E-3A2F-4D5C-8B7A-6C5D4E3F2010}']
    function Sign(const AInput, AKey: TBytes; AAlg: TRSAAlgorithm): TBytes;
    function Verify(const AInput, ASignature, AKey: TBytes; AAlg: TRSAAlgorithm): Boolean;
    function VerifyWithCertificate(const AInput, ASignature, ACertificate: TBytes; AAlg: TRSAAlgorithm): Boolean;
    function VerifyPublicKey(const AKey: TBytes): Boolean;
    function VerifyPrivateKey(const AKey: TBytes): Boolean;
  end;

  IJOSESignerECDSA = interface
    ['{4C8B7A2D-1E0F-4C3B-7A6C-5B4D3E2F1098}']
    function Sign(const AInput, APrivateKey: TBytes; AAlg: TECDSAAlgorithm): TBytes;
    function Verify(const AInput, ASignature, APublicKey: TBytes; AAlg: TECDSAAlgorithm): Boolean;
    function VerifyWithCertificate(const AInput, ASignature, ACertificate: TBytes; AAlg: TECDSAAlgorithm): Boolean;
    function VerifyPublicKey(const AKey: TBytes): Boolean;
    function VerifyPrivateKey(const AKey: TBytes): Boolean;
  end;

  /// <summary>Imports/exports raw RSA key material (RFC 7517/7518) to/from PEM, for JWK support.</summary>
  IJOSERSAKeyMaterialProvider = interface
    ['{3A2F1E0D-9C8B-4A7D-9E1F-2B3C4D5E6F70}']
    function ImportPEM(const APEM: TBytes): TJOSERSAKeyMaterial;
    function ExportPEM(const AKeyMaterial: TJOSERSAKeyMaterial; AIncludePrivate: Boolean): TBytes;
  end;

  /// <summary>Imports/exports raw EC key material (RFC 7517/7518) to/from PEM, for JWK support.</summary>
  IJOSEECKeyMaterialProvider = interface
    ['{9B1C2D3E-4F5A-4B6C-8D7E-1F2A3B4C5D6E}']
    function ImportPEM(const APEM: TBytes): TJOSEECKeyMaterial;
    function ExportPEM(const AKeyMaterial: TJOSEECKeyMaterial; AIncludePrivate: Boolean): TBytes;
  end;

{$ENDIF}

implementation

end.
