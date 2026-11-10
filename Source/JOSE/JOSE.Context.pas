{******************************************************************************}
{                                                                              }
{  Delphi JOSE-JWT Library                                                     }
{  Copyright (c) 2015 Paolo Rossi                                              }
{  https://github.com/paolo-rossi/delphi-jose-jwt                              }
{                                                                              }
{  Licensed under the MIT license                                              }
{                                                                              }
{******************************************************************************}

/// <summary>
///   Utility class to encode and decode a JWT
/// </summary>
unit JOSE.Context;

{$I ..\JOSE.inc}

interface

uses
  System.SysUtils, System.Generics.Collections,
  JOSE.Types.Bytes,
  JOSE.Core.Base,
  JOSE.Core.Parts,
  JOSE.Core.JWA,
  JOSE.Core.JWK,
  JOSE.Core.JWT,
  JOSE.Core.JWS,
  JOSE.Core.JWE,
  JOSE.Core.JWE.Header;

type
  /// <summary>
  ///   JOSE Context (for the Consumer)
  /// </summary>
  /// <remarks>
  ///   <para>
  ///     For a JWE the claims are empty until the consumer has decrypted the
  ///     token (TJOSEConsumer.ProcessContext): the context parses, it does not
  ///     decrypt
  ///   </para>
  ///   <para>
  ///     GetHeader and GetClaims describe the same layer. For a JWE that has not
  ///     been processed yet, that is the outer header (the only one there is);
  ///     once the consumer has processed a nested JWT, both are the inner JWS's.
  ///     The outer JWE header stays available through GetJWEHeader
  ///   </para>
  /// </remarks>
  TJOSEContext = class
  private
    FCompactToken: TJOSEBytes;
    FClaimsClass: TJWTClaimsClass;
    FJOSEObject: TJOSEParts;
    FJWT: TJWT;
    procedure FromCompactToken;
  public
    constructor Create(const ACompactToken: TJOSEBytes; AClaimsClass: TJWTClaimsClass);
    destructor Destroy; override;

    function GetJOSEObject: TJOSEParts; overload;
    function GetJOSEObject<T: TJOSEParts>: T; overload;

    /// <summary>
    ///   The header of the layer GetClaims describes. For a JWE it is the outer
    ///   header until the consumer has processed it; after a nested JWT it is
    ///   the inner JWS header, and GetJWEHeader gives the outer one
    /// </summary>
    function GetHeader: TJWTHeader;
    /// <summary>
    ///   The outer JWE header when the token is a JWE, nil for a JWS. A
    ///   separate object from GetHeader: both are parsed from the same part,
    ///   so their content is the same until a nested JWT is processed
    /// </summary>
    function GetJWEHeader: TJWEHeader;

    /// <summary>The claims the consumer validated: the inner JWS's for a nested JWT</summary>
    function GetClaims: TJWTClaims; overload;
    function GetClaims<T: TJWTClaims>: T; overload;
  end;

implementation

uses
  System.Types,
  System.StrUtils;

{ TJOSEContext }

constructor TJOSEContext.Create(const ACompactToken: TJOSEBytes; AClaimsClass: TJWTClaimsClass);
begin
  FCompactToken := ACompactToken;
  FClaimsClass := AClaimsClass;
  FJWT := TJWT.Create(FClaimsClass);

  // If this raises, the destructor is called automatically and releases
  // both FJWT and FJOSEObject
  FromCompactToken;
end;

destructor TJOSEContext.Destroy;
begin
  // FJOSEObject keeps a (non-owning) reference to FJWT: release it first
  FJOSEObject.Free;
  FJWT.Free;
  inherited;
end;

procedure TJOSEContext.FromCompactToken;
begin
  // The part count decides: 3 is a JWS, 5 a JWE, anything else is malformed.
  // A JWE is only parsed here (header and parts): the context holds no key,
  // so decryption, and with it the claims, comes later from the consumer
  case TJOSECompactSerialization.Split(FCompactToken).Kind of
    TJOSECompactKind.JWS: FJOSEObject := TJWS.Create(FJWT);
    TJOSECompactKind.JWE: FJOSEObject := TJWE.Create(FJWT);
  else
    raise EJOSEException.Create(SJOSEMalformedCompactSerialization);
  end;

  try
    FJOSEObject.CompactToken := FCompactToken;
  except
    // The token is not parsable: the context must *not* be built, or the
    // consumer would see a nil JOSE object and skip the whole verification
    on E: Exception do
    begin
      FreeAndNil(FJOSEObject);
      if E is EJOSEException then
        raise;
      raise EJOSEException.Create(SJOSEMalformedCompactSerialization);
    end;
  end;
end;

function TJOSEContext.GetClaims: TJWTClaims;
begin
  Result := FJWT.Claims;
end;

function TJOSEContext.GetClaims<T>: T;
begin
  Result := FJWT.Claims as T;
end;

function TJOSEContext.GetHeader: TJWTHeader;
begin
  Result := FJWT.Header;
end;

function TJOSEContext.GetJWEHeader: TJWEHeader;
begin
  if FJOSEObject is TJWE then
    Result := TJWE(FJOSEObject).Header
  else
    Result := nil;
end;

function TJOSEContext.GetJOSEObject: TJOSEParts;
begin
  Result := FJOSEObject;
end;

function TJOSEContext.GetJOSEObject<T>: T;
begin
  Result := FJOSEObject as T;
end;

end.
