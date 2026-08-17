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
  JOSE.Core.JWE;

type
  /// <summary>
  ///   JOSE Context (for the Consumer)
  /// </summary>
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

    function GetHeader: TJWTHeader;

    function GetClaims: TJWTClaims; overload;
    function GetClaims<T: TJWTClaims>: T; overload;
  end;

implementation

uses
  System.Types,
  System.StrUtils;

resourcestring
  SJOSEJWENotSupported = 'Compact Serialization appears to be a JWE Token which is not (yet) supported';
  SJOSEMalformedCompactSerialization = 'Malformed Compact Serialization';

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
var
  LRes: TStringDynArray;
begin
  LRes := SplitString(FCompactToken, PART_SEPARATOR);

  case Length(LRes) of
    3:
    begin
      FJOSEObject := TJWS.Create(FJWT);
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
    5:
    begin
      raise EJOSEException.Create(SJOSEJWENotSupported);
    end;

  else
    raise EJOSEException.Create(SJOSEMalformedCompactSerialization);
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

function TJOSEContext.GetJOSEObject: TJOSEParts;
begin
  Result := FJOSEObject;
end;

function TJOSEContext.GetJOSEObject<T>: T;
begin
  Result := FJOSEObject as T;
end;

end.
