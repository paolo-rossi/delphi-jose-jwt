{******************************************************}
{  Copyright (C) 2015                                  }
{  Delphi JOSE Library                                 }
{                                                      }
{  https://github.com/paolo-rossi/delphi-jose-jwt      }
{                                                      }
{  Authors:                                            }
{  Paolo Rossi <paolo(at)paolorossi(dot)net>           }
{                                                      }
{******************************************************}
unit JOSE.Core.Builder;

interface

uses
  System.SysUtils,
  JOSE.Types.Bytes,
  JOSE.Core.Base,
  JOSE.Core.Parts,
  JOSE.Core.JWA,
  JOSE.Core.JWK,
  JOSE.Core.JWT,
  JOSE.Core.JWS,
  JOSE.Core.JWE;

type
  TJOSE = class
  private
    class function DeserialzeVerify(AKey: TJWK; ACompactToken: TSuperBytes; AVerify: Boolean): TJWT;
  public
    class function Sign(AKey: TJWK; AAlg: TJWAEnum; AToken: TJWT): TSuperBytes;
    class function Verify(AKey: TJWK; ACompactToken: TSuperBytes): TJWT;

    class function SerializeCompact(AKey: TJWK; AAlg: TJWAEnum; AToken: TJWT): TSuperBytes;
    class function DeserializeCompact(const ACompactToken: TSuperBytes): TJWT;

    class function SHA256CompactToken(AKey: TSuperBytes; AToken: TJWT): TSuperBytes;
  end;


implementation

uses
  System.Types,
  System.StrUtils;

{ TJOSE }

class function TJOSE.DeserializeCompact(const ACompactToken: TSuperBytes): TJWT;
begin
  Result := DeserialzeVerify(nil, ACompactToken, True);
end;

class function TJOSE.DeserialzeVerify(AKey: TJWK; ACompactToken: TSuperBytes; AVerify: Boolean): TJWT;
var
  LRes: TStringDynArray;
  LSigner: TJWS;
begin
  Result := nil;
  LRes := SplitString(ACompactToken, PART_SEPARATOR);

  case Length(LRes) of
    3:
    begin
      Result := TJWT.Create(TJWTClaims);
      try
        LSigner := TJWS.Create(Result);
        try
          if AVerify then
            LSigner.Verify(AKey, ACompactToken)
          else
            LSigner.CompactToken := ACompactToken;
        finally
          LSigner.Free;
        end;
      except
        FreeAndNil(Result);
      end;
    end;
    5:
    begin
      raise EJOSEException.Create('Compact Serialization appears to be a JWE Token wich is not (yet) supported');
    end;
    else
      raise EJOSEException.Create('Malformed Compact Serialization');
  end
end;

class function TJOSE.SerializeCompact(AKey: TJWK; AAlg: TJWAEnum; AToken: TJWT): TSuperBytes;
var
  LSigner: TJWS;
begin
  LSigner := TJWS.Create(AToken);
  try
    LSigner.Sign(AKey, AAlg);
    Result := LSigner.CompactToken;
  finally
    LSigner.Free;
  end;
end;

class function TJOSE.Sign(AKey: TJWK; AAlg: TJWAEnum; AToken: TJWT): TSuperBytes;
var
  LSigner: TJWS;
begin
  LSigner := TJWS.Create(AToken);
  try
    Result := LSigner.Sign(AKey, AAlg);
  finally
    LSigner.Free;
  end;
end;

class function TJOSE.SHA256CompactToken(AKey: TSuperBytes; AToken: TJWT):
    TSuperBytes;
var
  LSigner: TJWS;
  LKey: TJWK;
begin
  LSigner := TJWS.Create(AToken);
  LKey := TJWK.Create(AKey);
  try
    LSigner.Sign(LKey, HS256);
    Result := LSigner.CompactToken;
  finally
    LKey.Free;
    LSigner.Free;
  end;
end;

class function TJOSE.Verify(AKey: TJWK; ACompactToken: TSuperBytes): TJWT;
begin
  Result := DeserialzeVerify(AKey, ACompactToken, True);
end;

end.
