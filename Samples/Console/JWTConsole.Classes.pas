unit JWTConsole.Classes;

interface

uses
  System.SysUtils,
  System.Classes,
  JOSE.Core.JWT,
  JOSE.Core.JWS,
  JOSE.Core.JWK,
  JOSE.Core.JWA,
  JOSE.Types.JSON;

type
  TSampleJWTConsole = class
  public
    class function CompileSampleToken: string;
  end;


implementation

uses
  System.DateUtils,
  JOSE.Types.Bytes,
  JOSE.Core.Builder;

{ TSampleJWTConsole }

class function TSampleJWTConsole.CompileSampleToken: string;
var
  LToken: TJWT;
  LSigner: TJWS;
  LKey: TJWK;
begin
  LToken := TJWT.Create();
  try
    LToken.Claims.Issuer := 'Delphi JOSE Library';
    LToken.Claims.IssuedAt := EncodeDateTime(2017, 3, 10, 10, 20, 30, 0);
    LToken.Claims.Expiration := LToken.Claims.IssuedAt + 1;

    LSigner := TJWS.Create(LToken);
    LKey := TJWK.Create('secret');
    try
      LSigner.SkipKeyValidation := True;
      LSigner.Sign(LKey, TJOSEAlgorithmId.HS256);

      Result := LSigner.CompactToken;

      Writeln('Header: ' + LToken.Header.JSON.ToJSON);
      Writeln('Claims: ' + LToken.Claims.JSON.ToJSON);

      Writeln('Header: ' + LSigner.Header.AsString);
      Writeln('Payload: ' + LSigner.Payload.AsString);
      Writeln('Signature: ' + LSigner.Signature.AsString);
      Writeln('Compact Token: ' + Result);
    finally
      LKey.Free;
      LSigner.Free;
    end;
  finally
    LToken.Free;
  end;
end;

end.
