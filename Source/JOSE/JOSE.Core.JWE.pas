{******************************************************************************}
{                                                                              }
{  Delphi JOSE-JWT Library                                                     }
{  Copyright (c) 2015 Paolo Rossi                                              }
{  https://github.com/paolo-rossi/delphi-jose-jwt                              }
{                                                                              }
{  Licensed under the MIT license                                              }
{                                                                              }
{******************************************************************************}

unit JOSE.Core.JWE;

{$I ..\JOSE.inc}

interface

uses
  System.SysUtils,
  JOSE.Types.Bytes,
  JOSE.Core.Base,
  JOSE.Core.Parts,
  JOSE.Core.JWT;

type
  /// <summary>
  ///   JSON Web Encryption (JWE) RFC implementation (initial)
  /// </summary>
  /// <seealso href="https://tools.ietf.org/html/rfc7516">
  ///   JWE RFC Document
  /// </seealso>
  TJWE = class(TJOSEParts)
  private
    const COMPACT_PARTS = 5;
  public
    constructor Create(AToken: TJWT); override;
    //class function Encrypt(AKey: TJWK; AAlg: TJWAEnum): string;
    //class function Decrypt(AKey: TJWK; AInput: TBytes): Boolean;
  end;

implementation

{ TJWEParts }

constructor TJWE.Create(AToken: TJWT);
var
  LIndex: Integer;
begin
  inherited Create(AToken);

  for LIndex := 0 to COMPACT_PARTS - 1 do
    FParts.Add(TJOSEBytes.Empty);
end;

end.
