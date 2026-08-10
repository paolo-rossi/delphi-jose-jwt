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
///   Token Parts
/// </summary>
unit JOSE.Core.Parts;

{$I ..\JOSE.inc}

interface

uses
  System.SysUtils,
  System.Generics.Collections,
  JOSE.Types.Bytes,
  JOSE.Core.JWA,
  JOSE.Core.JWT;

type
  /// <summary>
  ///   Base class that describes the token parts.
  /// </summary>
  TJOSEParts = class
  protected
    FParts: TList<TJOSEBytes>;
    FToken: TJWT;
    FSkipKeyValidation: Boolean;
    function GetCompactToken: TJOSEBytes; virtual; abstract;
    procedure SetCompactToken(const Value: TJOSEBytes); virtual; abstract;

    function GetHeaderAlgorithm: string;
    function GetHeaderAlgorithmId: TJOSEAlgorithmId;
  public
    constructor Create(AToken: TJWT); virtual;
    destructor Destroy; override;

    procedure SetHeaderAlgorithm(const AAlg: string); overload;
    procedure SetHeaderAlgorithm(AAlg: TJOSEAlgorithmId); overload;

    procedure Clear;
    procedure Empty;
    property CompactToken: TJOSEBytes read GetCompactToken write SetCompactToken;
    property HeaderAlgorithm: string read GetHeaderAlgorithm;
    property HeaderAlgorithmId: TJOSEAlgorithmId read GetHeaderAlgorithmId;
    property SkipKeyValidation: Boolean read FSkipKeyValidation write FSkipKeyValidation;
  end;

implementation

{ TJOSEParts }

procedure TJOSEParts.Clear;
begin
  FParts.Clear;
end;

constructor TJOSEParts.Create(AToken: TJWT);
begin
  FToken := AToken;
  FParts := TList<TJOSEBytes>.Create;
end;

destructor TJOSEParts.Destroy;
begin
  FParts.Free;
  inherited;
end;

procedure TJOSEParts.Empty;
var
  LIndex: Integer;
begin
  for LIndex := 0 to FParts.Count - 1 do
    FParts[LIndex] := TJOSEBytes.Empty;
end;

function TJOSEParts.GetHeaderAlgorithm: string;
begin
  Result := FToken.Header.Algorithm;
end;

function TJOSEParts.GetHeaderAlgorithmId: TJOSEAlgorithmId;
begin
  Result.AsString := FToken.Header.Algorithm;
end;

procedure TJOSEParts.SetHeaderAlgorithm(AAlg: TJOSEAlgorithmId);
begin
  FToken.Header.Algorithm := AAlg.AsString;
end;

procedure TJOSEParts.SetHeaderAlgorithm(const AAlg: string);
begin
  FToken.Header.Algorithm := AAlg;
end;

end.
