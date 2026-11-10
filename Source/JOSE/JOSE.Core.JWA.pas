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
///   JSON Web Algorithms (JWA) RFC implementation (partial) <br />
/// </summary>
/// <seealso href="https://tools.ietf.org/html/rfc7518">
///   JWA RFC Document
/// </seealso>
unit JOSE.Core.JWA;

{$I ..\JOSE.inc}

interface

uses
  System.SysUtils,
  System.Generics.Defaults,
  System.Generics.Collections,
  JOSE.Types.Bytes;

type
  {$SCOPEDENUMS ON}
  TJOSEKeyCategory = (None, Symmetric, Asymmetric);

  /// <summary>
  ///   Enumeration for the JOSE "alg" values: the JWS signing algorithms and
  ///   the JWE key management algorithms, which share one IANA namespace
  /// </summary>
  /// <remarks>
  ///   New members are appended, never inserted, so that the ordinals stay
  ///   stable. A JWS must only ever accept a signing member and a JWE only a
  ///   key management member: see IsSigning/IsKeyManagement
  /// </remarks>
  TJOSEAlgorithmId = (
    Unknown, None,
    HS256, HS384, HS512,
    RS256, RS384, RS512,
    ES256, ES256K, ES384, ES512,
    PS256, PS384, PS512,
    // JWE key management (RFC 7518 par. 4)
    Dir, RSA_OAEP, RSA_OAEP_256
  );
  TJOSEAlgorithmIdHelper = record helper for TJOSEAlgorithmId
  private
    function GetAsString: string;
    procedure SetAsString(const AValue: string);
    function GetLength: Integer;
  public
    /// <summary>
    ///   True for the JWS signing algorithms, "none" included
    /// </summary>
    function IsSigning: Boolean;
    /// <summary>
    ///   True for the JWE key management algorithms
    /// </summary>
    function IsKeyManagement: Boolean;
    /// <summary>
    ///   Hash length in bits of a signing algorithm, 0 for every other member
    /// </summary>
    property Length: Integer read GetLength;
    property AsString: string read GetAsString write SetAsString;
  end;

  TJOSEAlgorithms = set of TJOSEAlgorithmId;

  /// <summary>
  ///   Enumeration for the JWE "enc" values (RFC 7518 par. 5), a namespace of
  ///   its own, separate from "alg"
  /// </summary>
  TJOSEEncryptionAlgorithmId = (
    Unknown,
    A128GCM, A192GCM, A256GCM
  );
  TJOSEEncryptionAlgorithmIdHelper = record helper for TJOSEEncryptionAlgorithmId
  private
    function GetAsString: string;
    procedure SetAsString(const AValue: string);
  public
    /// <summary>
    ///   Length in bytes of the Content Encryption Key the algorithm needs,
    ///   0 for Unknown
    /// </summary>
    function CEKLength: Integer;
    property AsString: string read GetAsString write SetAsString;
  end;

  TJOSEEncryptionAlgorithms = set of TJOSEEncryptionAlgorithmId;

  IJOSEAlgorithm = interface
  ['{1BA290C7-D139-4CD8-86FE-7F80B9826007}']
    function GetAlgorithmIdentifier: TJOSEAlgorithmId;
    function GetKeyCategory: TJOSEKeyCategory;
    function GetKeyType: string;
  end;

  // IJOSEKeyManagementAlgorithm has moved to JOSE.Core.JWA.KeyManagement: its
  // methods take the JWE header, which this unit cannot reference

  /// <summary>
  ///   Defines the JW* algorithm
  /// </summary>
  TJOSEAlgorithm = class(TInterfacedObject, IJOSEAlgorithm)
    FAlgorithmIdentifier: TJOSEAlgorithmId;
    FKeyCategory: TJOSEKeyCategory;
    FKeyType: string;
  public
    function GetAlgorithmIdentifier: TJOSEAlgorithmId;
    function GetKeyCategory: TJOSEKeyCategory;
    function GetKeyType: string;
  end;

implementation

{ TJOSEAlgorithm }

function TJOSEAlgorithm.GetAlgorithmIdentifier: TJOSEAlgorithmId;
begin
  Result := FAlgorithmIdentifier;
end;

function TJOSEAlgorithm.GetKeyCategory: TJOSEKeyCategory;
begin
  Result := FKeyCategory;
end;

function TJOSEAlgorithm.GetKeyType: string;
begin
  Result := FKeyType;
end;

{ TJOSEAlgorithmIdHelper }

function TJOSEAlgorithmIdHelper.GetAsString: string;
begin
  // Every member is listed, so that Result is never left unassigned
  case Self of
    TJOSEAlgorithmId.Unknown: Result := '';
    TJOSEAlgorithmId.None:  Result := 'none';

    TJOSEAlgorithmId.HS256: Result := 'HS256';
    TJOSEAlgorithmId.HS384: Result := 'HS384';
    TJOSEAlgorithmId.HS512: Result := 'HS512';

    TJOSEAlgorithmId.RS256: Result := 'RS256';
    TJOSEAlgorithmId.RS384: Result := 'RS384';
    TJOSEAlgorithmId.RS512: Result := 'RS512';

    TJOSEAlgorithmId.ES256: Result := 'ES256';
    TJOSEAlgorithmId.ES256K: Result := 'ES256K';
    TJOSEAlgorithmId.ES384: Result := 'ES384';
    TJOSEAlgorithmId.ES512: Result := 'ES512';

    TJOSEAlgorithmId.PS256: Result := 'PS256';
    TJOSEAlgorithmId.PS384: Result := 'PS384';
    TJOSEAlgorithmId.PS512: Result := 'PS512';

    TJOSEAlgorithmId.Dir: Result := 'dir';
    TJOSEAlgorithmId.RSA_OAEP: Result := 'RSA-OAEP';
    TJOSEAlgorithmId.RSA_OAEP_256: Result := 'RSA-OAEP-256';
  else
    Result := '';
  end;
end;

function TJOSEAlgorithmIdHelper.IsKeyManagement: Boolean;
begin
  Result := Self in [TJOSEAlgorithmId.Dir, TJOSEAlgorithmId.RSA_OAEP, TJOSEAlgorithmId.RSA_OAEP_256];
end;

function TJOSEAlgorithmIdHelper.IsSigning: Boolean;
begin
  Result := Self in [TJOSEAlgorithmId.None..TJOSEAlgorithmId.PS512];
end;

function TJOSEAlgorithmIdHelper.GetLength: Integer;
begin
  Result := 0;
  case Self of
    TJOSEAlgorithmId.HS256: Result := 256;
    TJOSEAlgorithmId.HS384: Result := 384;
    TJOSEAlgorithmId.HS512: Result := 512;

    TJOSEAlgorithmId.RS256: Result := 256;
    TJOSEAlgorithmId.RS384: Result := 384;
    TJOSEAlgorithmId.RS512: Result := 512;

    TJOSEAlgorithmId.ES256: Result := 256;
    TJOSEAlgorithmId.ES256K: Result := 256;
    TJOSEAlgorithmId.ES384: Result := 384;
    TJOSEAlgorithmId.ES512: Result := 512;

    TJOSEAlgorithmId.PS256: Result := 256;
    TJOSEAlgorithmId.PS384: Result := 384;
    TJOSEAlgorithmId.PS512: Result := 512;
  end;
end;

procedure TJOSEAlgorithmIdHelper.SetAsString(const AValue: string);
begin
  if AValue = 'none' then
    Self := TJOSEAlgorithmId.None

  else if AValue = 'HS256' then
    Self := TJOSEAlgorithmId.HS256
  else if AValue = 'HS384' then
    Self := TJOSEAlgorithmId.HS384
  else if AValue = 'HS512' then
    Self := TJOSEAlgorithmId.HS512

  else if AValue = 'RS256' then
    Self := TJOSEAlgorithmId.RS256
  else if AValue = 'RS384' then
    Self := TJOSEAlgorithmId.RS384
  else if AValue = 'RS512' then
    Self := TJOSEAlgorithmId.RS512

  else if AValue = 'ES256' then
    Self := TJOSEAlgorithmId.ES256
  else if AValue = 'ES256K' then
    Self := TJOSEAlgorithmId.ES256K
  else if AValue = 'ES384' then
    Self := TJOSEAlgorithmId.ES384
  else if AValue = 'ES512' then
    Self := TJOSEAlgorithmId.ES512

  else if AValue = 'PS256' then
    Self := TJOSEAlgorithmId.PS256
  else if AValue = 'PS384' then
    Self := TJOSEAlgorithmId.PS384
  else if AValue = 'PS512' then
    Self := TJOSEAlgorithmId.PS512

  else if AValue = 'dir' then
    Self := TJOSEAlgorithmId.Dir
  else if AValue = 'RSA-OAEP' then
    Self := TJOSEAlgorithmId.RSA_OAEP
  else if AValue = 'RSA-OAEP-256' then
    Self := TJOSEAlgorithmId.RSA_OAEP_256

  else
    Self := TJOSEAlgorithmId.Unknown;
end;

{ TJOSEEncryptionAlgorithmIdHelper }

function TJOSEEncryptionAlgorithmIdHelper.CEKLength: Integer;
begin
  case Self of
    TJOSEEncryptionAlgorithmId.A128GCM: Result := 16;
    TJOSEEncryptionAlgorithmId.A192GCM: Result := 24;
    TJOSEEncryptionAlgorithmId.A256GCM: Result := 32;
  else
    Result := 0;
  end;
end;

function TJOSEEncryptionAlgorithmIdHelper.GetAsString: string;
begin
  case Self of
    TJOSEEncryptionAlgorithmId.A128GCM: Result := 'A128GCM';
    TJOSEEncryptionAlgorithmId.A192GCM: Result := 'A192GCM';
    TJOSEEncryptionAlgorithmId.A256GCM: Result := 'A256GCM';
  else
    Result := '';
  end;
end;

procedure TJOSEEncryptionAlgorithmIdHelper.SetAsString(const AValue: string);
begin
  // Case-sensitive, like "alg": RFC 7516 par. 4.1.2 makes "enc" a
  // case-sensitive string
  if AValue = 'A128GCM' then
    Self := TJOSEEncryptionAlgorithmId.A128GCM
  else if AValue = 'A192GCM' then
    Self := TJOSEEncryptionAlgorithmId.A192GCM
  else if AValue = 'A256GCM' then
    Self := TJOSEEncryptionAlgorithmId.A256GCM
  else
    Self := TJOSEEncryptionAlgorithmId.Unknown;
end;

end.
