{******************************************************************************}
{                                                                              }
{  Delphi JOSE Library                                                         }
{  Copyright (c) 2015-2017 Paolo Rossi                                         }
{  https://github.com/paolo-rossi/delphi-jose-jwt                              }
{                                                                              }
{******************************************************************************}
{                                                                              }
{  Licensed under the Apache License, Version 2.0 (the "License");             }
{  you may not use this file except in compliance with the License.            }
{  You may obtain a copy of the License at                                     }
{                                                                              }
{      http://www.apache.org/licenses/LICENSE-2.0                              }
{                                                                              }
{  Unless required by applicable law or agreed to in writing, software         }
{  distributed under the License is distributed on an "AS IS" BASIS,           }
{  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.    }
{  See the License for the specific language governing permissions and         }
{  limitations under the License.                                              }
{                                                                              }
{******************************************************************************}

/// <summary>
///   JSON Web Algorithms (JWA) RFC implementation (partial) <br />
/// </summary>
/// <seealso href="https://tools.ietf.org/html/rfc7518">
///   JWA RFC Document
/// </seealso>
unit JOSE.Core.JWA;

interface

uses
  System.SysUtils,
  System.Generics.Defaults,
  System.Generics.Collections,
  JOSE.Types.Bytes;

type
  {$SCOPEDENUMS ON}
  TJOSEKeyCategory = (None, Symmetric, Asymmetric);

  TJOSEAlgorithmId = (
    Unknown, None,
    HS256, HS384, HS512,
    RS256, RS384, RS512,
    ES256, ES384, ES512,
    PS256, PS384, PS512
  );
  TJOSEAlgorithmIdHelper = record helper for TJOSEAlgorithmId
  private
    function GetAsString: string;
    procedure SetAsString(const Value: string);
  public
    property AsString: string read GetAsString write SetAsString;
  end;

  IJOSEAlgorithm = interface
  ['{1BA290C7-D139-4CD8-86FE-7F80B9826007}']
    function GetAlgorithmIdentifier: TJOSEAlgorithmId;
    function GetKeyCategory: TJOSEKeyCategory;
    function GetKeyType: string;
  end;

  IJOSEKeyManagementAlgorithm = interface(IJOSEAlgorithm)
  ['{2A2FBF37-8267-4DA3-AA11-7E1C3ED235DD}']
  end;

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
  case Self of
    TJOSEAlgorithmId.None:  Result := 'none';

    TJOSEAlgorithmId.HS256: Result := 'HS256';
    TJOSEAlgorithmId.HS384: Result := 'HS384';
    TJOSEAlgorithmId.HS512: Result := 'HS512';

    TJOSEAlgorithmId.RS256: Result := 'RS256';
    TJOSEAlgorithmId.RS384: Result := 'RS384';
    TJOSEAlgorithmId.RS512: Result := 'RS512';

    TJOSEAlgorithmId.ES256: Result := 'ES256';
    TJOSEAlgorithmId.ES384: Result := 'ES384';
    TJOSEAlgorithmId.ES512: Result := 'ES512';

    TJOSEAlgorithmId.PS256: Result := 'PS256';
    TJOSEAlgorithmId.PS384: Result := 'PS384';
    TJOSEAlgorithmId.PS512: Result := 'PS512';
  end;
end;

procedure TJOSEAlgorithmIdHelper.SetAsString(const Value: string);
begin
  if Value = 'none' then
    Self := TJOSEAlgorithmId.None

  else if Value = 'HS256' then
    Self := TJOSEAlgorithmId.HS256
  else if Value = 'HS384' then
    Self := TJOSEAlgorithmId.HS384
  else if Value = 'HS512' then
    Self := TJOSEAlgorithmId.HS512

  else if Value = 'RS256' then
    Self := TJOSEAlgorithmId.RS256
  else if Value = 'RS384' then
    Self := TJOSEAlgorithmId.RS384
  else if Value = 'RS512' then
    Self := TJOSEAlgorithmId.RS512

  else if Value = 'ES256' then
    Self := TJOSEAlgorithmId.ES256
  else if Value = 'ES384' then
    Self := TJOSEAlgorithmId.ES384
  else if Value = 'ES512' then
    Self := TJOSEAlgorithmId.ES512

  else if Value = 'PS256' then
    Self := TJOSEAlgorithmId.PS256
  else if Value = 'PS384' then
    Self := TJOSEAlgorithmId.PS384
  else if Value = 'PS512' then
    Self := TJOSEAlgorithmId.PS512

  else
    Self := TJOSEAlgorithmId.Unknown;
end;

end.
