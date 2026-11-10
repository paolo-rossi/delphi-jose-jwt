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
unit JOSE.Core.JWA.Factory;

{$I ..\JOSE.inc}

interface

uses
  System.SysUtils,
  System.Generics.Defaults,
  System.Generics.Collections,
  JOSE.Types.Bytes,
  JOSE.Core.JWA,
  JOSE.Core.JWA.Signing,
  JOSE.Core.JWA.Compression,
  JOSE.Core.JWA.Encryption,
  JOSE.Core.JWA.KeyManagement;

type
  TJOSEAlgorithmRegistry<T: IJOSEAlgorithm> = class
  private
    FName: string;
    FAlgorithms: TDictionary<string, T>;
  public
    constructor Create(const AName: string);
    destructor Destroy; override;

    /// <summary>The algorithm registered under the identifier, nil when none is</summary>
    function GetAlgorithm(AAlgorithmIdentifier: string): T;

    /// <summary>Registers under GetAlgorithmIdentifier.AsString (an "alg" value)</summary>
    function RegisterAlgorithm(AAlgorithm: T): TJOSEAlgorithmRegistry<T>; overload;
    /// <summary>
    ///   Registers under an explicit identifier: for the namespaces that are
    ///   not "alg", like "enc" and "zip"
    /// </summary>
    function RegisterAlgorithm(const AIdentifier: string; AAlgorithm: T): TJOSEAlgorithmRegistry<T>; overload;
    procedure UnregisterAlgorithm(AAlgId: string); overload;
    procedure UnregisterAlgorithm(AAlgId: TJOSEAlgorithmId); overload;

    /// <summary>The header member the registry resolves: "alg", "enc" or "zip"</summary>
    property Name: string read FName;
  end;

  /// <summary>
  ///   Process-wide registry of the JOSE algorithms
  /// </summary>
  /// <remarks>
  ///   The instance is created during unit initialization and is then read-only
  ///   as far as this library is concerned, so concurrent verification is safe.
  ///   RegisterAlgorithm/UnregisterAlgorithm mutate a shared dictionary and are
  ///   not synchronised: register your own algorithms at startup, before any
  ///   worker thread runs.
  /// </remarks>
  TJOSEAlgorithmRegistryFactory = class
  private class var
    FInstance: TJOSEAlgorithmRegistryFactory;
    FInstanceLock: TObject;
  private
    FSigningAlgorithmRegistry: TJOSEAlgorithmRegistry<IJOSESigningAlgorithm>;
    FKeyManagementAlgorithmRegistry: TJOSEAlgorithmRegistry<IJOSEKeyManagementAlgorithm>;
    FEncryptionAlgorithmRegistry: TJOSEAlgorithmRegistry<IJOSEEncryptionAlgorithm>;
    FCompressionAlgorithmRegistry: TJOSEAlgorithmRegistry<IJOSECompressionAlgorithm>;

    constructor Create;

    class function GetInstance: TJOSEAlgorithmRegistryFactory; static;
  public
    destructor Destroy; override;

    /// <summary>JWS "alg". A JWS must resolve its algorithm here and nowhere else</summary>
    property SigningAlgorithmRegistry: TJOSEAlgorithmRegistry<IJOSESigningAlgorithm>
      read FSigningAlgorithmRegistry;
    /// <summary>JWE "alg". A JWE must resolve its algorithm here and nowhere else</summary>
    property KeyManagementAlgorithmRegistry: TJOSEAlgorithmRegistry<IJOSEKeyManagementAlgorithm>
      read FKeyManagementAlgorithmRegistry;
    /// <summary>JWE "enc"</summary>
    property EncryptionAlgorithmRegistry: TJOSEAlgorithmRegistry<IJOSEEncryptionAlgorithm>
      read FEncryptionAlgorithmRegistry;
    property CompressionAlgorithmRegistry: TJOSEAlgorithmRegistry<IJOSECompressionAlgorithm>
      read FCompressionAlgorithmRegistry;

    class property Instance: TJOSEAlgorithmRegistryFactory read GetInstance;
  end;



implementation

{ TJOSEAlgorithmRegistry<T> }

constructor TJOSEAlgorithmRegistry<T>.Create(const AName: string);
begin
  FAlgorithms := TDictionary<string,T>.Create;
  FName := AName;
end;

destructor TJOSEAlgorithmRegistry<T>.Destroy;
begin
  FAlgorithms.Free;
  inherited;
end;

function TJOSEAlgorithmRegistry<T>.GetAlgorithm(AAlgorithmIdentifier: string): T;
begin
  FAlgorithms.TryGetValue(AAlgorithmIdentifier, Result);
end;

function TJOSEAlgorithmRegistry<T>.RegisterAlgorithm(AAlgorithm: T): TJOSEAlgorithmRegistry<T>;
begin
  Result := RegisterAlgorithm(AAlgorithm.GetAlgorithmIdentifier.AsString, AAlgorithm);
end;

function TJOSEAlgorithmRegistry<T>.RegisterAlgorithm(const AIdentifier: string;
  AAlgorithm: T): TJOSEAlgorithmRegistry<T>;
begin
  FAlgorithms.Add(AIdentifier, AAlgorithm);
  Result := Self;
end;

procedure TJOSEAlgorithmRegistry<T>.UnregisterAlgorithm(AAlgId: string);
begin
  FAlgorithms.Remove(AAlgId);
end;

procedure TJOSEAlgorithmRegistry<T>.UnregisterAlgorithm(AAlgId: TJOSEAlgorithmId);
begin
  UnregisterAlgorithm(AAlgId.AsString);
end;

{ TJOSEAlgorithmRegistryFactory }

constructor TJOSEAlgorithmRegistryFactory.Create;
begin
  FSigningAlgorithmRegistry := TJOSEAlgorithmRegistry<IJOSESigningAlgorithm>.Create('alg');

  FSigningAlgorithmRegistry
    .RegisterAlgorithm(THmacUsingShaAlgorithm.HmacSha256)
    .RegisterAlgorithm(THmacUsingShaAlgorithm.HmacSha384)
    .RegisterAlgorithm(THmacUsingShaAlgorithm.HmacSha512)

{$IFDEF RSA_SIGNING}
    .RegisterAlgorithm(TRSAUsingShaAlgorithm.RSA256)
    .RegisterAlgorithm(TRSAUsingShaAlgorithm.RSA384)
    .RegisterAlgorithm(TRSAUsingShaAlgorithm.RSA512)

    .RegisterAlgorithm(TRSAUsingShaAlgorithm.PSS256)
    .RegisterAlgorithm(TRSAUsingShaAlgorithm.PSS384)
    .RegisterAlgorithm(TRSAUsingShaAlgorithm.PSS512)

    .RegisterAlgorithm(TECDSAUsingSHAAlgorithm.ECDSA256)
    .RegisterAlgorithm(TECDSAUsingSHAAlgorithm.ECDSA256K)
    .RegisterAlgorithm(TECDSAUsingSHAAlgorithm.ECDSA384)
    .RegisterAlgorithm(TECDSAUsingSHAAlgorithm.ECDSA512)
{$ENDIF}
  ;

  // Filled when the JWE algorithms are implemented (JWE step 1, phases 2-3)
  FKeyManagementAlgorithmRegistry := TJOSEAlgorithmRegistry<IJOSEKeyManagementAlgorithm>.Create('alg');

  FEncryptionAlgorithmRegistry := TJOSEAlgorithmRegistry<IJOSEEncryptionAlgorithm>.Create('enc');

  FCompressionAlgorithmRegistry := TJOSEAlgorithmRegistry<IJOSECompressionAlgorithm>.Create('zip');
end;

destructor TJOSEAlgorithmRegistryFactory.Destroy;
begin
  FSigningAlgorithmRegistry.Free;
  FKeyManagementAlgorithmRegistry.Free;
  FEncryptionAlgorithmRegistry.Free;
  FCompressionAlgorithmRegistry.Free;

  inherited;
end;

class function TJOSEAlgorithmRegistryFactory.GetInstance: TJOSEAlgorithmRegistryFactory;
begin
  // The singleton is built during unit initialization, which the RTL runs
  // before any user code, so the common path is a plain read. The guarded
  // branch below only covers a call that arrives after finalization freed it:
  // unguarded lazy construction let two threads verifying their first token
  // each build a registry, one of which was then leaked along with anything
  // registered on it
  if not Assigned(FInstance) then
  begin
    TMonitor.Enter(FInstanceLock);
    try
      if not Assigned(FInstance) then
        FInstance := TJOSEAlgorithmRegistryFactory.Create;
    finally
      TMonitor.Exit(FInstanceLock);
    end;
  end;

  Result := FInstance;
end;

initialization
  TJOSEAlgorithmRegistryFactory.FInstanceLock := TObject.Create;
  // Eagerly, so that the first token verified by a worker thread does not have
  // to build it - and so that two of them cannot build it at the same time
  TJOSEAlgorithmRegistryFactory.GetInstance;

finalization
  TJOSEAlgorithmRegistryFactory.FInstance.Free;
  TJOSEAlgorithmRegistryFactory.FInstance := nil;
  TJOSEAlgorithmRegistryFactory.FInstanceLock.Free;
  TJOSEAlgorithmRegistryFactory.FInstanceLock := nil;

end.
