{******************************************************************************}
{                                                                              }
{  Delphi JOSE Library                                                         }
{  Copyright (c) 2015-2021 Paolo Rossi                                         }
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

unit JOSE.OpenSSL.Headers;

interface

uses
  System.SysUtils,
  {$IFDEF MSWINDOWS}
  Winapi.Windows,
  {$ENDIF}
  {$IFDEF USE_VCL_POSIX}
  Posix.SysSocket,
  Posix.SysTime,
  Posix.SysTypes,
  {$ENDIF}
  IdSSLOpenSSLHeaders;

type
  PBytes = ^TBytes;
  PPBIGNUM = ^PBIGNUM;

  JoseSSL = class
  public
    //ECDASA Keys
    const PEM_PUBKEY: RawByteString = '-----BEGIN PUBLIC KEY-----';
    const PEM_PRVKEY_PKCS8: RawByteString = '-----BEGIN PRIVATE KEY-----';
    const PEM_PRVKEY_PKCS1: RawByteString = '-----BEGIN EC PRIVATE KEY-----';
    const PEM_X509_CERTIFICATE: RawByteString = '-----BEGIN CERTIFICATE-----';
  private const
    fn_SSLeay_version = 'SSLeay_version';

    fn_PEM_read_bio_PUBKEY = 'PEM_read_bio_PUBKEY';
    fn_PEM_write_bio_PUBKEY = 'PEM_write_bio_PUBKEY';
    fn_PEM_read_bio_RSA_PUBKEY = 'PEM_read_bio_RSA_PUBKEY';
    fn_PEM_read_bio_ECPrivateKey = 'PEM_read_bio_ECPrivateKey';
    fn_EVP_MD_CTX_create = 'EVP_MD_CTX_create';
    fn_EVP_MD_CTX_destroy = 'EVP_MD_CTX_destroy';

    // BIGNUMBER related functions
    fn_BN_num_bits = 'BN_num_bits';
    fn_BN_bn2bin = 'BN_bn2bin';
    fn_BN_bin2bn = 'BN_bin2bn';
    fn_BN_bn2hex = 'BN_bn2hex';
    fn_BN_hex2bn = 'BN_hex2bn';
    fn_BN_bn2dec = 'BN_bn2dec';
    fn_BN_dec2bn = 'BN_dec2bn';
    fn_BN_copy = 'BN_copy';
    fn_BN_dup = 'BN_copy';
    fn_BN_clear_free = 'BN_clear_free';

    fn_X509_get_pubkey = 'X509_get_pubkey';

    // SHA related functions
    fn_SHA256 = 'SHA256';
    fn_SHA384 = 'SHA384';
    fn_SHA512 = 'SHA512';

    // RSA related functions
    fn_RSA_size = 'RSA_size';
    fn_RSA_sign = 'RSA_sign';
    fn_RSA_verify = 'RSA_verify';

    // ECDSA related functions
    fn_ECDSA_size = 'ECDSA_size';
    fn_ECDSA_SIG_new = 'ECDSA_SIG_new';
    fn_ECDSA_SIG_free = 'ECDSA_SIG_free';
    fn_ECDSA_do_sign = 'ECDSA_do_sign';
    fn_ECDSA_do_verify = 'ECDSA_do_verify';
    fn_ECDSA_SIG_set0 = 'ECDSA_SIG_set0';
    fn_EC_KEY_get0_group = 'EC_KEY_get0_group';
    fn_EC_KEY_free = 'EC_KEY_free';
    fn_EC_GROUP_get_degree = 'EC_GROUP_get_degree';
    fn_d2i_ECDSA_SIG = 'd2i_ECDSA_SIG';
    fn_i2d_ECDSA_SIG = 'i2d_ECDSA_SIG';

  public const
    // Numeric ASN1 Object Identifiers
    NID_sha256 = 672;
    NID_sha384 = 673;
    NID_sha512 = 674;
    NID_X9_62_id_ecPublicKey = 408; // EC Key

  public class var
    SSLeay_version: function(_type: Integer): PAnsiChar cdecl;

    PEM_read_bio_PUBKEY: function(bp: PBIO; x: PPEVP_PKEY; cb: ppem_password_cb; u: Pointer): PEVP_PKEY; cdecl;
    PEM_write_bio_PUBKEY: function(bp: PBIO; x: PEVP_PKEY): Integer; cdecl;
    PEM_read_bio_RSA_PUBKEY: function(bp: PBIO; x: PPRSA; cb: ppem_password_cb; u: Pointer): PRSA cdecl;
    PEM_read_bio_ECPrivateKey: function(bp: PBIO; key: PPEC_KEY; cb: ppem_password_cb; u: Pointer): PEC_KEY cdecl;

    X509_get_pubkey: function(cert: PX509): PEVP_PKEY cdecl;

    EVP_MD_CTX_create: function: PEVP_MD_CTX cdecl;
    EVP_MD_CTX_destroy: procedure(ctx: PEVP_MD_CTX); cdecl;

    BN_num_bits: function(const a: PBIGNUM): Integer cdecl;
    BN_bn2bin: function(const a: PBIGNUM; _to: Pointer): Integer cdecl;
    BN_bin2bn: function(const s: Pointer; len: Integer; ret: PBIGNUM): PBIGNUM cdecl;
    BN_bn2hex: function(const a: PBIGNUM): PAnsiChar cdecl;
    BN_hex2bn: function(a: PPBIGNUM; str: PAnsiChar): Integer; cdecl;
    BN_bn2dec: function(const a: PBIGNUM): PAnsiChar cdecl;
    BN_dec2bn: function(a: PPBIGNUM; str: PAnsiChar): Integer; cdecl;
    BN_copy: function(_to: PBIGNUM; const _from: PBIGNUM): PBIGNUM cdecl;
    BN_dup: function(const _from: PBIGNUM): PBIGNUM cdecl;
    BN_clear_free: procedure(a: PBIGNUM); cdecl;

    SHA256: function (const d: PBytes; n: NativeUInt; md: PBytes): PBytes cdecl;
    SHA384: function (const d: PBytes; n: NativeUInt; md: PBytes): PBytes cdecl;
    SHA512: function (const d: PBytes; n: NativeUInt; md: PBytes): PBytes cdecl;

    RSA_size: function (const rsa: PRSA): Integer cdecl;
    RSA_sign: function(_type: Integer; m: PBytes; m_len: Cardinal; sigret: PBytes; siglen: PCardinal; rsa: PRSA): Integer; cdecl;
    RSA_verify: function(_type: Integer; m: PBytes; m_len: Cardinal; sigbuf: PBytes; siglen: Cardinal; rsa: PRSA): Integer; cdecl;

    ECDSA_size: function(const pKey: PEC_KEY): Integer cdecl;
    ECDSA_SIG_new: function(): PECDSA_SIG cdecl;
    ECDSA_SIG_free: procedure (sig: PECDSA_SIG) cdecl;
    ECDSA_do_sign: function(const dgst: Pointer; dgst_len: Integer; eckey: PEC_KEY): PECDSA_SIG cdecl;
    ECDSA_do_verify: function(const dgst: Pointer; dgst_len: Integer; sig: PECDSA_SIG; eckey: PEC_KEY): Integer cdecl;
    EC_KEY_get0_group: function(const pKey: PEC_KEY): PEC_GROUP cdecl;
    EC_KEY_free: procedure(pKey: PEC_KEY) cdecl;
    EC_GROUP_get_degree: function(const pGroup: PEC_GROUP): Integer cdecl;
    d2i_ECDSA_SIG: function(ppSignature: PPECDSA_SIG; const pp: PPointer; len: LongInt): PECDSA_SIG cdecl;
    i2d_ECDSA_SIG: function (const sig: PECDSA_SIG; pp: PPointer): Integer cdecl;

  public class var
    FLoadErrors: Integer;
  private
    class function LoadFunctionCLib(const AFunctionName: string; const ARaiseException: Boolean = True): Pointer;
  public
    class function BN_num_bytes(const a: PBIGNUM): Integer;
    class procedure ECDSA_SIG_get0(const sig: PECDSA_SIG; const pr: PPBIGNUM; const ps: PPBIGNUM);
    class function ECDSA_SIG_set0(const sig: PECDSA_SIG; const r: PBIGNUM; const s: PBIGNUM): Integer;
    class function GetLastError(): string;
  public
    class function Load: Boolean;
    class procedure Unload;
  end;

implementation

uses
  JOSE.Types.Utils;

class function JoseSSL.LoadFunctionCLib(const AFunctionName: string; const ARaiseException: Boolean = True): Pointer;
begin
  Result := {$IFDEF WINDOWS}Windows.{$ENDIF}GetProcAddress(GetCryptLibHandle, PChar(AFunctionName));
  if Result = nil then
  begin
    if ARaiseException then
      raise Exception.CreateFmt('Error loading [%s]', [AFunctionName])
    else
      Inc(FLoadErrors);
  end;
end;

class function JoseSSL.BN_num_bytes(const a: PBIGNUM): Integer;
begin
  Result := Trunc((JoseSSL.BN_num_bits(a) + 7) / 8);
end;

class procedure JoseSSL.ECDSA_SIG_get0(const sig: PECDSA_SIG; const pr, ps: PPBIGNUM);
begin
  if not (pr = nil) then
    pr^ := sig.r;
  if not (ps = nil) then
    ps^ := sig.s;
end;

class function JoseSSL.ECDSA_SIG_set0(const sig: PECDSA_SIG; const r: PBIGNUM; const s: PBIGNUM): Integer;
begin
	if (r = nil) or (s = nil) then
		Exit(0);

	BN_clear_free(sig.r);
	BN_clear_free(sig.s);

	sig.r := r;
	sig.s := s;

	Exit(1);
end;

class function JoseSSL.GetLastError: string;
var
  LErrMsg: array[0..160] of AnsiChar;
begin
  ERR_error_string(ERR_get_error, @LErrMsg);
  Result := string(LErrMsg);
end;

class function JoseSSL.Load: Boolean;
begin
  FLoadErrors := 0;

  @SSLeay_version := LoadFunctionCLib(fn_SSLeay_version);

  @PEM_read_bio_PUBKEY := LoadFunctionCLib(fn_PEM_read_bio_PUBKEY);
  @PEM_write_bio_PUBKEY := LoadFunctionCLib(fn_PEM_write_bio_PUBKEY);
  @PEM_read_bio_RSA_PUBKEY := LoadFunctionCLib(fn_PEM_read_bio_RSA_PUBKEY);
  @PEM_read_bio_ECPrivateKey := LoadFunctionCLib(fn_PEM_read_bio_ECPrivateKey);

  @EVP_MD_CTX_create := LoadFunctionCLib(fn_EVP_MD_CTX_create);
  @EVP_MD_CTX_destroy := LoadFunctionCLib(fn_EVP_MD_CTX_destroy);

  // BIGNUMBER functions
  @BN_num_bits := LoadFunctionCLib(fn_BN_num_bits);
  @BN_bn2bin := LoadFunctionCLib(fn_BN_bn2bin);
  @BN_bin2bn := LoadFunctionCLib(fn_BN_bin2bn);
  @BN_bn2hex := LoadFunctionCLib(fn_BN_bn2hex);
  @BN_hex2bn := LoadFunctionCLib(fn_BN_hex2bn);
  @BN_bn2dec := LoadFunctionCLib(fn_BN_bn2dec);
  @BN_dec2bn := LoadFunctionCLib(fn_BN_dec2bn);
  @BN_copy := LoadFunctionCLib(fn_BN_copy);
  @BN_dup := LoadFunctionCLib(fn_BN_dup);
  @BN_clear_free := LoadFunctionCLib(fn_BN_clear_free);

  @X509_get_pubkey := LoadFunctionCLib(fn_X509_get_pubkey);

  // SHA related functions
  @SHA256 := LoadFunctionCLib(fn_SHA256);
  @SHA384 := LoadFunctionCLib(fn_SHA384);
  @SHA512 := LoadFunctionCLib(fn_SHA512);

  // RSA related functions
  @RSA_size := LoadFunctionCLib(fn_RSA_size);
  @RSA_sign := LoadFunctionCLib(fn_RSA_sign);
  @RSA_verify := LoadFunctionCLib(fn_RSA_verify);

  // ECDSA related functions
  @ECDSA_size := LoadFunctionCLib(fn_ECDSA_size);
  @ECDSA_SIG_new := LoadFunctionCLib(fn_ECDSA_SIG_new);
  @ECDSA_SIG_free := LoadFunctionCLib(fn_ECDSA_SIG_free);
  @ECDSA_do_sign := LoadFunctionCLib(fn_ECDSA_do_sign);
  @ECDSA_do_verify := LoadFunctionCLib(fn_ECDSA_do_verify);
  @EC_KEY_get0_group := LoadFunctionCLib(fn_EC_KEY_get0_group);
  @EC_KEY_free := LoadFunctionCLib(fn_EC_KEY_free);
  @EC_GROUP_get_degree := LoadFunctionCLib(fn_EC_GROUP_get_degree);
  @d2i_ECDSA_SIG := LoadFunctionCLib(fn_d2i_ECDSA_SIG);
  @i2d_ECDSA_SIG := LoadFunctionCLib(fn_i2d_ECDSA_SIG);

  Result := FLoadErrors = 0;
end;

class procedure JoseSSL.Unload;
begin
  @PEM_read_bio_PUBKEY := nil;
  @PEM_write_bio_PUBKEY := nil;
  @PEM_read_bio_RSA_PUBKEY := nil;
  @PEM_read_bio_ECPrivateKey := nil;
  @EVP_MD_CTX_create := nil;
  @EVP_MD_CTX_destroy := nil;

  @BN_num_bits := nil;
  @BN_bn2bin := nil;
  @BN_bin2bn := nil;
  @BN_bn2hex := nil;
  @BN_hex2bn := nil;
  @BN_bn2dec := nil;
  @BN_dec2bn := nil;
  @BN_copy := nil;
  @BN_dup := nil;
  @BN_clear_free := nil;

  @X509_get_pubkey := nil;

  @ECDSA_SIG_new := nil;
  @ECDSA_SIG_free := nil;
  @EC_KEY_get0_group := nil;
  @EC_KEY_free := nil;
  @EC_GROUP_get_degree := nil;
  @d2i_ECDSA_SIG := nil;
  @i2d_ECDSA_SIG := nil;
end;

end.
