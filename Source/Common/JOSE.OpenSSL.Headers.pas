{******************************************************************************}
{                                                                              }
{  Delphi JOSE Library                                                         }
{  Copyright (c) 2015 Paolo Rossi                                              }
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

{$I ..\JOSE.inc}

interface

{$IFDEF RSA_SIGNING}

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
  IdGlobal,
  IdSSLOpenSSLHeaders;

type
  PBytes = ^TBytes;
  PPBIGNUM = ^PBIGNUM;

  JoseSSL = class
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

    // RSASSA-PSS (RFC 7518 3.5). Loaded lazily and non-fatally - see EnsurePSSSupport.
    fn_RSA_padding_add_PKCS1_PSS = 'RSA_padding_add_PKCS1_PSS';
    fn_RSA_verify_PKCS1_PSS = 'RSA_verify_PKCS1_PSS';
    fn_RSA_private_encrypt = 'RSA_private_encrypt';
    fn_RSA_public_decrypt = 'RSA_public_decrypt';
    fn_EVP_sha256 = 'EVP_sha256';
    fn_EVP_sha384 = 'EVP_sha384';
    fn_EVP_sha512 = 'EVP_sha512';

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

    // EC key-material related functions (used by JWK, not by JWS signing)
    fn_EC_KEY_new = 'EC_KEY_new';
    fn_EC_KEY_new_by_curve_name = 'EC_KEY_new_by_curve_name';
    fn_EC_KEY_set_group = 'EC_KEY_set_group';
    fn_EC_KEY_generate_key = 'EC_KEY_generate_key';
    fn_EC_KEY_get0_private_key = 'EC_KEY_get0_private_key';
    fn_EC_KEY_set_private_key = 'EC_KEY_set_private_key';
    fn_EC_KEY_get0_public_key = 'EC_KEY_get0_public_key';
    fn_EC_KEY_set_public_key = 'EC_KEY_set_public_key';
    fn_EC_GROUP_new_by_curve_name = 'EC_GROUP_new_by_curve_name';
    fn_EC_GROUP_free = 'EC_GROUP_free';
    fn_EC_GROUP_get_curve_name = 'EC_GROUP_get_curve_name';
    fn_EC_KEY_set_asn1_flag = 'EC_KEY_set_asn1_flag';
    fn_EC_POINT_new = 'EC_POINT_new';
    fn_EC_POINT_free = 'EC_POINT_free';
    fn_EC_POINT_get_affine_coordinates_GFp = 'EC_POINT_get_affine_coordinates_GFp';
    fn_EC_POINT_set_affine_coordinates_GFp = 'EC_POINT_set_affine_coordinates_GFp';
    fn_BN_CTX_new = 'BN_CTX_new';
    fn_BN_CTX_free = 'BN_CTX_free';
    fn_BN_new = 'BN_new';
    fn_BN_free = 'BN_free';

  public const
    // Numeric ASN1 Object Identifiers
    NID_sha256 = 672;
    NID_sha384 = 673;
    NID_sha512 = 674;
    NID_X9_62_id_ecPublicKey = 408; // EC Key

    // Curve Numeric ASN1 Object Identifiers (JWK crv <-> OpenSSL NID mapping)
    NID_X9_62_prime256v1 = 415; // P-256
    NID_secp384r1 = 715;        // P-384
    NID_secp521r1 = 716;        // P-521
    NID_secp256k1 = 714;        // secp256k1

    // EC_KEY ASN1 encoding flags (EC_KEY_set_asn1_flag): forces the curve to be serialized
    // by its named-curve OID instead of explicit domain parameters, so EC_GROUP_get_curve_name
    // can recover the NID after a PEM write/read round-trip.
    OPENSSL_EC_NAMED_CURVE = $001;

  public class var
    SSLeay_version: function(_type: Integer): PIdAnsiChar cdecl;

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
    BN_bn2hex: function(const a: PBIGNUM): PIdAnsiChar cdecl;
    BN_hex2bn: function(a: PPBIGNUM; str: PIdAnsiChar): Integer; cdecl;
    BN_bn2dec: function(const a: PBIGNUM): PIdAnsiChar cdecl;
    BN_dec2bn: function(a: PPBIGNUM; str: PIdAnsiChar): Integer; cdecl;
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

    // EC key-material related functions (used by JWK, not by JWS signing)
    EC_KEY_new: function(): PEC_KEY cdecl;
    EC_KEY_new_by_curve_name: function(nid: Integer): PEC_KEY cdecl;
    EC_KEY_set_group: function(key: PEC_KEY; const group: PEC_GROUP): Integer cdecl;
    EC_KEY_generate_key: function(key: PEC_KEY): Integer cdecl;
    EC_KEY_get0_private_key: function(const key: PEC_KEY): PBIGNUM cdecl;
    EC_KEY_set_private_key: function(key: PEC_KEY; const prv: PBIGNUM): Integer cdecl;
    EC_KEY_get0_public_key: function(const key: PEC_KEY): PEC_POINT cdecl;
    EC_KEY_set_public_key: function(key: PEC_KEY; const pub: PEC_POINT): Integer cdecl;
    EC_GROUP_new_by_curve_name: function(nid: Integer): PEC_GROUP cdecl;
    EC_GROUP_free: procedure(group: PEC_GROUP) cdecl;
    EC_GROUP_get_curve_name: function(const group: PEC_GROUP): Integer cdecl;
    EC_KEY_set_asn1_flag: procedure(key: PEC_KEY; asn1_flag: Integer) cdecl;
    EC_POINT_new: function(const group: PEC_GROUP): PEC_POINT cdecl;
    EC_POINT_free: procedure(point: PEC_POINT) cdecl;
    EC_POINT_get_affine_coordinates_GFp: function(const group: PEC_GROUP; const point: PEC_POINT; x: PBIGNUM; y: PBIGNUM; ctx: PBN_CTX): Integer cdecl;
    EC_POINT_set_affine_coordinates_GFp: function(const group: PEC_GROUP; point: PEC_POINT; const x: PBIGNUM; const y: PBIGNUM; ctx: PBN_CTX): Integer cdecl;
    BN_CTX_new: function(): PBN_CTX cdecl;
    BN_CTX_free: procedure(c: PBN_CTX) cdecl;
    BN_new: function(): PBIGNUM cdecl;
    BN_free: procedure(a: PBIGNUM) cdecl;

    RSA_padding_add_PKCS1_PSS: function(rsa: PRSA; EM: PByte; const mHash: PByte; const Hash: PEVP_MD; sLen: Integer): Integer cdecl;
    RSA_verify_PKCS1_PSS: function(rsa: PRSA; const mHash: PByte; const Hash: PEVP_MD; const EM: PByte; sLen: Integer): Integer cdecl;
    RSA_private_encrypt: function(flen: Integer; const from: PByte; _to: PByte; rsa: PRSA; padding: Integer): Integer cdecl;
    RSA_public_decrypt: function(flen: Integer; const from: PByte; _to: PByte; rsa: PRSA; padding: Integer): Integer cdecl;
    EVP_sha256: function(): PEVP_MD cdecl;
    EVP_sha384: function(): PEVP_MD cdecl;
    EVP_sha512: function(): PEVP_MD cdecl;

  public class var
    FLoadErrors: Integer;
    FECKeySupportLoaded: Boolean;
    FECKeySupportAvailable: Boolean;
    FPSSSupportLoaded: Boolean;
    FPSSSupportAvailable: Boolean;
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
    /// <summary>
    ///   Lazily loads the low-level EC key-construction symbols (EC_KEY_new_by_curve_name,
    ///   EC_POINT_get/set_affine_coordinates_GFp, etc). Non-fatal: returns False (instead of
    ///   raising) if the loaded OpenSSL library is missing one of these symbols, so that
    ///   oct/RSA-only consumers are never affected by a missing EC symbol.
    /// </summary>
    class function EnsureECKeySupport: Boolean;
    /// <summary>
    ///   Lazily loads the RSASSA-PSS symbols (RSA_padding_add_PKCS1_PSS, RSA_verify_PKCS1_PSS,
    ///   the raw RSA primitives and EVP_sha*). Non-fatal in exactly the same way as
    ///   <c>EnsureECKeySupport</c>: returns False rather than raising, so an OpenSSL build
    ///   without them leaves RS/ES/oct users completely unaffected.
    /// </summary>
    class function EnsurePSSSupport: Boolean;
  end;

{$ENDIF}

implementation

{$IFDEF RSA_SIGNING}

uses
  JOSE.Types.Utils;

resourcestring
  SJOSEErrorLoadingFunction = 'Error loading [%s]';

class function JoseSSL.LoadFunctionCLib(const AFunctionName: string; const ARaiseException: Boolean = True): Pointer;
begin
  Result := {$IFDEF WINDOWS}Windows.{$ENDIF}GetProcAddress(GetCryptLibHandle, PChar(AFunctionName));
  if Result = nil then
  begin
    if ARaiseException then
      raise Exception.CreateFmt(SJOSEErrorLoadingFunction, [AFunctionName])
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

class function JoseSSL.EnsureECKeySupport: Boolean;
var
  LErrors: Integer;
begin
  if FECKeySupportLoaded then
    Exit(FECKeySupportAvailable);

  LErrors := 0;

  @EC_KEY_new := LoadFunctionCLib(fn_EC_KEY_new, False);
  if not Assigned(EC_KEY_new) then Inc(LErrors);
  @EC_KEY_new_by_curve_name := LoadFunctionCLib(fn_EC_KEY_new_by_curve_name, False);
  if not Assigned(EC_KEY_new_by_curve_name) then Inc(LErrors);
  @EC_KEY_set_group := LoadFunctionCLib(fn_EC_KEY_set_group, False);
  if not Assigned(EC_KEY_set_group) then Inc(LErrors);
  @EC_KEY_generate_key := LoadFunctionCLib(fn_EC_KEY_generate_key, False);
  if not Assigned(EC_KEY_generate_key) then Inc(LErrors);
  @EC_KEY_get0_private_key := LoadFunctionCLib(fn_EC_KEY_get0_private_key, False);
  if not Assigned(EC_KEY_get0_private_key) then Inc(LErrors);
  @EC_KEY_set_private_key := LoadFunctionCLib(fn_EC_KEY_set_private_key, False);
  if not Assigned(EC_KEY_set_private_key) then Inc(LErrors);
  @EC_KEY_get0_public_key := LoadFunctionCLib(fn_EC_KEY_get0_public_key, False);
  if not Assigned(EC_KEY_get0_public_key) then Inc(LErrors);
  @EC_KEY_set_public_key := LoadFunctionCLib(fn_EC_KEY_set_public_key, False);
  if not Assigned(EC_KEY_set_public_key) then Inc(LErrors);
  @EC_GROUP_new_by_curve_name := LoadFunctionCLib(fn_EC_GROUP_new_by_curve_name, False);
  if not Assigned(EC_GROUP_new_by_curve_name) then Inc(LErrors);
  @EC_GROUP_free := LoadFunctionCLib(fn_EC_GROUP_free, False);
  if not Assigned(EC_GROUP_free) then Inc(LErrors);
  @EC_GROUP_get_curve_name := LoadFunctionCLib(fn_EC_GROUP_get_curve_name, False);
  if not Assigned(EC_GROUP_get_curve_name) then Inc(LErrors);
  @EC_KEY_set_asn1_flag := LoadFunctionCLib(fn_EC_KEY_set_asn1_flag, False);
  if not Assigned(EC_KEY_set_asn1_flag) then Inc(LErrors);
  @EC_POINT_new := LoadFunctionCLib(fn_EC_POINT_new, False);
  if not Assigned(EC_POINT_new) then Inc(LErrors);
  @EC_POINT_free := LoadFunctionCLib(fn_EC_POINT_free, False);
  if not Assigned(EC_POINT_free) then Inc(LErrors);
  @EC_POINT_get_affine_coordinates_GFp := LoadFunctionCLib(fn_EC_POINT_get_affine_coordinates_GFp, False);
  if not Assigned(EC_POINT_get_affine_coordinates_GFp) then Inc(LErrors);
  @EC_POINT_set_affine_coordinates_GFp := LoadFunctionCLib(fn_EC_POINT_set_affine_coordinates_GFp, False);
  if not Assigned(EC_POINT_set_affine_coordinates_GFp) then Inc(LErrors);
  @BN_CTX_new := LoadFunctionCLib(fn_BN_CTX_new, False);
  if not Assigned(BN_CTX_new) then Inc(LErrors);
  @BN_CTX_free := LoadFunctionCLib(fn_BN_CTX_free, False);
  if not Assigned(BN_CTX_free) then Inc(LErrors);
  @BN_new := LoadFunctionCLib(fn_BN_new, False);
  if not Assigned(BN_new) then Inc(LErrors);
  @BN_free := LoadFunctionCLib(fn_BN_free, False);
  if not Assigned(BN_free) then Inc(LErrors);

  FECKeySupportAvailable := LErrors = 0;
  FECKeySupportLoaded := True;
  Result := FECKeySupportAvailable;
end;

class function JoseSSL.EnsurePSSSupport: Boolean;
var
  LErrors: Integer;
begin
  if FPSSSupportLoaded then
    Exit(FPSSSupportAvailable);

  LErrors := 0;

  @RSA_padding_add_PKCS1_PSS := LoadFunctionCLib(fn_RSA_padding_add_PKCS1_PSS, False);
  if not Assigned(RSA_padding_add_PKCS1_PSS) then Inc(LErrors);
  @RSA_verify_PKCS1_PSS := LoadFunctionCLib(fn_RSA_verify_PKCS1_PSS, False);
  if not Assigned(RSA_verify_PKCS1_PSS) then Inc(LErrors);
  @RSA_private_encrypt := LoadFunctionCLib(fn_RSA_private_encrypt, False);
  if not Assigned(RSA_private_encrypt) then Inc(LErrors);
  @RSA_public_decrypt := LoadFunctionCLib(fn_RSA_public_decrypt, False);
  if not Assigned(RSA_public_decrypt) then Inc(LErrors);
  @EVP_sha256 := LoadFunctionCLib(fn_EVP_sha256, False);
  if not Assigned(EVP_sha256) then Inc(LErrors);
  @EVP_sha384 := LoadFunctionCLib(fn_EVP_sha384, False);
  if not Assigned(EVP_sha384) then Inc(LErrors);
  @EVP_sha512 := LoadFunctionCLib(fn_EVP_sha512, False);
  if not Assigned(EVP_sha512) then Inc(LErrors);

  FPSSSupportAvailable := LErrors = 0;
  FPSSSupportLoaded := True;
  Result := FPSSSupportAvailable;
end;

class function JoseSSL.GetLastError: string;
const
  LErrMsgLength = 160;
var
  LErrMsg: TBytes;
begin
  SetLength(LErrMsg, LErrMsgLength);
  ERR_error_string_n(ERR_get_error, @LErrMsg[0], LErrMsgLength);
  Result := TEncoding.ASCII.GetString(LErrMsg);
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

  @EC_KEY_new := nil;
  @EC_KEY_new_by_curve_name := nil;
  @EC_KEY_set_group := nil;
  @EC_KEY_generate_key := nil;
  @EC_KEY_get0_private_key := nil;
  @EC_KEY_set_private_key := nil;
  @EC_KEY_get0_public_key := nil;
  @EC_KEY_set_public_key := nil;
  @EC_GROUP_new_by_curve_name := nil;
  @EC_GROUP_free := nil;
  @EC_GROUP_get_curve_name := nil;
  @EC_KEY_set_asn1_flag := nil;
  @EC_POINT_new := nil;
  @EC_POINT_free := nil;
  @EC_POINT_get_affine_coordinates_GFp := nil;
  @EC_POINT_set_affine_coordinates_GFp := nil;
  @BN_CTX_new := nil;
  @BN_CTX_free := nil;
  @BN_new := nil;
  @BN_free := nil;
  FECKeySupportLoaded := False;
  FECKeySupportAvailable := False;

  @RSA_padding_add_PKCS1_PSS := nil;
  @RSA_verify_PKCS1_PSS := nil;
  @RSA_private_encrypt := nil;
  @RSA_public_decrypt := nil;
  @EVP_sha256 := nil;
  @EVP_sha384 := nil;
  @EVP_sha512 := nil;
  FPSSSupportLoaded := False;
  FPSSSupportAvailable := False;
end;

{$ENDIF}

end.
