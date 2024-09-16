unit JOSE.Encryption.RSA;

interface

uses
  System.SysUtils,
  IdSSLOpenSSLHeaders,
  JOSE.Signing.Base;

type
  TRSAEncryption = class(TSigningBase)
  private
    class function LoadRSAPublicKeyFromCert(const ACertificate: TBytes): PRSA;
  public
    class function EncryptWithPublicCertificate(const ACertificate, AValue: TBytes): TBytes;
  end;

implementation

class function TRSAEncryption.LoadRSAPublicKeyFromCert(const ACertificate: TBytes): PRSA;
var
  LKey: PEVP_PKEY;
begin
  LKey := LoadPublicKeyFromCert(ACertificate, NID_rsaEncryption);
  try
    Result := EVP_PKEY_get1_RSA(LKey);
    if not Assigned(Result) then
      raise ESignException.Create('[RSA] Error extracting RSA key from EVP_PKEY');
  finally
    EVP_PKEY_free(LKey);
  end;
end;

class function TRSAEncryption.EncryptWithPublicCertificate(const ACertificate, AValue: TBytes): TBytes;
begin

  var RSA := LoadRSAPublicKeyFromCert(ACertificate);
  try

    SetLength(Result, RSA_size(rsa));
    var EncryptedLen := RSA_public_encrypt(Length(AValue), PByte(AValue), @Result[0], RSA, RSA_PKCS1_PADDING);

    if encryptedLen = -1 then
      raise ESignException.Create('[RSA] Error encrypting');

    SetLength(Result, EncryptedLen);

  finally
    RSA_free(RSA);
  end;

end;

end.
