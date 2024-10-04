object frmCryptoRSA: TfrmCryptoRSA
  Left = 0
  Top = 0
  Caption = 'frmCryptoRSA'
  ClientHeight = 521
  ClientWidth = 1020
  Color = clBtnFace
  Font.Charset = DEFAULT_CHARSET
  Font.Color = clWindowText
  Font.Height = -11
  Font.Name = 'Tahoma'
  Font.Style = []
  OldCreateOrder = False
  PixelsPerInch = 96
  TextHeight = 13
  object memoPayload: TMemo
    Left = 94
    Top = 8
    Width = 417
    Height = 133
    Font.Charset = ANSI_CHARSET
    Font.Color = clWindowText
    Font.Height = -13
    Font.Name = 'Courier New'
    Font.Style = []
    Lines.Strings = (
      
        'eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiw' +
        'ibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0')
    ParentFont = False
    TabOrder = 0
    WantReturns = False
    WordWrap = False
  end
  object memoSignature: TMemo
    Left = 94
    Top = 147
    Width = 417
    Height = 62
    Font.Charset = ANSI_CHARSET
    Font.Color = clWindowText
    Font.Height = -13
    Font.Name = 'Courier New'
    Font.Style = []
    Lines.Strings = (
      'Signature')
    ParentFont = False
    TabOrder = 1
  end
  object memoPrivateKey: TMemo
    Left = 533
    Top = 147
    Width = 417
    Height = 133
    Font.Charset = ANSI_CHARSET
    Font.Color = clWindowText
    Font.Height = -13
    Font.Name = 'Courier New'
    Font.Style = []
    Lines.Strings = (
      '-----BEGIN RSA PRIVATE KEY-----'
      'MIIEogIBAAKCAQEAnzyis1ZjfNB0bBgKFMSvvkTtwlvBsaJq7S5wA+kzeVOVpVWw'
      'kWdVha4s38XM/pa/yr47av7+z3VTmvDRyAHcaT92whREFpLv9cj5lTeJSibyr/Mr'
      'm/YtjCZVWgaOYIhwrXwKLqPr/11inWsAkfIytvHWTxZYEcXLgAXFuUuaS3uF9gEi'
      'NQwzGTU1v0FqkqTBr4B8nW3HCN47XUu0t8Y0e+lf4s4OxQawWD79J9/5d3Ry0vbV'
      '3Am1FtGJiJvOwRsIfVChDpYStTcHTCMqtvWbV6L11BWkpzGXSW4Hv43qa+GSYOD2'
      'QU68Mb59oSk2OB+BtOLpJofmbGEGgvmwyCI9MwIDAQABAoIBACiARq2wkltjtcjs'
      'kFvZ7w1JAORHbEufEO1Eu27zOIlqbgyAcAl7q+/1bip4Z/x1IVES84/yTaM8p0go'
      'amMhvgry/mS8vNi1BN2SAZEnb/7xSxbflb70bX9RHLJqKnp5GZe2jexw+wyXlwaM'
      '+bclUCrh9e1ltH7IvUrRrQnFJfh+is1fRon9Co9Li0GwoN0x0byrrngU8Ak3Y6D9'
      'D8GjQA4Elm94ST3izJv8iCOLSDBmzsPsXfcCUZfmTfZ5DbUDMbMxRnSo3nQeoKGC'
      '0Lj9FkWcfmLcpGlSXTO+Ww1L7EGq+PT3NtRae1FZPwjddQ1/4V905kyQFLamAA5Y'
      'lSpE2wkCgYEAy1OPLQcZt4NQnQzPz2SBJqQN2P5u3vXl+zNVKP8w4eBv0vWuJJF+'
      'hkGNnSxXQrTkvDOIUddSKOzHHgSg4nY6K02ecyT0PPm/UZvtRpWrnBjcEVtHEJNp'
      'bU9pLD5iZ0J9sbzPU/LxPmuAP2Bs8JmTn6aFRspFrP7W0s1Nmk2jsm0CgYEAyH0X'
      '+jpoqxj4efZfkUrg5GbSEhf+dZglf0tTOA5bVg8IYwtmNk/pniLG/zI7c+GlTc9B'
      'BwfMr59EzBq/eFMI7+LgXaVUsM/sS4Ry+yeK6SJx/otIMWtDfqxsLD8CPMCRvecC'
      '2Pip4uSgrl0MOebl9XKp57GoaUWRWRHqwV4Y6h8CgYAZhI4mh4qZtnhKjY4TKDjx'
      'QYufXSdLAi9v3FxmvchDwOgn4L+PRVdMwDNms2bsL0m5uPn104EzM6w1vzz1zwKz'
      '5pTpPI0OjgWN13Tq8+PKvm/4Ga2MjgOgPWQkslulO/oMcXbPwWC3hcRdr9tcQtn9'
      'Imf9n2spL/6EDFId+Hp/7QKBgAqlWdiXsWckdE1Fn91/NGHsc8syKvjjk1onDcw0'
      'NvVi5vcba9oGdElJX3e9mxqUKMrw7msJJv1MX8LWyMQC5L6YNYHDfbPF1q5L4i8j'
      '8mRex97UVokJQRRA452V2vCO6S5ETgpnad36de3MUxHgCOX3qL382Qx9/THVmbma'
      '3YfRAoGAUxL/Eu5yvMK8SAt/dJK6FedngcM3JEFNplmtLYVLWhkIlNRGDwkg3I5K'
      'y18Ae9n7dHVueyslrb6weq7dTkYDi3iOYRW8HRkIQh06wEdbxt0shTzAJvvCQfrB'
      'jg/3747WSsf/zBTcHihTRBdAv6OmdhV4/dD5YBfLAkLrd+mX7iE='
      '-----END RSA PRIVATE KEY-----')
    ParentFont = False
    TabOrder = 2
    WantReturns = False
    WordWrap = False
  end
  object memoPublicKey: TMemo
    Left = 533
    Top = 8
    Width = 417
    Height = 133
    Font.Charset = ANSI_CHARSET
    Font.Color = clWindowText
    Font.Height = -13
    Font.Name = 'Courier New'
    Font.Style = []
    Lines.Strings = (
      '-----BEGIN PUBLIC KEY-----'
      'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEpxD52WR65kGaNMX9dGl444fATtIS'
      'wqqIE6SVqAZK+3xA0b5LW/SS8XTvmwGcPi4th1JuWvKpSWIGwQ3+6xh8hA=='
      '-----END PUBLIC KEY-----')
    ParentFont = False
    TabOrder = 3
    WantReturns = False
    WordWrap = False
  end
  object memoCertificate: TMemo
    Left = 94
    Top = 215
    Width = 417
    Height = 201
    Lines.Strings = (
      '-----BEGIN CERTIFICATE-----'
      'MIIFjzCCA3egAwIBAgIUXAPJDPALopHhAi24Yazxb9dUGs0wDQYJKoZIhvcNAQEL'
      'BQAwVzELMAkGA1UEBhMCSVQxEzARBgNVBAgMClNvbWUtU3RhdGUxETAPBgNVBAcM'
      'CFBpYWNlbnphMRAwDgYDVQQKDAdXaW50ZWNoMQ4wDAYDVQQDDAVQYW9sbzAeFw0y'
      'MDEyMjIxMDQxNTBaFw0yMTEyMTcxMDQxNTBaMFcxCzAJBgNVBAYTAklUMRMwEQYD'
      'VQQIDApTb21lLVN0YXRlMREwDwYDVQQHDAhQaWFjZW56YTEQMA4GA1UECgwHV2lu'
      'dGVjaDEOMAwGA1UEAwwFUGFvbG8wggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIK'
      'AoICAQDj2YF3h6DUv8MAK5MXG25me0dCS5+JnYPt/OfYMoTXuWtuzkq0zsSAaEwx'
      'uPtIVAHB5rfSeFQd5aEw9Kre2oLzEaceL4I84eImbbaf2dzQDfcUJfMiDWPlnNzd'
      'rzZJg2MvGLgFAoLNKKSY26FYnXM1aOVcUZjnW4JN/2l38bo+dF02do+GbNzm9OPT'
      '+P1tcPwtSpQ1vHt6zmuxtnneS87KevsEmekQY4d8eTutN1aVLLa+dKDCYxoBn1JX'
      'rC7GK/T5JemVIogbnqJoa3wq+/qByDQolUCGB8e7Q72+L5a8JXWA+XpZ4eO+vq7b'
      '5b7i+AXiptnP02Xl84cFQRUqGIhgLFE5Y5Fn26aalZX7Utn8M2sPhr89R7xfFVUD'
      'R/sxUFG2qTD/0xOGbEPDgWg7JjBCQFrbiNQ4w7z1DNQolvulRlAFiTatySv2xgb2'
      'bs516vV7eKV6br0fUV1LKA1bucSztfkRbGKPgZAGskKVfE33uBlaIEcZ2b03cFHY'
      'zzDInCiOBc0BZTZcUhYlo9f+lxb84GowqU0myurOlUMsPOFsQw2JG2BEuNN14GUS'
      '/4i+0c3hZoTnCIdXrNBuCoPRrRqQJLenBPkmzOwvTTwSe0o+N/jJyMCNXG5frCiJ'
      '8GM9WB5dNvFNlRCv95rFUAxvrBLgxFy544gQu6kkthstp5+4NQIDAQABo1MwUTAd'
      'BgNVHQ4EFgQUfSXdPT10YtvLG7L9h6grVuqt8H8wHwYDVR0jBBgwFoAUfSXdPT10'
      'YtvLG7L9h6grVuqt8H8wDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOC'
      'AgEAw56NQR98TwtjIP3wihLSLISQ+7oGYBB4pNwVUs2XCOeRpcPQkUSgz9+RST4Z'
      'TQozmSvn4PI1Vh5KpFbqqVNpDvtGnXmUsRrUtoRGwQQWmRzK7pg/Rj4loM6GBmWd'
      'AtViQPhQD3XjqAXuH4eBZ/50vsqt2kYiBUDWrJeLIVAGRVwH926GEb5uy7E0gC/V'
      'HE95v+vEEFKai6jxNuI5yZFNoxYgY/eTHYw2ZI4HAWQ0aqlVfcObearTmqkdfO5c'
      'IYcgSc1rMhNQFbMZ2iQg1KzebfQtO1XCD5CtPtpgdbbCSljqrxkxSCHVQ4Ccdw0r'
      'MyFFZPZvdR+2Zx7McwDXaymxflHvE8U9ehdTcRe/bL6IaCPo8NcNk/D68GOPXH79'
      '08grsiwW31mvUdZG+r7a9AgV2DT6Wf7BbdiqE5jDkOVAjZUwrtsZrHx8AcrnGHU+'
      'mBr0dIDVyOf81A/I++6rl/+ArclhSHvzc7fej+2mnMuR0DXv7qJZD+74xOl1ga1f'
      'ltiRjfIiC61ikuvxugDxfNHGLSrAjnKYkzj6rcUJV55YMFR3MoiT0I5EAcYXfnT7'
      'wO6H/VnVCKsTqUKbG6tZOdDPrl74y3R1iT6QMpg3BQdMGJwLS1GEyWZL8rJ6aM7h'
      'Qwr+PQlsZUJCq2yDLreLoUmjsIc+t3mzmqrTmvGyGbshcEo='
      '-----END CERTIFICATE-----')
    TabOrder = 4
    WantReturns = False
    WordWrap = False
  end
  object btnCertificate: TButton
    Left = 8
    Top = 255
    Width = 75
    Height = 25
    Caption = 'Certificate'
    TabOrder = 5
    OnClick = btnCertificateClick
  end
  object btnRSASign: TButton
    Left = 8
    Top = 8
    Width = 75
    Height = 25
    Caption = 'RSA Sign'
    TabOrder = 6
    OnClick = btnRSASignClick
  end
end
