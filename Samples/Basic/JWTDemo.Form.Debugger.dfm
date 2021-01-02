object frmDebugger: TfrmDebugger
  Left = 0
  Top = 0
  Caption = 'Debugger'
  ClientHeight = 695
  ClientWidth = 838
  Color = clBtnFace
  Font.Charset = DEFAULT_CHARSET
  Font.Color = clWindowText
  Font.Height = -11
  Font.Name = 'Tahoma'
  Font.Style = []
  OldCreateOrder = False
  OnCreate = FormCreate
  OnDestroy = FormDestroy
  DesignSize = (
    838
    695)
  PixelsPerInch = 96
  TextHeight = 13
  object shpStatus: TShape
    Left = 8
    Top = 605
    Width = 822
    Height = 65
    Anchors = [akLeft, akRight]
    Brush.Color = 15841536
  end
  object lblEncoded: TLabel
    Left = 8
    Top = 48
    Width = 68
    Height = 19
    Caption = 'Encoded'
    Font.Charset = DEFAULT_CHARSET
    Font.Color = clWindowText
    Font.Height = -16
    Font.Name = 'Tahoma'
    Font.Style = [fsBold]
    ParentFont = False
  end
  object lblDecoded: TLabel
    Left = 507
    Top = 48
    Width = 70
    Height = 19
    Caption = 'Decoded'
    Font.Charset = DEFAULT_CHARSET
    Font.Color = clWindowText
    Font.Height = -16
    Font.Name = 'Tahoma'
    Font.Style = [fsBold]
    ParentFont = False
  end
  object lblStatus: TLabel
    Left = 297
    Top = 621
    Width = 244
    Height = 29
    Anchors = [akBottom]
    Caption = 'Signature Verified'
    Font.Charset = ANSI_CHARSET
    Font.Color = clWhite
    Font.Height = -24
    Font.Name = 'Verdana'
    Font.Style = [fsBold]
    ParentFont = False
  end
  object pnlSignatureRSA: TPanel
    Left = 507
    Top = 320
    Width = 323
    Height = 281
    Anchors = [akTop, akRight, akBottom]
    TabOrder = 2
    object lblSignatureRSA: TLabel
      Left = 1
      Top = 1
      Width = 321
      Height = 19
      Align = alTop
      Caption = ' Verify Signature'
      Color = clBlack
      Font.Charset = DEFAULT_CHARSET
      Font.Color = clWhite
      Font.Height = -16
      Font.Name = 'Tahoma'
      Font.Style = []
      ParentColor = False
      ParentFont = False
      Transparent = False
      ExplicitWidth = 118
    end
    object lblRSA: TLabel
      Left = 8
      Top = 26
      Width = 297
      Height = 247
      Caption = 
        'RSASHA%s('#13#10'  base64UrlEncode(header) + "." +'#13#10'  base64UrlEncode(' +
        'payload),'#13#10#13#10#13#10#13#10#13#10#13#10#13#10#13#10#13#10#13#10')'
      Font.Charset = ANSI_CHARSET
      Font.Color = 15841536
      Font.Height = -16
      Font.Name = 'Consolas'
      Font.Style = []
      ParentFont = False
    end
    object memoPublicKeyRSA: TMemo
      Left = 25
      Top = 89
      Width = 280
      Height = 79
      Font.Charset = ANSI_CHARSET
      Font.Color = 15841536
      Font.Height = -16
      Font.Name = 'Consolas'
      Font.Style = []
      Lines.Strings = (
        '-----BEGIN PUBLIC KEY-----'
        'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnzyis1ZjfNB0bBgKFMSv'
        'vkTtwlvBsaJq7S5wA+kzeVOVpVWwkWdVha4s38XM/pa/yr47av7+z3VTmvDRyAHc'
        'aT92whREFpLv9cj5lTeJSibyr/Mrm/YtjCZVWgaOYIhwrXwKLqPr/11inWsAkfIy'
        'tvHWTxZYEcXLgAXFuUuaS3uF9gEiNQwzGTU1v0FqkqTBr4B8nW3HCN47XUu0t8Y0'
        'e+lf4s4OxQawWD79J9/5d3Ry0vbV3Am1FtGJiJvOwRsIfVChDpYStTcHTCMqtvWb'
        'V6L11BWkpzGXSW4Hv43qa+GSYOD2QU68Mb59oSk2OB+BtOLpJofmbGEGgvmwyCI9'
        'MwIDAQAB'
        '-----END PUBLIC KEY-----')
      ParentFont = False
      ScrollBars = ssVertical
      TabOrder = 0
      WantReturns = False
      WordWrap = False
      OnChange = memoPublicKeyRSAChange
    end
    object memoPrivateKeyRSA: TMemo
      Left = 25
      Top = 174
      Width = 280
      Height = 79
      Font.Charset = ANSI_CHARSET
      Font.Color = 15841536
      Font.Height = -16
      Font.Name = 'Consolas'
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
      ScrollBars = ssVertical
      TabOrder = 1
      WantReturns = False
      WordWrap = False
      OnChange = memoPrivateKeyRSAChange
    end
  end
  object richEncoded: TRichEdit
    Left = 9
    Top = 73
    Width = 493
    Height = 528
    Anchors = [akLeft, akTop, akRight, akBottom]
    Font.Charset = ANSI_CHARSET
    Font.Color = clBlack
    Font.Height = -19
    Font.Name = 'Consolas'
    Font.Style = [fsBold]
    HideSelection = False
    HideScrollBars = False
    ParentFont = False
    ScrollBars = ssVertical
    TabOrder = 0
    WantReturns = False
    Zoom = 100
  end
  object pnlPayload: TPanel
    Left = 507
    Top = 191
    Width = 323
    Height = 123
    Anchors = [akTop, akRight]
    BevelOuter = bvNone
    TabOrder = 3
    object lblPayload: TLabel
      Left = 0
      Top = 0
      Width = 323
      Height = 19
      Margins.Left = 10
      Margins.Top = 10
      Margins.Right = 10
      Margins.Bottom = 10
      Align = alTop
      Caption = ' Payload: Data'
      Color = clBlack
      Font.Charset = DEFAULT_CHARSET
      Font.Color = clWhite
      Font.Height = -16
      Font.Name = 'Tahoma'
      Font.Style = []
      ParentColor = False
      ParentFont = False
      Transparent = False
      ExplicitWidth = 103
    end
    object memoPayload: TMemo
      Left = 0
      Top = 19
      Width = 323
      Height = 104
      Align = alClient
      Font.Charset = ANSI_CHARSET
      Font.Color = clFuchsia
      Font.Height = -16
      Font.Name = 'Consolas'
      Font.Style = []
      Lines.Strings = (
        '{'
        '  "sub": "1234567890",'
        '  "name": "John Doe",'
        '  "iat": 1516239022'
        '}')
      ParentFont = False
      ScrollBars = ssVertical
      TabOrder = 0
      OnChange = memoPayloadChange
    end
  end
  object pnlHeader: TPanel
    Left = 507
    Top = 73
    Width = 323
    Height = 112
    Anchors = [akTop, akRight]
    BevelOuter = bvNone
    TabOrder = 4
    object lblHeader: TLabel
      Left = 0
      Top = 0
      Width = 323
      Height = 19
      Margins.Left = 10
      Margins.Top = 10
      Margins.Right = 10
      Margins.Bottom = 10
      Align = alTop
      Caption = ' Header: Algorithm && Token Type'
      Color = clBlack
      Font.Charset = DEFAULT_CHARSET
      Font.Color = clWhite
      Font.Height = -16
      Font.Name = 'Tahoma'
      Font.Style = []
      ParentColor = False
      ParentFont = False
      Transparent = False
      ExplicitWidth = 242
    end
    object memoHeader: TMemo
      Left = 0
      Top = 19
      Width = 323
      Height = 93
      Align = alClient
      Font.Charset = ANSI_CHARSET
      Font.Color = clRed
      Font.Height = -16
      Font.Name = 'Consolas'
      Font.Style = []
      Lines.Strings = (
        '{'
        '  "alg": "%s",'
        '  "typ": "JWT"'
        '}')
      ParentFont = False
      ScrollBars = ssVertical
      TabOrder = 0
      OnChange = memoHeaderChange
    end
  end
  object pnlAlgorithm: TPanel
    Left = 0
    Top = 0
    Width = 838
    Height = 41
    Align = alTop
    Color = clBlack
    ParentBackground = False
    TabOrder = 5
    DesignSize = (
      838
      41)
    object lblAlgorithm: TLabel
      Left = 310
      Top = 11
      Width = 81
      Height = 19
      Alignment = taCenter
      Anchors = [akTop]
      Caption = 'Algorithm'
      Font.Charset = DEFAULT_CHARSET
      Font.Color = clWhite
      Font.Height = -16
      Font.Name = 'Tahoma'
      Font.Style = [fsBold]
      ParentFont = False
    end
    object cbbDebuggerAlgo: TComboBox
      Left = 401
      Top = 11
      Width = 101
      Height = 24
      Style = csDropDownList
      Anchors = [akTop]
      Font.Charset = DEFAULT_CHARSET
      Font.Color = clWindowText
      Font.Height = -13
      Font.Name = 'Tahoma'
      Font.Style = []
      ItemIndex = 0
      ParentFont = False
      TabOrder = 0
      Text = 'HS256'
      OnChange = cbbDebuggerAlgoChange
      Items.Strings = (
        'HS256'
        'HS384'
        'HS512'
        'RS256'
        'RS384'
        'RS512'
        'ES256'
        'ES256K'
        'ES384'
        'ES512')
    end
  end
  object statusDebugger: TStatusBar
    Left = 0
    Top = 676
    Width = 838
    Height = 19
    Panels = <
      item
        Text = 'Error:'
        Width = 50
      end
      item
        Width = 400
      end
      item
        Width = 50
      end>
  end
  object pnlSignatureECDSA: TPanel
    Left = 507
    Top = 320
    Width = 323
    Height = 281
    Anchors = [akTop, akRight, akBottom]
    TabOrder = 7
    object lblSignatureECDSA: TLabel
      Left = 1
      Top = 1
      Width = 321
      Height = 19
      Align = alTop
      Caption = ' Verify Signature'
      Color = clBlack
      Font.Charset = DEFAULT_CHARSET
      Font.Color = clWhite
      Font.Height = -16
      Font.Name = 'Tahoma'
      Font.Style = []
      ParentColor = False
      ParentFont = False
      Transparent = False
      ExplicitWidth = 118
    end
    object lblECDSA: TLabel
      Left = 7
      Top = 26
      Width = 297
      Height = 247
      Caption = 
        'ECDSASHA%s('#13#10'  base64UrlEncode(header) + "." +'#13#10'  base64UrlEncod' +
        'e(payload),'#13#10#13#10#13#10#13#10#13#10#13#10#13#10#13#10#13#10#13#10')'
      Font.Charset = ANSI_CHARSET
      Font.Color = 15841536
      Font.Height = -16
      Font.Name = 'Consolas'
      Font.Style = []
      ParentFont = False
    end
    object memoPublicKeyECDSA: TMemo
      Left = 25
      Top = 89
      Width = 280
      Height = 79
      Font.Charset = ANSI_CHARSET
      Font.Color = 15841536
      Font.Height = -16
      Font.Name = 'Consolas'
      Font.Style = []
      Lines.Strings = (
        '-----BEGIN PUBLIC KEY-----'
        'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE/zRQfSF8eJ5lLtpMLK78IFWLhbCY'
        '3A31Qu5BtdzSZu/kC2A039WijHslorU7eBWe+n9y5ei8MdC0F19Yoij0kA=='
        '-----END PUBLIC KEY-----')
      ParentFont = False
      ScrollBars = ssVertical
      TabOrder = 0
      WantReturns = False
      WordWrap = False
      OnChange = memoPublicKeyECDSAChange
    end
    object memoPrivateKeyECDSA: TMemo
      Left = 25
      Top = 174
      Width = 280
      Height = 79
      Font.Charset = ANSI_CHARSET
      Font.Color = 15841536
      Font.Height = -16
      Font.Name = 'Consolas'
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
      ScrollBars = ssVertical
      TabOrder = 1
      WantReturns = False
      WordWrap = False
      OnChange = memoPrivateKeyECDSAChange
    end
  end
  object pnlSignatureSHA: TPanel
    Left = 507
    Top = 320
    Width = 323
    Height = 281
    Anchors = [akTop, akRight, akBottom]
    TabOrder = 1
    object lblSignatureSHA: TLabel
      Left = 1
      Top = 1
      Width = 321
      Height = 19
      Align = alTop
      Caption = ' Verify Signature'
      Color = clBlack
      Font.Charset = DEFAULT_CHARSET
      Font.Color = clWhite
      Font.Height = -16
      Font.Name = 'Tahoma'
      Font.Style = []
      ParentColor = False
      ParentFont = False
      Transparent = False
      ExplicitWidth = 118
    end
    object lblHMAC: TLabel
      Left = 7
      Top = 26
      Width = 297
      Height = 171
      Caption = 
        'HMACSHA%s('#13#10'  base64UrlEncode(header) + "." +'#13#10'  base64UrlEncode' +
        '(payload),'#13#10#13#10#13#10#13#10#13#10#13#10')'
      Font.Charset = ANSI_CHARSET
      Font.Color = 15841536
      Font.Height = -16
      Font.Name = 'Consolas'
      Font.Style = []
      ParentFont = False
    end
    object chkKeyBase64: TCheckBox
      Left = 25
      Top = 179
      Width = 238
      Height = 17
      ParentCustomHint = False
      Caption = 'secret base64 encoded'
      Color = clBtnFace
      Ctl3D = True
      Font.Charset = ANSI_CHARSET
      Font.Color = clTeal
      Font.Height = -16
      Font.Name = 'Consolas'
      Font.Style = [fsBold]
      ParentColor = False
      ParentCtl3D = False
      ParentFont = False
      TabOrder = 0
      OnClick = chkKeyBase64Click
    end
    object memoSecretHMAC: TMemo
      Left = 25
      Top = 90
      Width = 280
      Height = 79
      Font.Charset = ANSI_CHARSET
      Font.Color = 15841536
      Font.Height = -16
      Font.Name = 'Consolas'
      Font.Style = []
      Lines.Strings = (
        'your-%s-bit-secret')
      ParentFont = False
      ScrollBars = ssVertical
      TabOrder = 1
      WantReturns = False
      WordWrap = False
      OnChange = memoSecretHMACChange
    end
  end
  object dlgOpenPEMFile: TOpenTextFileDialog
    DefaultExt = '.pem'
    Filter = 'PEM File|*.pem'
    Left = 640
    Top = 536
  end
end
