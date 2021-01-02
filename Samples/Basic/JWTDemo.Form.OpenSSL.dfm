object frmOpenSSL: TfrmOpenSSL
  Left = 0
  Top = 0
  Caption = 'frmOpenSSL'
  ClientHeight = 725
  ClientWidth = 987
  Color = clBtnFace
  Font.Charset = DEFAULT_CHARSET
  Font.Color = clWindowText
  Font.Height = -11
  Font.Name = 'Tahoma'
  Font.Style = []
  OldCreateOrder = False
  DesignSize = (
    987
    725)
  PixelsPerInch = 96
  TextHeight = 13
  object pnlSignatureRSA: TPanel
    Left = 8
    Top = 304
    Width = 457
    Height = 411
    Anchors = [akLeft, akTop, akBottom]
    TabOrder = 0
    DesignSize = (
      457
      411)
    object lblSignatureRSA: TLabel
      Left = 1
      Top = 1
      Width = 455
      Height = 19
      Align = alTop
      Caption = 'RSA KeyPair'
      Color = clBlack
      Font.Charset = DEFAULT_CHARSET
      Font.Color = clWhite
      Font.Height = -16
      Font.Name = 'Tahoma'
      Font.Style = []
      ParentColor = False
      ParentFont = False
      Transparent = False
      ExplicitWidth = 87
    end
    object lblRSA: TLabel
      Left = 9
      Top = 25
      Width = 99
      Height = 19
      Caption = 'Public Key:'
      Font.Charset = ANSI_CHARSET
      Font.Color = 15841536
      Font.Height = -16
      Font.Name = 'Consolas'
      Font.Style = []
      ParentFont = False
    end
    object Label1: TLabel
      Left = 9
      Top = 215
      Width = 108
      Height = 19
      Caption = 'Private Key:'
      Font.Charset = ANSI_CHARSET
      Font.Color = clFuchsia
      Font.Height = -16
      Font.Name = 'Consolas'
      Font.Style = []
      ParentFont = False
    end
    object memoPublicKey: TMemo
      Left = 9
      Top = 50
      Width = 432
      Height = 159
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
    end
    object memoPrivateKey: TMemo
      Left = 9
      Top = 240
      Width = 432
      Height = 159
      Anchors = [akLeft, akTop, akBottom]
      Font.Charset = ANSI_CHARSET
      Font.Color = clFuchsia
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
    end
  end
  object pnlPlainText: TPanel
    Left = 8
    Top = 55
    Width = 971
    Height = 243
    Anchors = [akLeft, akTop, akRight]
    TabOrder = 1
    DesignSize = (
      971
      243)
    object lblPlainText: TLabel
      Left = 1
      Top = 1
      Width = 969
      Height = 19
      Align = alTop
      Caption = 'Text to sign'
      Color = clBlack
      Font.Charset = DEFAULT_CHARSET
      Font.Color = clWhite
      Font.Height = -16
      Font.Name = 'Tahoma'
      Font.Style = []
      ParentColor = False
      ParentFont = False
      Transparent = False
      ExplicitWidth = 84
    end
    object memoPlainText: TMemo
      Left = 17
      Top = 26
      Width = 831
      Height = 207
      Anchors = [akLeft, akTop, akRight]
      Font.Charset = ANSI_CHARSET
      Font.Color = clMaroon
      Font.Height = -16
      Font.Name = 'Consolas'
      Font.Style = []
      Lines.Strings = (
        '(request-target): get /wally-services/protocol/tests/signature'
        'host: staging.authservices.satispay.com'
        'date: Mon, 18 Mar 2019 15:10:24 +0000'
        'digest: SHA-256=47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=')
      ParentFont = False
      ScrollBars = ssVertical
      TabOrder = 0
      WantReturns = False
      WordWrap = False
    end
    object rgTerminator: TRadioGroup
      Left = 854
      Top = 26
      Width = 104
      Height = 207
      Anchors = [akTop, akRight]
      Caption = 'Terminator'
      ItemIndex = 0
      Items.Strings = (
        'CRLF'
        'CR'
        'LF'
        'No CRLF')
      TabOrder = 1
      WordWrap = True
    end
  end
  object pnlAlgorithm: TPanel
    Left = 0
    Top = 0
    Width = 987
    Height = 41
    Align = alTop
    Color = clBlack
    ParentBackground = False
    TabOrder = 2
    DesignSize = (
      987
      41)
    object lblAlgorithm: TLabel
      Left = 359
      Top = 9
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
      Left = 446
      Top = 7
      Width = 102
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
      Text = 'RS256'
      Items.Strings = (
        'RS256'
        'RS384'
        'RS512')
    end
    object btnSign: TButton
      Left = 556
      Top = 7
      Width = 88
      Height = 25
      Anchors = [akTop, akBottom]
      Caption = 'Sign'
      TabOrder = 1
      OnClick = btnSignClick
    end
  end
  object pnlSignedText: TPanel
    Left = 477
    Top = 304
    Width = 501
    Height = 411
    Anchors = [akLeft, akTop, akRight, akBottom]
    TabOrder = 3
    DesignSize = (
      501
      411)
    object lblSignedText: TLabel
      Left = 1
      Top = 1
      Width = 499
      Height = 19
      Align = alTop
      Caption = 'Signed Text'
      Color = clBlack
      Font.Charset = DEFAULT_CHARSET
      Font.Color = clWhite
      Font.Height = -16
      Font.Name = 'Tahoma'
      Font.Style = []
      ParentColor = False
      ParentFont = False
      Transparent = False
      ExplicitWidth = 84
    end
    object memoSignedText: TMemo
      Left = 9
      Top = 26
      Width = 480
      Height = 372
      Anchors = [akLeft, akTop, akRight, akBottom]
      Font.Charset = ANSI_CHARSET
      Font.Color = clMaroon
      Font.Height = -16
      Font.Name = 'Consolas'
      Font.Style = []
      ParentFont = False
      ScrollBars = ssVertical
      TabOrder = 0
      WantReturns = False
    end
  end
end
