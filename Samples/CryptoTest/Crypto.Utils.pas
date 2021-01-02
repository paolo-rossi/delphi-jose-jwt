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

unit Crypto.Utils;

interface

const
  // Sample key from JWT.IO
  PublicKey =
    '-----BEGIN PUBLIC KEY-----'#13#10 +
    'MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDdlatRjRjogo3WojgGHFHYLugd'#13#10 +
    'UWAY9iR3fy4arWNA1KoS8kVw33cJibXr8bvwUAUparCwlvdbH6dvEOfou0/gCFQs'#13#10 +
    'HUfQrSDv+MuSUMAe8jzKE4qW+jK+xQU9a03GUnKHkkle+Q0pX/g6jXZ7r1/xAK5D'#13#10 +
    'o2kQ+X5xK9cipRgEKwIDAQAB'#13#10 +
    '-----END PUBLIC KEY-----';

  PPPK =
    '-----BEGIN RSA PUBLIC KEY-----'#13#10 +
    'MIIB9AKB9wDYeWoC8B1yAth5agLMw2MAEMFjAPB8bQIA9RkAFeFSAAh2VACgaWwC'#13#10 +
    'K3ZUAGj1GQA5gVQAoGlsAqXbUgBo9RkAgPcZAKBpbAIVAgAAAAAAAIaVAHF27Yl3'#13#10 +
    'FQIAAAAAAABcE7R3AAAAAPz///8AAAAAAAAAALDls3eGlQBxQDKcAvMAAAAAAAAA'#13#10 +
    'XBO0d+ySP2Jc9BkAa76Ld/YNLgAVAgAAAAAAAAAAAAAAAAAAzau63ECUAHEVAgAA'#13#10 +
    'AAAAAET1GQA6g4t3vY6ES/YNLgBE9RkA/IWLd16Di3cbDFujQJQAcfYNLgCLg4t3'#13#10 +
    'OoOLd5WOhEv2DS4AbPUCgfcA2HlqAvAdcgLYeWoCzMNjABDBYwDwfG0CAPUZABXh'#13#10 +
    'UgAIdlQAoGlsAit2VABo9RkAOYFUAKBpbAKl21IAaPUZAID3GQCgaWwCFQIAAAAA'#13#10 +
    'AACGlQBxdu2JdxUCAAAAAAAAXBO0dwAAAAD8////AAAAAAAAAACw5bN3hpUAcUAy'#13#10 +
    'nALzAAAAAAAAAFwTtHfskj9iXPQZAGu+i3f2DS4AFQIAAAAAAAAAAAAAAAAAAM2r'#13#10 +
    'utxAlABxFQIAAAAAAABE9RkAOoOLd72OhEv2DS4ARPUZAPyFi3deg4t3Gwxbo0CU'#13#10 +
    'AHH2DS4Ai4OLdzqDi3eVjoRL9g0uAGz1'#13#10 +
    '-----END RSA PUBLIC KEY-----';


  JWTIO_PK =
    '-----BEGIN PUBLIC KEY-----'#13#10 +
    'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnzyis1ZjfNB0bBgKFMSv'#13#10 +
    'vkTtwlvBsaJq7S5wA+kzeVOVpVWwkWdVha4s38XM/pa/yr47av7+z3VTmvDRyAHc'#13#10 +
    'aT92whREFpLv9cj5lTeJSibyr/Mrm/YtjCZVWgaOYIhwrXwKLqPr/11inWsAkfIy'#13#10 +
    'tvHWTxZYEcXLgAXFuUuaS3uF9gEiNQwzGTU1v0FqkqTBr4B8nW3HCN47XUu0t8Y0'#13#10 +
    'e+lf4s4OxQawWD79J9/5d3Ry0vbV3Am1FtGJiJvOwRsIfVChDpYStTcHTCMqtvWb'#13#10 +
    'V6L11BWkpzGXSW4Hv43qa+GSYOD2QU68Mb59oSk2OB+BtOLpJofmbGEGgvmwyCI9'#13#10 +
    'MwIDAQAB'#13#10 +
    '-----END PUBLIC KEY-----';

  PK =
    '-----BEGIN PUBLIC KEY-----'#13#10 +
    'MDEwDQYJKoZIhvcNAQEBBQADIAAwHQIWALII4ZZOo6ffLoKffLqd+IaXsWpqZQID'#13#10 +
    'AQAB'#13#10 +
    '-----END PUBLIC KEY-----'#13#10;


implementation

end.
