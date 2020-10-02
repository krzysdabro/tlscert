# tlscert
TLS certificate chain viewer

## Installation
```
go install github.com/krzysdabro/tlscert
```

## Usage
```
tlscert facebook.com:443
```

Output:
```
Subject
  Common Name           *.facebook.com
  Organization          Facebook, Inc.
  Locality              Menlo Park
  State/Province        California
  Country               US
Issuer
  Common Name           DigiCert SHA2 High Assurance Server CA
  Organization Unit     www.digicert.com
  Organization          DigiCert Inc
  Country               US
DNS Name                *.facebook.com
DNS Name                *.facebook.net
DNS Name                *.fbcdn.net
DNS Name                *.fbsbx.com
DNS Name                *.m.facebook.com
DNS Name                *.messenger.com
DNS Name                *.xx.fbcdn.net
DNS Name                *.xy.fbcdn.net
DNS Name                *.xz.fbcdn.net
DNS Name                facebook.com
DNS Name                messenger.com
Valid                   yes
Not Valid Before        2020-09-11 02:00:00 +0200 CEST
Not Valid After         2020-12-10 13:00:00 +0100 CET
Serial Number           04 FF 68 11 BE 24 1A CF 41 31 8D B5 6E E5 C9 43
```
