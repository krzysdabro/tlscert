# tlscert
TLS certificate chain viewer

## Usage
```
tlscert https://facebook.com
```
Output:
```
Subject               CN=*.facebook.com,O=Facebook\, Inc.,L=Menlo Park,ST=California,C=US
Issuer                CN=DigiCert SHA2 High Assurance Server CA,OU=www.digicert.com,O=DigiCert Inc,C=US
DNS names             *.facebook.com, *.facebook.net, *.fbcdn.net, *.fbsbx.com, *.messenger.com, facebook.com, messenger.com, *.m.facebook.com, *.xx.fbcdn.net, *.xy.fbcdn.net, *.xz.fbcdn.net
Valid                 yes
Not valid before      2020-05-14 00:00:00 +0000 UTC
Not valid after       2020-08-05 12:00:00 +0000 UTC
Serial number         E8EF818D55D9736AE927EE75E910207
------------------------------
Subject               CN=DigiCert SHA2 High Assurance Server CA,OU=www.digicert.com,O=DigiCert Inc,C=US
Issuer                CN=DigiCert High Assurance EV Root CA,OU=www.digicert.com,O=DigiCert Inc,C=US
Valid                 yes
Not valid before      2013-10-22 12:00:00 +0000 UTC
Not valid after       2028-10-22 12:00:00 +0000 UTC
Serial number         4E1E7A4DC5CF2F36DC02B42B85D159F
```
