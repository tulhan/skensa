# Skensa

## About
Skensa is an SSL/TLS cipher enumeration tool. Aside from enumeration, skensa also aims to detect common cipher and certificate misconfigurations.

Skensa is a portmanteau of the words SSL and the japanese work 'kensa' which means to inspect.

## Build

Skensa currently only works in linux. A make file is included for building from source.

To build from source, type:

    $ make
        
## Usage
        
Once built, skensa can be run from the same folder as `./skensa`.

    $ ./skensa yahoo.com
    skensa v0.2
    Copyright (c) 2013, Naresh Annangar <hi@tulhan.in>

    Connecting to 98.139.183.24:443
            Default Protocol: TLSv1
            Issued to: www.yahoo.com
            Issued by: Equifax
            Not valid before: Apr  1 23:00:14 2010 GMT
            Not Valid After: Jul  3 04:50:00 2015 GMT
            Public Key Algorithm: RSA (2048 bits)

    Enumerating ciphers...
            256 bits  SSLv3    AES256-SHA                     Accepted
            256 bits  SSLv3    CAMELLIA256-SHA                Accepted
            168 bits  SSLv3    DES-CBC3-SHA                   Accepted
            128 bits  SSLv3    AES128-SHA                     Accepted
            128 bits  SSLv3    SEED-SHA                       Accepted
            128 bits  SSLv3    CAMELLIA128-SHA                Accepted
            128 bits  SSLv3    RC4-SHA                        Accepted
            128 bits  SSLv3    RC4-MD5                        Accepted
            256 bits  TLSv1    AES256-SHA                     Accepted
            256 bits  TLSv1    CAMELLIA256-SHA                Accepted
            168 bits  TLSv1    DES-CBC3-SHA                   Accepted
            128 bits  TLSv1    AES128-SHA                     Accepted
            128 bits  TLSv1    SEED-SHA                       Accepted
            128 bits  TLSv1    CAMELLIA128-SHA                Accepted
            128 bits  TLSv1    RC4-SHA                        Accepted
            128 bits  TLSv1    RC4-MD5                        Accepted

## Changelog

__v0.2__
* Enumerates ciphersuite support for the following protocols
  - SSLv2
  - SSLv3
  - TLSv1
  - TLSv1.1
  - TLSv1.2

__v0.1__
* Establishes SSL connection with the server and prints information about the certificate.
