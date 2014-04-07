# Skensa

## About
Skensa is an SSL/TLS cipher enumeration tool. Aside from enumeration, skensa also aims to detect common cipher and certificate misconfigurations.

Skensa is a portmanteau of the words SSL and the japanese work 'kensa' which means to inspect.

## Supported Platforms

Skensa is written in Python3. So, ideally, it should work on any platform that supports it.
No SSL module is required, as communication happens by directly spewing the bits to the server.
The only python module required is `pyasn1` which is used to wrangle the complexities of the X.509 certificate format.
You can install the requirements by typing `pip install -r requirements.txt`

## Usage

    usage: skensa.py [-h] [--ssl2] [--ssl3] [--tls1] [--tls11] [--tls12] [--cert]
                    [--debug]
                    hostname port
    
    positional arguments:
    hostname    IP/Hostname of the URL to scan
    port        IP/Hostname of the URL to scan
    
    optional arguments:
    -h, --help  show this help message and exit
    --ssl2      Scan for SSLv2 Ciphers
    --ssl3      Scan for SSLv3 Ciphers
    --tls1      Scan for TLSv1.0 Ciphers
    --tls11     Scan for TLSv1.1 Ciphers
    --tls12     Scan for TLSv1.2 Ciphers
    --cert      Get only the certificate details
    --debug     Start in debug mode

Example:

    $ skensa www.google.com 443
    Accepted   SSLv3 256 bits ECDHE-RSA-AES256-SHA (HIGH)
    Accepted   SSLv3 256 bits AES256-SHA (HIGH)
    Accepted   SSLv3 168 bits ECDHE-RSA-DES-CBC3-SHA (HIGH)
    Accepted   SSLv3 168 bits DES-CBC3-SHA (HIGH)
    Accepted   SSLv3 128 bits ECDHE-RSA-AES128-SHA (MED)
    Accepted   SSLv3 128 bits AES128-SHA (MED)
    Accepted   SSLv3 128 bits ECDHE-RSA-RC4-SHA (MED)
    Accepted   SSLv3 128 bits RC4-SHA (MED)
    Accepted   SSLv3 128 bits RC4-MD5 (MED)
    Accepted TLSv1.0 256 bits ECDHE-RSA-AES256-SHA (HIGH)
    Accepted TLSv1.0 256 bits AES256-SHA (HIGH)
    Accepted TLSv1.0 168 bits ECDHE-RSA-DES-CBC3-SHA (HIGH)
    Accepted TLSv1.0 168 bits DES-CBC3-SHA (HIGH)
    Accepted TLSv1.0 128 bits ECDHE-RSA-AES128-SHA (MED)
    Accepted TLSv1.0 128 bits AES128-SHA (MED)
    Accepted TLSv1.0 128 bits ECDHE-RSA-RC4-SHA (MED)
    Accepted TLSv1.0 128 bits RC4-SHA (MED)
    Accepted TLSv1.0 128 bits RC4-MD5 (MED)
    Accepted TLSv1.1 256 bits ECDHE-RSA-AES256-SHA (HIGH)
    Accepted TLSv1.1 256 bits AES256-SHA (HIGH)
    Accepted TLSv1.1 168 bits ECDHE-RSA-DES-CBC3-SHA (HIGH)
    Accepted TLSv1.1 168 bits DES-CBC3-SHA (HIGH)
    Accepted TLSv1.1 128 bits ECDHE-RSA-AES128-SHA (MED)
    Accepted TLSv1.1 128 bits AES128-SHA (MED)
    Accepted TLSv1.1 128 bits ECDHE-RSA-RC4-SHA (MED)
    Accepted TLSv1.1 128 bits RC4-SHA (MED)
    Accepted TLSv1.1 128 bits RC4-MD5 (MED)
    Accepted TLSv1.2 256 bits ECDHE-RSA-AES256-GCM-SHA384 (HIGH)
    Accepted TLSv1.2 256 bits ECDHE-RSA-AES256-SHA384 (HIGH)
    Accepted TLSv1.2 256 bits ECDHE-RSA-AES256-SHA (HIGH)
    Accepted TLSv1.2 256 bits AES256-GCM-SHA384 (HIGH)
    Accepted TLSv1.2 256 bits AES256-SHA256 (HIGH)
    Accepted TLSv1.2 256 bits AES256-SHA (HIGH)
    Accepted TLSv1.2 168 bits ECDHE-RSA-DES-CBC3-SHA (HIGH)
    Accepted TLSv1.2 168 bits DES-CBC3-SHA (HIGH)
    Accepted TLSv1.2 128 bits ECDHE-RSA-AES128-GCM-SHA256 (MED)
    Accepted TLSv1.2 128 bits ECDHE-RSA-AES128-SHA256 (MED)
    Accepted TLSv1.2 128 bits ECDHE-RSA-AES128-SHA (MED)
    Accepted TLSv1.2 128 bits AES128-GCM-SHA256 (MED)
    Accepted TLSv1.2 128 bits AES128-SHA256 (MED)
    Accepted TLSv1.2 128 bits AES128-SHA (MED)
    Accepted TLSv1.2 128 bits ECDHE-RSA-RC4-SHA (MED)
    Accepted TLSv1.2 128 bits RC4-SHA (MED)
    Accepted TLSv1.2 128 bits RC4-MD5 (MED)
    Version: 2
    Serial No.: 8151063296760904526
    Signature: SHA1 with RSA Encryption
    Issuer: Google Inc (O), Google Internet Authority G2 (CN)
    Not Valid Before: 140312093830Z
    Not Valid After: 140610000000Z
    Subject: Google Inc (O), www.google.com (CN)
    Public Key Algorithm: RSA Encryption (2048 bits)

## Changelog

__v0.3__
* Switch to Python
* SSLv2 support not yet implemented
* Gets and prints certificate information

__v0.2__
* Enumerates ciphersuite support for the following protocols
  - SSLv2
  - SSLv3
  - TLSv1
  - TLSv1.1
  - TLSv1.2

__v0.1__
* Establishes SSL connection with the server and prints information about the certificate.
