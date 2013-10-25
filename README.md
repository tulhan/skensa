# Skensa

## About
Skensa is an SSL/TLS cipher enumeration tool. Aside from enumeration, skensa also aims to detect common cipher and certificate misconfigurations.

Skensa is a portmanteau of the words SSL and the japanese work 'kensa' which means to inspect.

## Build

Skensa currently only works in linux. A make file is included for building from source.

To build from souce, type:

    $ make
        
## Usage
        
Once built, skensa can be run from the same folder as `.\skensa`.
        
    $ .\skensa
    skensa v0.1
    Copyright (c) 2013, Naresh Annangar <hi@tulhan.in>
    
    skensa <options> hostname[:port]
    -v = verbose output
                                                
## Changelog

__v0.1__
* Establishes SSL connection with the server and prints information about the certificate.
