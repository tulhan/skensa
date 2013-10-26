/**
 * skensa - An SSL/TLS cipher enumeration tool.
 * Copyright (C) 2013, Naresh Annangar <hi@tulhan.in>
 *
 * This program is free software; it may be distributed under the terms of BSD
 * license.
 *
 * For more information view the LICENSE file.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <netdb.h>

#include <openssl/ssl.h>

#define ske_print(verbosity, ...) if (verbosity <= ske_verbosity) { printf(__VA_ARGS__); }
#define SKE_VER "0.1"

static const char *ske_version =
"skensa v" SKE_VER "\n"
"Copyright (c) 2013, Naresh Annangar <hi@tulhan.in>\n";

static const char *ske_usage =
"skensa <options> hostname[:port]\n"
"-v = verbose output\n";

/* Program's verbosity level */
enum { INFO, VERB, DBUG };

/* Global parameters shared by all functions */
static int ske_verbosity;
static char *hostname;
static char *port;
static struct addrinfo *server;

/*
 * Gets and prints certificate information based on the ssl object.
 *
 * @ssl Pointer to an established SSL connection object.
 */
void cert_info(void)
{
    int sock;

    SSL_CTX *ssl_context;
    SSL *ssl;

    ssl_context = SSL_CTX_new(SSLv23_method());
    ssl = SSL_new(ssl_context);

    sock = socket(server->ai_family, server->ai_socktype, server->ai_protocol);
    connect(sock, server->ai_addr, server->ai_addrlen);

    SSL_set_fd(ssl, sock);
    if(SSL_connect(ssl) ==1) {
        BIO *bio = BIO_new(BIO_s_mem());
        X509 *cert = SSL_get_peer_certificate(ssl);
        EVP_PKEY *key = X509_get_pubkey(cert);
        char _buf[255];

        switch(SSL_version(ssl)) {
            case 2:
                ske_print(INFO, "\tDefault Protocol: SSLv2\n");
                break;

            case 768:
                ske_print(INFO, "\tDefault Protocol: SSLv3\n");
                break;

            case 769:
                ske_print(INFO, "\tDefault Protocol: TLSv1\n");
                break;

            case 770:
                ske_print(INFO, "\tDefault Protocol: TLSv1.1\n");
                break;

            case 771:
                ske_print(INFO, "\tDefault Protocol: TLSv1.2\n");
                break;

            default:
                ske_print(INFO, "\tDefault Protocol: Unknown (%d)", 
                        SSL_version(ssl));
        }

        X509_NAME_oneline(X509_get_subject_name(cert), _buf, 255);
        ske_print(INFO, "\tIssued to: %s\n", strstr(_buf, "CN=") + 3);

        X509_NAME_oneline(X509_get_issuer_name(cert), _buf, 255);
        ske_print(INFO, "\tIssued by: %s\n", strstr(_buf, "CN=") + 3);

        ASN1_TIME_print(bio, X509_get_notBefore(cert));
        BIO_gets(bio, _buf, 255);
        ske_print(INFO, "\tNot valid before: %s\n", _buf);

        ASN1_TIME_print(bio, X509_get_notAfter(cert));
        BIO_gets(bio, _buf, 255);
        ske_print(INFO, "\tNot Valid After: %s\n", _buf);

        switch (key->type) {
            case EVP_PKEY_RSA:
                ske_print(INFO, "\tPublic Key Algorithm: RSA (%d bits)\n", 
                        BN_num_bits(key->pkey.rsa->n));
                break;

            case EVP_PKEY_DSA:
                ske_print(INFO, "\tPublic Key Algorithm: DSA\n");
                break;

            case EVP_PKEY_EC:
                ske_print(INFO, "\tPublic Key Algorithm: ECDSA\n");
                break;

            default:
                ske_print(INFO, "\tPublic Key Algorithm: Unknown\n");
        }
    } else {
        ske_print(INFO, " SSL Connection couldn\'t be established\n");
    }

    SSL_shutdown(ssl);
}

/**
 * Functional routine. Calls helper functions based on arguments.
 *
 * Returns 0 on success, -1 on error.
 */
int skensa(void)
{
    struct addrinfo addr_info;

    memset(&addr_info, 0, sizeof addr_info);
    addr_info.ai_family = AF_INET;
    addr_info.ai_socktype = SOCK_STREAM;

    SSL_load_error_strings();
    SSL_library_init();
    getaddrinfo(hostname, port, &addr_info, &server);

    cert_info();

    return 0;
}

int main(int argc, char **argv)
{
    ske_verbosity = INFO;
    ske_print(INFO,"%s\n", ske_version);

    /* Process command line arguments */
    if (argc < 2) {
        ske_print(INFO, "%s", ske_usage);
        return -1;
    }

    for(int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-v") == 0) {
            ske_verbosity = VERB;
        } else {
            /* If hostname is already set, this argument is superfluous; balk */
            if (hostname) {
                ske_print(INFO, "%s\n", ske_usage);
                return -1;
            }

            /* if argument starts with -, it's not a hostname; balk */
            if (argv[i][0] == '-') {
                ske_print(INFO, "%s", ske_usage);
                return -1;
            }

            char *port_pos = strchr(argv[i], ':');
            if (port_pos != NULL) {
                port = strdup(port_pos + 1);
                *port_pos = '\0';
                hostname = strdup(argv[i]);
            } else {
                hostname = strdup(argv[i]);
                port = strdup("443");
            }
        }
    }

    ske_print(INFO, " Connecting to %s:%s\n", hostname, port);

    return skensa();
}
