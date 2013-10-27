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

#include <sys/socket.h>
#include <arpa/inet.h>
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

char *ssl_ver(int version)
{
    switch(version) {
        case 2:
            return strdup("SSLv2");

        case 768:
            return strdup("SSLv3");

        case 769:
            return strdup("TLSv1");

        case 770:
            return strdup("TLSv1.1");

        case 771:
            return strdup("TLSv1l2");

        default:
            return strdup("Unknown");
    }
}

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

    if ((ssl_context = SSL_CTX_new(SSLv23_method())) == NULL) {
        ske_print(INFO, "\tcert_info: Can\'t create SSL context\n");
        return;
    }

    if ((ssl = SSL_new(ssl_context)) == NULL) {
        ske_print(INFO, "\tcert_info: Can\'t create SSL object\n");
        return;
    }

    sock = socket(server->ai_family, server->ai_socktype, server->ai_protocol);

    if (sock == -1) {
        ske_print(INFO, "\tcert_info: Can\'t create socket\n");
        return;
    }

    if (connect(sock, server->ai_addr, server->ai_addrlen) == -1) {
        ske_print(INFO, "\tcert_info: Can\'t connect to host\n");
        return;
    }

    SSL_set_fd(ssl, sock);
    if(SSL_connect(ssl) ==1) {
        BIO *bio = BIO_new(BIO_s_mem());
        X509 *cert = SSL_get_peer_certificate(ssl);
        EVP_PKEY *key = X509_get_pubkey(cert);
        char _buf[255], *_pos1, *_pos2;

        ske_print(INFO, "\tDefault Protocol: %s\n",
                  ssl_ver(SSL_version(ssl)));

        X509_NAME_oneline(X509_get_subject_name(cert), _buf, 255);
        if ((_pos1 = strstr(_buf, "CN=")) != NULL) {
            _pos1 += strlen("CN=");
            if((_pos2 = strchr(_pos1, '/')) != NULL) {
                *_pos2 = '\0';
            }
            ske_print(INFO, "\tIssued to: %s\n", _pos1);
        } else if ((_pos1 = strstr(_buf, "O=")) != NULL) {
            _pos1 += strlen("O=");
            if((_pos2 = strchr(_pos1, '/')) != NULL) {
                *_pos2 = '\0';
            }
            ske_print(INFO, "\tIssued to: %s\n", _pos1);
        } else {
            ske_print(INFO, "\tIssued to: %s\n", _buf);
        }

        X509_NAME_oneline(X509_get_issuer_name(cert), _buf, 255);
        if ((_pos1 = strstr(_buf, "CN=")) != NULL) {
            _pos1 += strlen("CN=");
            if((_pos2 = strchr(_pos1, '/')) != NULL) {
                *_pos2 = '\0';
            }
            ske_print(INFO, "\tIssued by: %s\n", _pos1);
        } else if ((_pos1 = strstr(_buf, "O=")) != NULL) {
            _pos1 += strlen("O=");
            if((_pos2 = strchr(_pos1, '/')) != NULL) {
                *_pos2 = '\0';
            }
            ske_print(INFO, "\tIssued by: %s\n", _pos1);
        } else {
            ske_print(INFO, "\tIssued by: %s\n", _buf);
        }

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
    int ret = getaddrinfo(hostname, port, &addr_info, &server);

    if (ret == 0) {
        char ip_addr[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, 
                  &(((struct sockaddr_in *)server->ai_addr)->sin_addr),
                  ip_addr, 
                  INET_ADDRSTRLEN);
        ske_print(INFO, " Connecting to %s:%s\n", ip_addr, port);
        cert_info();
    } else {
        ske_print(INFO, "Can\'t resolve hostname (%s).", gai_strerror(ret));
        return -1;
    }

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

    return skensa();
}
