#!python

import csv
import uuid
import socket
import argparse
import collections

from pyasn1.codec.der import decoder

Cipher = collections.namedtuple('Cipher', 'code, name, kx, au, enc, bits, mac')

with open('ciphers') as csvfile:
    rows = csv.reader(csvfile, delimiter=' ')
    tls_ciphers = []
    for row in rows:
        tls_ciphers.append(Cipher._make(row))


def enum_ciphers(hostname, port, protos):

    TLSVersions = {
        "SSLv3": b'\x03\x00',
        "TLSv1.0": b'\x03\x01',
        "TLSv1.1": b'\x03\x02',
        "TLSv1.2": b'\x03\03'
    }

    for proto in protos:
        for cipher in tls_ciphers:
            ver_code = TLSVersions[proto]

            ch_ver = ver_code
            ch_rand = bytes.fromhex(uuid.uuid4().hex + uuid.uuid4().hex)
            ch_sessid = b'\x00'
            ch_cipher_suite = b'\x00\x04' + bytes.fromhex(cipher.code) + \
                b'\x00\xff'
            ch_compression = b'\x01\x00'
            ch_payload = ch_ver + ch_rand + ch_sessid + ch_cipher_suite \
                + ch_compression

            ch_payload_in_bytes = len(ch_payload).to_bytes(3, 'big')
            client_hello = b'\x01' + ch_payload_in_bytes + ch_payload
            ch_len_in_bytes = len(client_hello).to_bytes(2, 'big')

            tls_record = b'\x16' + ver_code + ch_len_in_bytes + client_hello

            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((hostname, port))
            s.send(tls_record)
            data = s.recv(1)
            if data == b'\x16':
                if cipher.name.startswith('EXP'):
                    cipher_strength = 'EXP'
                elif cipher.au == 'None':
                    cipher_strength = 'ANON'
                elif cipher.enc == 'None':
                    cipher_strength = 'NULL'
                elif cipher.bits < '128':
                    cipher_strength = 'WEAK'
                elif cipher.bits == '128':
                    cipher_strength = 'MED'
                else:
                    cipher_strength = 'HIGH'

                print("Accepted %7s %3s bits %-s (%s)" %
                    (proto, cipher.bits, cipher.name, cipher_strength))
            s.close()


def cert_info(hostname, port):
    ch_ver = b'\x03\x00'
    ch_rand = bytes.fromhex(uuid.uuid4().hex + uuid.uuid4().hex)
    ch_sessid = b'\x00'
    ch_ciphers = b''.join(bytes.fromhex(cipher.code) for cipher in tls_ciphers)
    ch_ciphers = ch_ciphers + b'\x00\xff'
    ch_cipher_suite = len(ch_ciphers).to_bytes(2, 'big') + ch_ciphers
    ch_compression = b'\x01\x00'
    ch_payload = ch_ver + ch_rand + ch_sessid + ch_cipher_suite \
        + ch_compression

    ch_payload_in_bytes = len(ch_payload).to_bytes(3, 'big')
    client_hello = b'\x01' + ch_payload_in_bytes + ch_payload
    ch_len_in_bytes = len(client_hello).to_bytes(2, 'big')

    tls_record = b'\x16' + b'\x03\x00' + ch_len_in_bytes + client_hello

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((hostname, port))
    s.send(tls_record)
    data = s.recv(10*1024)
    if data[0] == 22:
        data = data[3:]
        sh_len = int.from_bytes(data[:2], 'big')
        data = data[2:]

        certs_rec = data[sh_len:]
        certs_rec = certs_rec[3:] # Rec. type(1B), Rec. proto.(2B)
        certs_rec_len = int.from_bytes(certs_rec[:2], 'big') # Rec. len.(2B)
        certs_rec = certs_rec[2:]
        print(certs_rec_len)

        certs_payld = certs_rec[:certs_rec_len]
        certs_payld = certs_rec[7:] # Hs. type(1B), Rec. len(3B), cert. len(3B)

        print(len(certs_payld))
        print(certs_payld[:100])
        #sh_len += 17
        #cert1_len = int.from_bytes(data[sh_len:sh_len+3], 'big')
        #cert1 = data[sh_len+3:sh_len+cert1_len+3]
        #print(len(cert1))
        #print(cert1[:100])
        #decc = decoder.decode(cert1)
        #print(decc[0][0][2][0])
    else:
        print("No Server Hello")



if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("hostname", help="IP/Hostname of the URL to scan")
    parser.add_argument("port", help="IP/Hostname of the URL to scan", type=int)
    parser.add_argument("--ssl2", help="Scan for SSLv2 Ciphers",
        action="store_true")
    parser.add_argument("--ssl3", help="Scan for SSLv3 Ciphers",
        action="store_true")
    parser.add_argument("--tls1", help="Scan for TLSv1.0 Ciphers",
        action="store_true")
    parser.add_argument("--tls11", help="Scan for TLSv1.1 Ciphers",
        action="store_true")
    parser.add_argument("--tls12", help="Scan for TLSv1.2 Ciphers",
        action="store_true")
    parser.add_argument("--cert", help="Get only the certificate details",
        action="store_true")
    args = parser.parse_args()

    protos = []
    if args.ssl3:
        protos.append("SSLv3")
    if args.tls1:
        protos.append("TLSv1.0")
    if args.tls11:
        protos.append("TLSv1.1")
    if args.tls12:
        protos.append("TLSv1.2")
    if not protos:
        protos = ["SSLv3", "TLSv1.0", "TLSv1.1", "TLSv1.2"]

    if args.cert:
        cert_info(args.hostname, args.port)
    else:
        enum_ciphers(args.hostname, args.port, protos)
        cert_info(args.hostname, args.port)
