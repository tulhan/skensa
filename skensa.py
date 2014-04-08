#!python

import csv
import uuid
import socket
import logging
import argparse
import collections

from pyasn1.codec.der import decoder
from pyasn1.type import univ

log = logging.getLogger(__name__)
logging.basicConfig(format='%(message)s', level=logging.INFO)

Cipher = collections.namedtuple('Cipher', 'code, name, kx, au, enc, bits, mac')

with open('ciphers') as csvfile:
    rows = csv.reader(csvfile, delimiter=' ')
    tls_ciphers = []
    for row in rows:
        tls_ciphers.append(Cipher._make(row))


def oid2str(oid):
    OID_MAP = {
        "1.2.840.113549.1.1.1": "RSA Encryption",
        "1.2.840.113549.1.1.2": "MD2 with RSA Encryption",
        "1.2.840.113549.1.1.3": "MD4 with RSA Encryption",
        "1.2.840.113549.1.1.4": "MD5 with RSA Encryption",
        "1.2.840.113549.1.1.5": "SHA1 with RSA Encryption",
        "1.2.840.113549.1.1.11": "SHA256 with RSA Encryption",
        "2.5.4.3": "CN",
        "2.5.4.10": "O",
        "2.5.4.11": "OU",
    }
    oid = str(oid)
    if oid in OID_MAP.keys():
        return OID_MAP[oid]
    else:
        return False


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

                log.info("Accepted %7s %3s bits %-s (%s)" %
                         (proto, cipher.bits,
                          cipher.name, cipher_strength))
            s.close()


def fastfwd_packet(blob):
    if blob[0] == 22:
        len_offset = 3  # Rec. Type(1B), TLS Ver. (2B)
        len_length = 2
        start_pos = len_offset
        end_pos = len_offset + len_length
        pyld_len = int.from_bytes(blob[start_pos:end_pos], 'big')
        blob = blob[end_pos + pyld_len:]
    else:
        raise DecodeError('Packet is not a TLS Record')

    # Check if the next byte indicates the start of a new record
    if blob[0] == 22:
        return blob
    else:
        raise DecodeError('Unable to identify packet boundary')


def get_tls_payload(blob):
    if blob[0] == 22:
        len_offset = 3  # Rec. Type(1B), TLS Ver. (2B)
        len_length = 2
        start_pos = len_offset
        end_pos = len_offset + len_length
        pyld_len = int.from_bytes(blob[start_pos:end_pos], 'big')
        blob = blob[end_pos:]
    else:
        raise DecodeError('Packet is not a TLS Record')

    if blob[0] == 11:
        return blob[:pyld_len]
    else:
        raise DecodeError('Unable to identify packet boundary')

    certs_rec = certs_rec[2:]
    certs = certs_rec[:certs_rec_len]
    certs = certs_rec[7:]  # Hs. type(1B), Rec. len(3B), cert. len(3B)


def get_first_cert_from_certs_record(blob):
    if blob[0] == 11:
        # Skip record header
        blob = blob[7:]
        len_length = 3
        cert1_len = int.from_bytes(blob[:len_length], 'big')
        start_pos = len_length
        end_pos = len_length + cert1_len

        if blob[start_pos] == 30:
            return blob[start_pos:end_pos]
        else:
            raise DecodeError('Unable to identify packet boundary')
    else:
        raise DecodeError('Packet is not a Certificate Record')


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
        data = fastfwd_packet(data)

        # Check for ServerHelloDone and skip it too
        if data[5:6] == 14:
            data = fastfwd_packet(data)

        if data[5:6] == 11:
            data = get_tls_payload(data)

        data = get_first_cert_from_certs_record(data)

        the_cert = decoder.decode(data)
        signed_cert = the_cert[0][0]

        log.info("Version: {}".format(signed_cert[0]))

        log.info("Serial No.: {}".format(signed_cert[1]))

        log.info("Signature: {}".format(oid2str(signed_cert[2][0])))

        cert_issuer = []
        for field in signed_cert[3]:
            oid_str = oid2str(field[0][0])
            if oid_str:
                cert_issuer.append("{} ({})".format(field[0][1], oid_str))

        log.info("Issuer: {}".format(', '.join(cert_issuer)))

        log.info("Not Valid Before: {}".format(signed_cert[4][0]))

        log.info("Not Valid After: {}".format(signed_cert[4][1]))

        cert_subj = []
        for field in signed_cert[5]:
            oid_str = oid2str(field[0][0])
            if oid_str:
                cert_subj.append("{} ({})".format(field[0][1], oid_str))
        log.info("Subject: {}".format(', '.join(cert_subj)))

        binval = ''.join([str(x) for x in signed_cert[6][1]])
        pubkey = decoder.decode(univ.OctetString(binValue=binval))
        key_len = int(pubkey[0][0]).bit_length()
        log.info("Public Key Algorithm: {} ({} bits)"
                 .format(oid2str(signed_cert[6][0][0]),
                         key_len))
    else:
        log.error("No Server Hello")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("hostname", help="IP/Hostname of the URL to scan")
    parser.add_argument("port", help="IP/Hostname of the URL to scan",
                        type=int)
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
    parser.add_argument("--debug", help="Start in debug mode",
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

    if args.debug:
        log.setLevel(logging.DEBUG)

    if args.cert:
        cert_info(args.hostname, args.port)
    else:
        enum_ciphers(args.hostname, args.port, protos)
        cert_info(args.hostname, args.port)
