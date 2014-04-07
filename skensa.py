#!python

import csv
import uuid
import socket
import logging
import argparse
import collections

from pyasn1.codec.der import decoder

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
        # Skip ServerHello
        data = data[3:]
        sh_len = int.from_bytes(data[:2], 'big')
        log.debug("ServerHello: {}".format(sh_len))
        log.debug("SH Data: {}".format(data[:100]))
        log.debug("")
        data = data[2 + sh_len:]

        #Check for ServerHelloDone and skip it too
        if int.from_bytes(data[5:6], 'big') == 14:
            shd_rec = data[3:]
            shd_rec_len = int.from_bytes(data[:2], 'big')
            log.debug("ServerHelloDone: {}".format(shd_rec_len))
            log.debug("SHD Data: {}".format(shd_rec[:100]))
            log.debug("")
            certs_rec = shd_rec[shd_rec_len + 2:]
        else:
            certs_rec = data

        certs_rec = certs_rec[3:] # Rec. type(1B), Rec. proto.(2B)
        certs_rec_len = int.from_bytes(certs_rec[:2], 'big') # Rec. len.(2B)
        log.debug("Certs Rec: {}".format(certs_rec_len))
        log.debug("Certs Data: {}".format(certs_rec[:100]))
        log.debug("")
        certs_rec = certs_rec[2:]

        certs = certs_rec[:certs_rec_len]
        certs = certs_rec[7:] # Hs. type(1B), Rec. len(3B), cert. len(3B)

        cert1_len = int.from_bytes(certs[:3], 'big')
        cert1 = certs[3:]
        cert1 = cert1[:cert1_len]
        log.debug("Cert1 Rec: {}".format(cert1_len))
        log.debug("Cert1 Data: {}".format(cert1[:100]))
        log.debug("")

        the_cert = decoder.decode(cert1)
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
        log.info("Public Key Algorithm: {}".format(oid2str(signed_cert[6][0][0])))
        serial_no = signed_cert[1]

    else:
        log.error("No Server Hello")



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
