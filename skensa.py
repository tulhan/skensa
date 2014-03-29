#!python

import csv
import uuid
import socket
import collections

Cipher = collections.namedtuple('Cipher', 'code, name, kx, au, enc, bits, mac')

with open('ciphers') as csvfile:
    rows = csv.reader(csvfile, delimiter=' ')
    tls_ciphers = []
    for row in rows:
        tls_ciphers.append(Cipher._make(row))

TLSVersions = {
    "SSLv3": b'\x03\x00',
    "TLSv1.0": b'\x03\x01',
    "TLSv1.1": b'\x03\x02',
    "TLSv1.2": b'\x03\03'
}

for ver_str, ver_code in TLSVersions.items():
    for cipher in tls_ciphers:
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
        s.connect(('www.google.com', 443))
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
                  (ver_str, cipher.bits, cipher.name, cipher_strength))
        s.close()
