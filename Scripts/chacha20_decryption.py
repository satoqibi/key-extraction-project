from Crypto.Cipher import ChaCha20
from Crypto.Hash import Poly1305
import binascii
import pyshark
import struct
import string

SSH_PKT_FIELD = 'SSH Version 2 (encryption:chacha20-poly1305@openssh.com mac:<implicit> compression:none)'
LEN_FIELD = 'ssh.packet_length_encrypted_raw'
PAYLOAD_FIELD = 'ssh.encrypted_packet_raw'
MAC_FIELD = 'ssh.mac_raw'
DIRECTION_FIELD = 'ssh.direction'
s2c_seqnr = c2s_seqnr = 3
directions = {0: 'C->S', 1: 'S->C'}
LOG_FILE = '/path/to/your/logfile.log'
f = open(LOG_FILE, 'w', encoding='utf-8', errors='replace')

def set_keys(s2c_str, c2s_str):
    s2c = binascii.unhexlify(s2c_str)
    c2s = binascii.unhexlify(c2s_str)
    return s2c[:32], s2c[32:], c2s[:32], c2s[32:]

def print_decrypted_msg(plaintext):
    printable_chars = string.printable.encode()
    readable = bytes(b if b in printable_chars else ord('.') for b in plaintext).decode('ascii', errors='replace')
    print(f'\nDecrypted payload:\n{plaintext}\n', file=f)
    print(f'Readable output:\n{readable}\n', file=f)

def decrypt(seqnr, k1, k2, payload):
    '''
    returns (output_code, next_seqnr, plaintext)
    output_code = { -1: failed decryption,
                     0: successful decryption }
    '''

    i = seqnr
    while (i - seqnr < 10):
        nonce = int(i).to_bytes(8, 'big')
        cipher_length = ChaCha20.new(key=k1, nonce=nonce)
        cipher_length.seek(0)
        enc_length = payload[:4]
        dec_length = cipher_length.decrypt(enc_length)
        payload_len = struct.unpack('>I', dec_length)[0]
        if (payload_len + 20 <= len(payload) and payload_len <= 32768):
            break
        i += 1
    else:
        print(f'Wrong seqnr or key. Calc len = {payload_len}', file=f)
        return -1, seqnr, ''

    print(f'seqnr = {i} | Calc len = {payload_len}', file=f)

    mac = Poly1305.new(key=k2, nonce=nonce, cipher=ChaCha20, data=payload[:-16])
    if (binascii.unhexlify(mac.hexdigest()) == payload[-16:]):
        print('MAC is valid', file=f)
    else:
        print('MAC is invalid', file=f)

    ciphertext = payload[4:4+payload_len]
    payload_cipher = ChaCha20.new(key=k2, nonce=nonce)
    payload_cipher.seek(64)
    plaintext = payload_cipher.decrypt(ciphertext)
    return 0, i + 1, plaintext

pcap_path = '/path/to/your/ssh.pcap'
cap = pyshark.FileCapture(pcap_path, display_filter='ssh', use_json=True, include_raw=True)

handshake = 4
rekey = False

# Replace with actual hex strings
s2c_str = ['pre-rekey-s2c', 'post-rekey-s2c']
c2s_str = ['pre-rekey-c2s', 'post-rekey-c2s']

s2c_k2, s2c_k1, c2s_k2, c2s_k1 = set_keys(s2c_str[0], c2s_str[0])
print('*' * 60, end = '\n', file=f)

for frame in cap:
    ssh = frame.ssh._all_fields
    if not SSH_PKT_FIELD in ssh: continue
    if isinstance(ssh[SSH_PKT_FIELD], list):
        pkt = ssh[SSH_PKT_FIELD][1]
    else:
        if not LEN_FIELD in ssh[SSH_PKT_FIELD]: continue
        pkt = ssh[SSH_PKT_FIELD]

    direction = int(ssh[DIRECTION_FIELD])
    print(f'Frame: {frame.frame_info.number}', file=f)
    print(directions[direction], file=f)
    print(f'{frame.ip.src}->{frame.ip.dst}', file=f)
    payload = binascii.unhexlify(pkt[LEN_FIELD][0] + pkt[PAYLOAD_FIELD][0] + pkt[MAC_FIELD][0])
    plaintext = ''

    if direction:
        code, s2c_seqnr, plaintext = decrypt(s2c_seqnr, s2c_k1, s2c_k2, payload)
        if code == -1: break
    else:
        code, c2s_seqnr, plaintext = decrypt(c2s_seqnr, c2s_k1, c2s_k2, payload)
        if code == -1: break

    print_decrypted_msg(plaintext)
    if len(plaintext) > 900 and b'mlkem' in plaintext:
        rekey = True
    if rekey:
        if handshake > 1: handshake -= 1
        else:
            s2c_k2, s2c_k1, c2s_k2, c2s_k1 = set_keys(s2c_str[1], c2s_str[1])
            handshake = 4
            rekey = False

    print('*' * 60, end = '\n', file=f)    

f.close()