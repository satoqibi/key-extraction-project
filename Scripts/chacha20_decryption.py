from Crypto.Cipher import ChaCha20
from Crypto.Hash import Poly1305
import binascii
import pyshark
import struct
import string

SSH_PKT_FIELD = 'SSH Version 2 (encryption:chacha20-poly1305@openssh.com mac:<implicit> compression:none)'
S2C = 'S->C'
C2S = 'C->S'
LOG_FILE = '/home/kali/key-extraction-project/session_logs/decrypted_msgs.log'

f = open(LOG_FILE, 'w', encoding='utf-8', errors='replace')

def decrypt(seqnr, k1, k2, payload):
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
        return

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
    print(f'\nDecrypted payload:\n{plaintext}\n', file=f)
    printable_chars = string.printable.encode()
    readable = bytes(b if b in printable_chars else ord('.') for b in plaintext)
    print(f'Readable output:\n{readable.decode('ascii', errors='replace')}\n', file=f)
    return i + 1


full_s2c_key = binascii.unhexlify(input('Enter S->C key: ').strip())
full_c2s_key = binascii.unhexlify(input('Enter C->S key: ').strip())
pcap_path = input('Enter PCAP file path: ').strip()
s2c_seqnr = 3
c2s_seqnr = 3

try:
    cap = pyshark.FileCapture(pcap_path, display_filter='ssh', use_json=True, include_raw=True)
except FileNotFoundError:
    print(f'File not found: {pcap_path}')
    sys.exit(1)

frame_count = 0
total_frames = len(list(cap))
directions = {0: C2S, 1: S2C}

# skip SSH handshake msgs
while frame_count < total_frames:
    ssh_layer = cap[frame_count].ssh._all_fields
    if SSH_PKT_FIELD in ssh_layer:
        break
    frame_count += 1

frame = cap[frame_count]
ssh_layer = frame.ssh._all_fields
direction = int(ssh_layer['ssh.direction'])
pkt = ssh_layer[SSH_PKT_FIELD][1] # 1st s2c enc pkt
print('*' * 60, file=f)
print(f'Frame: {frame.frame_info.number}', file=f)
print(directions[direction], file=f)
print(f'{frame.ip.src}->{frame.ip.dst}', file=f)
payload = binascii.unhexlify(pkt['ssh.packet_length_encrypted_raw'][0] + pkt['ssh.encrypted_packet_raw'][0] + pkt['ssh.mac_raw'][0])
s2c_seqnr = decrypt(s2c_seqnr, full_s2c_key[32:], full_s2c_key[:32], payload)
print('*' * 60, end='\n\n', file=f)
frame_count += 1

# skip newkeys msg between 1st s2c enc and 1st c2s enc msgs
while frame_count < total_frames:
    if 'ssh.packet_length_encrypted_raw' in cap[frame_count].ssh._all_fields[SSH_PKT_FIELD]:
        break
    frame_count += 1

while frame_count < total_frames:
    frame = cap[frame_count]
    ssh_layer = frame.ssh._all_fields
    direction = int(ssh_layer['ssh.direction'])
    pkt = ssh_layer[SSH_PKT_FIELD]
    print(f'Frame: {frame.frame_info.number}', file=f)
    print(directions[direction], file=f)
    print(f'{frame.ip.src}->{frame.ip.dst}', file=f)
    payload = binascii.unhexlify(pkt['ssh.packet_length_encrypted_raw'][0] + pkt['ssh.encrypted_packet_raw'][0] + pkt['ssh.mac_raw'][0])
    if direction:
        s2c_seqnr = decrypt(s2c_seqnr, full_s2c_key[32:], full_s2c_key[:32], payload)
    else:
        c2s_seqnr = decrypt(c2s_seqnr, full_c2s_key[32:], full_c2s_key[:32], payload)
    print('*' * 60, end='\n\n', file=f)
    frame_count += 1

f.close()
