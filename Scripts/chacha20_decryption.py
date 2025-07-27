from Crypto.Cipher import ChaCha20
from Crypto.Hash import Poly1305
import binascii
# uncomment to run this file alone
# from pyshark.capture.file_capture import FileCapture
import struct
import string

def set_keys(s2c_str, c2s_str):
    s2c = binascii.unhexlify(s2c_str)
    c2s = binascii.unhexlify(c2s_str)
    return s2c[:32], s2c[32:], c2s[:32], c2s[32:]

def print_decrypted_msg(code, plaintext, calc_len, is_mac_valid, seqnr, f):
    if code == -1:
        print(f'Wrong seqnr or key. Calc len = {calc_len}', file=f)
        return
    print(f'seqnr = {seqnr} | Calc len = {calc_len}', file=f)
    print(f'MAC is {"valid" if is_mac_valid else "invalid"}', file=f)
    printable_chars = string.printable.encode()
    readable = bytes(b if b in printable_chars else ord('.') for b in plaintext).decode('ascii', errors='replace')
    print(f'\nDecrypted payload:\n{plaintext}\n', file=f)
    print(f'Readable output:\n{readable}\n', file=f)

def decrypt(seqnr, k1, k2, payload):
    '''
    returns (output_code, next_seqnr, plaintext, calc_len, is_mac_valid)
    output_code = { -1: failed decryption,
                      0: successful decryption }
    '''
    i = seqnr
    while (i - seqnr < 10):
        nonce = int(i).to_bytes(8, 'big')
        cipher_length = ChaCha20.new(key=k1, nonce=nonce)
        enc_length = payload[:4]
        dec_length = cipher_length.decrypt(enc_length)
        payload_len = struct.unpack('>I', dec_length)[0]
        if (payload_len + 20 <= len(payload) and payload_len <= 35000):
            break
        i += 1
    else:
        return -1, seqnr, b'', payload_len, False

    mac = Poly1305.new(key=k2, nonce=nonce, cipher=ChaCha20, data=payload[:-16])
    is_mac_valid = (binascii.unhexlify(mac.hexdigest()) == payload[-16:])

    ciphertext = payload[4:4+payload_len]
    payload_cipher = ChaCha20.new(key=k2, nonce=nonce)
    payload_cipher.seek(64)
    plaintext = payload_cipher.decrypt(ciphertext)
    return 0, i + 1, plaintext, payload_len, is_mac_valid

if __name__ == '__main__':
    SSH_PKT_FIELD = 'SSH Version 2 (encryption:chacha20-poly1305@openssh.com mac:<implicit> compression:none)'
    LEN_FIELD = 'ssh.packet_length_encrypted_raw'
    PAYLOAD_FIELD = 'ssh.encrypted_packet_raw'
    MAC_FIELD = 'ssh.mac_raw'
    DIRECTION_FIELD = 'ssh.direction'
    directions = {0: 'C->S', 1: 'S->C'}
    LOG_FILE = '/path/to/log/file.log'

    f = open(LOG_FILE, 'w', encoding='utf-8', errors='replace')
    pcap_path = '/path/to/pcap.pcapng'
    cap = FileCapture(pcap_path, display_filter='ssh', use_json=True, include_raw=True)

    handshake = 4
    rekey = False
    s2c_seqnr = c2s_seqnr = 3

    # Replace these with actual hex strings from the SSH session
    s2c_str = ['hex-str', 'hex-str']
    c2s_str = ['hex-str', 'hex-str']

    s2c_k2, s2c_k1, c2s_k2, c2s_k1 = set_keys(s2c_str[0], c2s_str[0])
    print('*' * 60, end = '\n', file=f)

    for frame in cap:
        ssh = frame.ssh._all_fields
        if not SSH_PKT_FIELD in ssh: continue
        if type(ssh[SSH_PKT_FIELD]) == list:
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
            code, s2c_seqnr, plaintext, calc_len, is_mac_valid = decrypt(s2c_seqnr, s2c_k1, s2c_k2, payload)
            seqnr = s2c_seqnr - 1
            if code == -1: break
        else:
            code, c2s_seqnr, plaintext, calc_len, is_mac_valid = decrypt(c2s_seqnr, c2s_k1, c2s_k2, payload)
            seqnr = c2s_seqnr - 1
            if code == -1: break

        print_decrypted_msg(code, plaintext, calc_len, is_mac_valid, seqnr, f)
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