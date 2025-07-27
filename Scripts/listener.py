import string
import binascii
from chacha20_decryption import decrypt
import asyncio
import aiofiles
import threading
from typing import Any, Optional, TextIO
import queue
import json
from pyshark.packet.packet import Packet
from pyshark.capture.live_capture import LiveCapture

PCAP_PATH = '/home/kali/key-extraction-project/pcaps/live2.pcapng'
KEX_MONITOR_PATH = '/home/kali/key-extraction-project/Scripts/kex_monitor.bt'
LOG_FILE = '/home/kali/key-extraction-project/session_logs/live2.log'
SSH_PKT_FIELD = 'SSH Version 2 (encryption:chacha20-poly1305@openssh.com mac:<implicit> compression:none)'
LEN_FIELD = 'ssh.packet_length_encrypted_raw'
PAYLOAD_FIELD = 'ssh.encrypted_packet_raw'
MAC_FIELD = 'ssh.mac_raw'
DIRECTION_FIELD = 'ssh.direction'
DIRECTIONS = {0: 'C->S', 1: 'S->C'}
clients = dict()

# Thread-safe queue to hold captured packets
packet_queue: queue.Queue = queue.Queue()

# Global references to the capture process and its thread
capture: Optional[LiveCapture] = None
capture_thread: Optional[threading.Thread] = None

def capture_packets(interface: str) -> None:
    global PCAP_PATH, capture
    capture = LiveCapture(interface=interface, bpf_filter='tcp port 22', use_json=True, include_raw=True, output_file=PCAP_PATH)

    def packet_handler(packet: Any) -> None:
        packet_queue.put(packet)

    try:
        # run indefinitely until capture.close() is called
        capture.apply_on_packets(packet_handler)
    finally:
        print("[PCAP] Capture stopped.")

async def process_packets(log_file: TextIO) -> None:
    while True:
        try:
            packet = packet_queue.get_nowait()
            await process_packet(packet, log_file, asyncio.get_running_loop())
        except queue.Empty:
            await asyncio.sleep(0.1)
        except asyncio.CancelledError:
            print("[PROCESS] Packet processing stopped.")
            break

async def process_packet(packet: Packet, f: TextIO, loop: asyncio.AbstractEventLoop) -> None:
    global clients
    try:
        if 'ssh' not in packet: return

        ssh = packet.ssh._all_fields
        pkt_info = None
        if SSH_PKT_FIELD not in ssh: return
        if isinstance(ssh[SSH_PKT_FIELD], list):
            pkt_info = ssh[SSH_PKT_FIELD][1]
        else:
            if LEN_FIELD not in ssh[SSH_PKT_FIELD]: return
            pkt_info = ssh[SSH_PKT_FIELD]

        direction = int(ssh[DIRECTION_FIELD])
        payload = binascii.unhexlify(pkt_info[LEN_FIELD][0] + pkt_info[PAYLOAD_FIELD][0] + pkt_info[MAC_FIELD][0])
        
        ip_port = f'{packet.ip.dst}_{packet.tcp.dstport}' if direction else f'{packet.ip.src}_{packet.tcp.srcport}'
        while ip_port not in clients:
            await asyncio.sleep(0.1)
        
        client = clients[ip_port]
        key_list = client['S2C_keys'] if direction else client['C2S_keys']
        seqnr_key = 'S2C_seqnr' if direction else 'C2S_seqnr'
        
        # if there are two keys, a rekey is happening, use the OLD key [0].
        # else, use the latest key [-1].
        key_index = 0 if len(key_list) > 1 else -1
        key_to_use = binascii.unhexlify(key_list[key_index])

        code, next_seqnr, plaintext, calc_len, is_mac_valid = decrypt(client[seqnr_key], key_to_use[32:], key_to_use[:32], payload)
        
        client[seqnr_key] = next_seqnr
        seqnr = next_seqnr - 1

        if code == -1:
            error_msg = f'[FATAL] Error decrypting packet: {packet.frame_info.number} | Dir: {DIRECTIONS[direction]} | KeyIndex: {key_index}. Shutting down.\n'
            print(error_msg, end='')
            await f.write(error_msg)
            asyncio.create_task(shutdown(loop))
            return

        printable_chars = string.printable.encode()
        readable = bytes(b if b in printable_chars else ord('.') for b in plaintext).decode('utf-8', errors='replace')
        log_entry = (
            f'Frame: {packet.frame_info.number}\n'
            f'{DIRECTIONS[direction]}\n'
            f'{packet.ip.src}:{packet.tcp.srcport} -> {packet.ip.dst}:{packet.tcp.dstport}\n'
            f'seqnr = {seqnr} | Calc len = {calc_len}\n'
            f'MAC is {"valid" if is_mac_valid else "invalid"}\n'
            f'Decrypted payload: {plaintext}\n'
            f'Readable payload:\n{readable}\n\n'
        )
        await f.write(log_entry)
        await f.flush()

        # 1. trigger the rekey state when the s2c handshake message is seen
        if not client['rekey_in_progress'] and len(plaintext) > 900 and b'mlkem' in plaintext:
            print(f'[REKEY] Triggered for {ip_port} at packet {packet.frame_info.number}')
            client['rekey_in_progress'] = True

        # 2. count down 4 packets after the 1st handshake msg
        if client['rekey_in_progress']:
            # check if a new key is available
            if len(key_list) > 1:
                if client['rekey_handshake_count'] > 1:
                    client['rekey_handshake_count'] -= 1
                else:
                    # Countdown finished, switch to new keys and reset state
                    print(f'[REKEY] Completing for {ip_port}. Switching to new keys.')
                    # Replace the list with a new list containing only the new key
                    client['C2S_keys'] = [client['C2S_keys'][-1]]
                    client['S2C_keys'] = [client['S2C_keys'][-1]]
                    client['rekey_in_progress'] = False
                    client['rekey_handshake_count'] = 4 # Reset for next time
            else:
                # wait for bpftrace to provide the new key
                pass
    except Exception as e:
        print(f'[PCAP] Error processing packet {getattr(packet, "frame_info", "N/A")}: {e}')

async def run_bpftrace() -> None:
    global KEX_MONITOR_PATH, clients
    proc = await asyncio.create_subprocess_exec(
        'sudo', '/usr/bin/bpftrace', KEX_MONITOR_PATH,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE
    )
    print(f'[KEX] BPFtrace started (PID: {proc.pid})')

    async def read_output(stream, prefix):
        while True:
            try:
                line = await stream.readline()
                if not line: break
                info = line.decode().strip()
                if info == 'Attaching 6 probes...': continue
                data = json.loads(info)
                client_id = f"{data['IP']}_{data['Port']}"

                if data['Type'] == 'New Client':
                    print(f"{prefix} New client detected: {client_id}")
                    clients[client_id] = {
                        'Name': data['C2S']['Cipher Name'],
                        'C2S_keys': [data['C2S']['Key']],
                        'S2C_keys': [data['S2C']['Key']],
                        'C2S_seqnr': 3,
                        'S2C_seqnr': 3,
                        'rekey_in_progress': False,
                        'rekey_handshake_count': 4
                    }
                elif data['Type'] == 'Rekey Client':
                    if client_id in clients:
                        print(f"{prefix} Rekeying client: {client_id}")
                        clients[client_id]['C2S_keys'].append(data['C2S']['Key'])
                        clients[client_id]['S2C_keys'].append(data['S2C']['Key'])
            except (json.JSONDecodeError, KeyError) as e:
                print(f"{prefix} Error parsing BPFtrace output: {e} | Line: {line.decode().strip()}")
            except asyncio.CancelledError:
                break

    stdout_task = asyncio.create_task(read_output(proc.stdout, '[KEX]'))
    stderr_task = asyncio.create_task(read_output(proc.stderr, '[KEX ERROR]'))
    try:
        await asyncio.gather(stdout_task, stderr_task)
    except asyncio.CancelledError:
        print("[KEX] BPFtrace task cancelled.")
    finally:
        if proc.returncode is None:
            proc.terminate()
            await proc.wait()
        stdout_task.cancel()
        stderr_task.cancel()
        await asyncio.gather(stdout_task, stderr_task, return_exceptions=True)
        print("[KEX] BPFtrace stopped.")

async def shutdown(loop: asyncio.AbstractEventLoop) -> None:
    print('\nShutting down monitoring...')
    if capture:
        print("[PCAP] Closing live capture...")
        capture.close()

    tasks = [t for t in asyncio.all_tasks() if t is not asyncio.current_task()]
    for task in tasks:
        task.cancel()

    await asyncio.gather(*tasks, return_exceptions=True)

    if capture_thread and capture_thread.is_alive():
        print("[THREAD] Waiting for capture thread to join...")
        capture_thread.join()

    # The loop.stop() will be called in the finally block of __main__
    
async def main() -> None:
    global capture_thread
    interface = 'eth0'  # Replace with your actual interface name

    capture_thread = threading.Thread(target=capture_packets, args=(interface,))
    capture_thread.daemon = False # Should be false to allow .join()
    capture_thread.start()

    async with aiofiles.open(LOG_FILE, 'w', encoding='utf-8', errors='replace') as log_f:
        try:
            await asyncio.gather(
                process_packets(log_f),
                run_bpftrace()
            )
        except asyncio.CancelledError:
            pass

if __name__ == '__main__':
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    try:
        loop.run_until_complete(main())
    except KeyboardInterrupt:
        print("\n[INT] KeyboardInterrupt detected.")
        loop.run_until_complete(shutdown(loop))
    finally:
        if loop.is_running():
            # wait for any final tasks from shutdown to complete
            loop.run_until_complete(asyncio.sleep(0.1))
            loop.stop()
        if not loop.is_closed():
            loop.close()
        print("Shutdown complete.")