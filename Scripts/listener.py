import asyncio
import aiofiles
import threading
from typing import Any, Optional
import queue
import pyshark
from pyshark.packet.packet import Packet
from pyshark.capture.live_capture import LiveCapture

PCAP_PATH = '/path/to/pcap.pcapng'
KEX_MONITOR_PATH = '/path/to/bt/script.bt'
LOG_FILE = '/path/to/log/file.log'
SSH_PKT_FIELD = 'SSH Version 2 (encryption:chacha20-poly1305@openssh.com mac:<implicit> compression:none)'
LEN_FIELD = 'ssh.packet_length_encrypted_raw'
MAC_FIELD = 'ssh.mac_raw'

# Thread-safe queue to hold captured packets
packet_queue: queue.Queue = queue.Queue()

# Global references to the capture process and its thread
capture: Optional[LiveCapture] = None
capture_thread: Optional[threading.Thread] = None


def capture_packets(interface: str) -> None:
    global PCAP_PATH, capture
    # Assign the capture instance to the global variable
    capture = pyshark.LiveCapture(interface=interface, bpf_filter='tcp port 22', use_json=True, include_raw=True, output_file=PCAP_PATH)

    def packet_handler(packet: Any) -> None:
        packet_queue.put(packet)

    try:
        capture.apply_on_packets(packet_handler, timeout=100)
    except asyncio.CancelledError:
        # This can be triggered when the capture is closed from another thread
        print("[PCAP] Capture operation cancelled.")
    finally:
        print("[PCAP] Capture stopped.")

async def process_packets() -> None:
    while True:
        try:
            packet = packet_queue.get_nowait()
            await process_packet(packet)
        except queue.Empty:
            await asyncio.sleep(0.1)
        except asyncio.CancelledError:
            print("[PROCESS] Packet processing stopped.")
            break

async def process_packet(packet: Packet) -> None:
    global LOG_FILE, SSH_PKT_FIELD, LEN_FIELD, MAC_FIELD
    async with aiofiles.open(LOG_FILE, 'a', encoding='utf-8', errors='replace') as f:
        # Async packet processing
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

            log_entry = (
                f'Frame: {packet.frame_info.number}\n'
                f'{packet.ip.src}->{packet.ip.dst}\n'
                f'MAC: {pkt_info[MAC_FIELD][0]}\n\n'
            )
            await f.write(log_entry)
            await f.flush()  # Ensure immediate write
        except AttributeError:
            print(f'[PCAP] Packet {packet.frame_info.number} missing expected fields: {packet}')
        except Exception as e:
            print(f'[PCAP] Error processing packet: {e}')

async def run_bpftrace() -> None:
    '''Run bpftrace script and capture output'''
    global KEX_MONITOR_PATH
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
                if not line:
                    break
                print(f'{prefix} {line.decode().strip()}')
            except asyncio.CancelledError:
                break
    
    # Create reader tasks
    stdout_task = asyncio.create_task(read_output(proc.stdout, f'[KEX]'))
    stderr_task = asyncio.create_task(read_output(proc.stderr, f'[KEX ERROR]'))

    try:
        await asyncio.gather(stdout_task, stderr_task)
        await proc.wait()
    except asyncio.CancelledError:
        print("[KEX] BPFtrace task cancelled.")
        if proc.returncode is None:
            proc.terminate()
            await proc.wait()
        print("[KEX] BPFtrace stopped.")
    finally:
        # Ensure tasks are cancelled if the subprocess finishes early
        stdout_task.cancel()
        stderr_task.cancel()

async def shutdown(loop):
    '''Graceful shutdown handler'''
    print('\nShutting down monitoring...')

    # 1. Close the pyshark capture, which will unblock the thread
    if capture:
        print("[PCAP] Closing live capture...")
        capture.close()

    # 2. Cancel all running asyncio tasks
    tasks = [t for t in asyncio.all_tasks() if t is not asyncio.current_task()]
    for task in tasks:
        task.cancel()

    # 3. Wait for all tasks to complete their cancellation
    await asyncio.gather(*tasks, return_exceptions=True)

    # 4. Wait for the non-async capture thread to finish
    if capture_thread and capture_thread.is_alive():
        print("[THREAD] Waiting for capture thread to join...")
        capture_thread.join()

    loop.stop()

async def main() -> None:
    '''
    Main coroutine that starts the packet capture in a separate thread and
    runs the packet processing and other tasks concurrently.
    '''
    global capture_thread
    interface = 'interface_name'  # Replace with your actual interface name

    # Start the packet capture in a separate thread
    capture_thread = threading.Thread(target=capture_packets, args=(interface,))
    # Make the thread non-daemon so we can .join() it on shutdown
    capture_thread.daemon = False
    capture_thread.start()

    await asyncio.gather(
        process_packets(),
        run_bpftrace()
    )

if __name__ == '__main__':
    # 1. Create a new event loop
    loop = asyncio.new_event_loop()
    # 2. Set it as the current event loop for this thread
    asyncio.set_event_loop(loop)

    try:
        # Run the main coroutine
        loop.run_until_complete(main())
    except KeyboardInterrupt:
        # The shutdown function will use the same loop
        loop.run_until_complete(shutdown(loop))
    finally:
        if loop.is_running():
            loop.stop()
        if not loop.is_closed():
            loop.close()
        print("Shutdown complete.")