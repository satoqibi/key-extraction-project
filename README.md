# key-extraction-project
### Set up: Kali Linux 6.12.25

### Dependencies:
1. Open debug.list:
   $ sudo nano /etc/apt/sources.list.d/debug.list
2. Add this line:
   deb http://deb.debian.org/debian-debug/ trixie-debug main
3. Update apt pkg list:
   $ sudo apt update
4. Install debug symbols:
   $ sudo apt install openssh-server-dbgsym
5. Install gdb debugger:
   $ sudo apt install gdb
6. Install bpftrace:
   $ sudo apt install bpftrace
7. Python dependencies:
   - Create a virtual environment: $ python3 -m venv venv_name
   - Activate venv_name:           $ source venv_name/bin/activate
   - Install libraries:            $ pip3 install pycryptodome
                                   $ pip3 install pyshark

### Run:
1. Start the SSH server:
   $ sudo systemctl start ssh
2. Start packet capture on Wireshark.
3. Run the bpftrace script:
   $ sudo bpftrace [auth_kex | auth_state].bt # prints the keys in the terminal when the client connects
   or
   $ sudo kex_key_logger.sh # logs the keys to a log file when the client connects
4. Client connects to the server. The keys get logged/printed. The SSH session continues.
5. When the SSH session ends, stop the network capture and save the pcap file.
6. Run the decryption script:
   $ python3 chacha20_decryption.py
