#!/bin/bash

timestamp=$(date +"%Y-%m-%d_%H:%M:%S")
log_file="/home/kali/key-extraction-project/key_logs/chacha20/${timestamp}.log"

sudo bpftrace auth_kex.bt > ${log_file}

echo "EK logged to ${log_file}"
