#!/bin/bash

# Function to handle Ctrl+C
function ctrl_c() {
    echo "Ctrl+C detected. Stopping ebpf_performance..."
    pkill -SIGINT ebpf_performance  # Send SIGINT signal to terminate the process

    # Step 2: Check if output.txt exists and is not empty
    if [ -s "output.txt" ]; then
        echo "Output file generated successfully."

        # Step 3: Run Python script to process the data
        echo "Running Python script to process the data..."
        sudo python3 ./py/hash_aray.py

        if [ $? -eq 0 ]; then
            echo "Python script executed successfully."
        else
            echo "Python script failed to execute."
        fi
    else
        echo "Failed to generate output file or the file is empty."
        exit 1
    fi

    exit 0
}

# Trap Ctrl+C signal
trap ctrl_c INT

# Step 1: Run eBPF program and redirect output to output.txt in a loop
echo "Starting eBPF program..."
sudo ./ebpf_performance -a > output.txt &

# Wait for the eBPF program to be manually terminated by Ctrl+C
wait $!

# If the script reaches here without Ctrl+C, it means ebpf_performance finished by itself
echo "eBPF program finished by itself, running Python script..."
ctrl_c
