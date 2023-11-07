Wi-Fi Handshake Capture and Cracking Tool
This application is designed for educational purposes to demonstrate the process of capturing Wi-Fi handshakes and attempting to crack them using a wordlist. It automates the detection and processing of wireless networks and handles handshake capturing and password cracking.

Prerequisites
Linux Operating System
Python 3.x installed
aircrack-ng suite installed
A wireless adapter capable of monitor mode
Wordlist files stored in a wordlists directory
Setup
Clone the repository or download the script to your local machine.
Make sure you have the necessary permissions to execute the script (run as root or with sudo).
Usage
Start the Script:

Run the script using Python:
Copy code
sudo python3 cracker.py

Select Wireless Interface:

The script will list available wireless interfaces. Enter the number corresponding to the interface you want to use.

Scanning for Networks:

The script will then scan for available Wi-Fi networks. Press Ctrl+C to stop scanning.

Select Networks to Process:

Choose the networks you want to capture handshakes from. Enter the numbers corresponding to the networks, separated by commas.

Capture Handshakes:

The script will capture handshakes for the selected networks and save them in the handshakes directory, organized by network name.

Wordlist Selection:

Select a wordlist from the wordlists directory for password cracking.

Cracking Passwords:

The script will attempt to crack the captured handshakes using the selected wordlist.

Important Notes:
This tool is intended for educational and ethical use only. Unauthorized network scanning and access are illegal and unethical.
Ensure you have explicit permission to test the networks you are scanning.
The effectiveness of the password cracking depends on the wordlist used and the complexity of the network password.

Author: @rdvdn5
