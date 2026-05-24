import getpass
from netmiko import ConnectHandler
from netmiko.exceptions import NetmikoTimeoutException, NetmikoAuthenticationException

# 1. Collect Inputs
hostname = input("Enter Device Hostname: ")
username = input("Enter Username: ")
password = getpass.getpass("Enter Password: ")
interface_name = input("Which interface? (e.g., ge-0/0/0): ")

# 2. Define our two connection targets
# The script will try 'hostname' first, then 'hostname-con'
connection_targets = [hostname, f"{hostname}-con"]

connection = None

# 3. Loop through the targets
for target in connection_targets:
    print(f"\n>>> Attempting to connect to: {target}...")
    
    device_params = {
        'device_type': 'juniper_junos',
        'host': target,
        'username': username,
        'password': password,
    }

    try:
        connection = ConnectHandler(**device_params)
        print(f"SUCCESS: Connected to {target}")
        break  # Exit the loop if connection works
        
    except (NetmikoTimeoutException, NetmikoAuthenticationException) as e:
        print(f"FAILED: Could not reach {target}.")
        if target == connection_targets[-1]: # If this was the last attempt
            print("ERROR: All connection attempts failed. Check physical cabling or DNS.")
        else:
            print("Retrying with Console address...")

# 4. If we successfully connected, run the command
if connection:
    command = f"show interfaces terse {interface_name}"
    output = connection.send_command(command)
    
    print("\n--- COMMAND OUTPUT ---")
    print(output)
    
    connection.disconnect()