import getpass
from netmiko import ConnectHandler

# 1. Ask you for the device details
ip_address = input("Enter Juniper Device IP: ")
username = input("Enter Username: ")
password = getpass.getpass("Enter Password: ") # This hides your typing
interface_name = input("Which interface do you want to check? (e.g., ge-0/0/0): ")

# 2. Define the device "dictionary"
juniper_device = {
    'device_type': 'juniper_junos',
    'host': ip_address,
    'username': username,
    'password': password,
}

print(f"\n--- Connecting to {ip_address} ---")

try:
    # 3. Establish the SSH connection
    connection = ConnectHandler(**juniper_device)
    
    # 4. Create the command
    command = f"show interfaces terse {interface_name}"
    
    # 5. Send the command and get the output
    output = connection.send_command(command)
    
    print("\nRESULT:")
    print(output)
    
    # 6. Close the connection
    connection.disconnect()

except Exception as e:
    print(f"Error: Could not connect. {e}")