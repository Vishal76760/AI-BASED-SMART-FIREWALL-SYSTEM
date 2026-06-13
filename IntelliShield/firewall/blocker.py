import os

# IP to block
ip = "192.168.1.100"

# Windows firewall command
command = f'netsh advfirewall firewall add rule name="BlockIP" dir=in action=block remoteip={ip}'

# Execute command
os.system(command)

print(f"{ip} blocked successfully!")