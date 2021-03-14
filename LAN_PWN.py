import os
import subprocess
import time
import socket
import psutil
import sys

# Grabs local IP for default
def local_ip():
    hostname = socket.gethostname()
    localip = socket.gethostbyname(hostname)
    return localip

#Check if an IP is valid
def validate_ip(s):
    a = s.split('.')
    if len(a) != 4:
        return False
    for x in a:
        if not x.isdigit():
            return False
        i = int(x)
        if i < 0 or i > 255:
            return False
    return True

# Clear console
def cls():
    os.system('clear')

#Global vars
NIC_Choice = "eth0"
ip_range = ""
fast = False
passive = False

def change_global(var, value):
    if var == "NIC_Choice":
        global NIC_Choice
        NIC_Choice = value
    elif var == "ip_range":
        global ip_range
        ip_range = value
    elif var == "fast":
        global fast
        fast = value
    elif var == "passive":
        global passive
        passive = value


def check_global(var):
    if var == "NIC_Choice":
        global NIC_Choice
        return NIC_Choice
    elif var == "ip_range":
        global ip_range
        return ip_range
    elif var == "fast":
        global fast
        return fast
    elif var == "passive":
        global passive
        return passive

# Net Discover (Option 1)
def net_discover():

    print("""
     __ _ ____ ___   ___  _ ____ ____ ____ _  _ ____ ____
     | \| |===  |    |__> | ==== |___ [__]  \/  |=== |--<
    """)
    print(f"(1) IP range # Default auto")
    print(f"(2) Interface # Default eth0")
    print("(3) Fast mode")
    print("(4) Passive mode")
    print("(5) Start scan")
    print("(6) Back")
    netdiscover_menu_choice = int(input("Please pick which tool you would like to use (by number): "))
    if netdiscover_menu_choice == 1:
        ip = input("Please enter IP range (ip)/(range): ")
        if validate_ip(ip[:-3]) is False:
            print("\nPlease enter a valid IP")
            time.sleep(3)
            cls()
            main()
        else:
            print(f"\nIP Range set to: {ip}")
            change_global("ip_range", ip)
            time.sleep(3)
            cls()
            net_discover()
    elif netdiscover_menu_choice == 2:
        addrs = psutil.net_if_addrs()
        num = 1
        print("List of available NICs: ")
        keys = addrs.keys()
        NICs = []
        for NIC in keys:
            print(f"{NIC}")
            num += 1
            NICs.append(NIC)
        NIC_Choice = input("Please enter an NIC to use (By name): ")
        if NIC_Choice in NICs:
            print(f"NIC set to: {NIC_Choice}")
            change_global("NIC_Choice", NIC_Choice)
            time.sleep(3)
            cls()
            net_discover()
        else:
            print(f"Invalid NIC: {NIC_Choice}")
            time.sleep(3)
            cls()
            net_discover()
    elif netdiscover_menu_choice == 3:
        if check_global("fast") is False:
            change_global("fast", True)
            print("Fast mode enabled!")
            time.sleep(3)
            cls()
            net_discover()
        else:
            change_global("fast", False)
            print("Fast mode disabled!")
            time.sleep(3)
            cls()
            net_discover()
    elif netdiscover_menu_choice == 4:
        if check_global("passive") is False:
            change_global("passive", True)
            print("Passive mode enabled!")
            time.sleep(3)
            cls()
            net_discover()
        else:
            change_global("passive", False)
            print("Passive mode disabled!")
            time.sleep(3)
            cls()
            net_discover()
    elif netdiscover_menu_choice == 5:
        if fast is True and passive is True:
            print("Passive and fast cannot be active at the same time!")
            time.sleep(3)
            cls()
            net_discover()
        else:
            print("This may take a while to run. Please be patient!\n")
            if fast is False:
                if passive is False:
                    ip_range = check_global("ip_range")
                    if ip_range == "":
                        NIC_Choice = check_global("NIC_Choice")
                        print(f"Starting scan on {NIC_Choice}")
                        time.sleep(3)
                        os.system(f"netdiscover -i {NIC_Choice}")
                    else:
                        os.system(f"netdiscover -i {NIC_Choice} -r {ip_range}")
                else:
                    os.system(f"netdiscover -i {NIC_Choice} -p")
            else:
                os.system(f"netdiscover -i {NIC_Choice} -f")
    elif netdiscover_menu_choice == 6:
        cls()
        main()
    else:
        print("\nPlease choose from 1 - 6")
        time.sleep(3)
        cls()
        net_discover()

def port_scan():
    pass

# Main menu
def main():
    if os.geteuid() != 0:
        print("\nPlease run this with sudo or as root!")
        sys.exit()

    print("""
     _  _ ____ _ __ _   _  _ ____ __ _ _  _
     |\/| |--| | | \|   |\/| |=== | \| |__|
    """)
    print("(1) Net discover")
    print("(2) Port scan")
    print("(3) Packet sniffer")
    print("(4) ARP poisining")
    print("(5) ARP spoofing")
    print("(6) MAC changer")
    print("(7) MSFVenom")
    print("(8) Credits")
    menu_choice = input("Please pick which tool you would like to use (by number): ")
    menu_choice = int(menu_choice)
    if menu_choice == 1:
        cls()
        net_discover()
    elif menu_choice == 2:
        cls()
        port_scan()
    elif menu_choice == 3:
        pass
    elif menu_choice == 4:
        pass
    elif menu_choice == 5:
        pass
    elif menu_choice == 6:
        pass
    elif menu_choice == 7:
        pass
    elif menu_choice == 8:
        pass
    else:
        print("\nPlease pick a number between 1 and 8!")
        time.sleep(3)
        cls()
        main()


if __name__ == "__main__":

    main()
