import os
import subprocess
import time
import socket
import psutil
import sys
import threading
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
# Global vars
NIC_Choice = "eth0"
ip_range = ""
nmap_ips = ""
nmap_ports = ""
scan_type = ""
fast = False
passive = False
banners = []
verbose = False
scan_type = ""
display_filter = ""
capture_filter = ""
protocol_filter = ""
count = ""
default_gateway = ""
target_ip = ""
driftnet_check = True
mac_address = ""
change_type = "-r"
BIA = False

# Change global var
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
    elif var == "nmap_ips":
        global nmap_ips
        nmap_ips = value
    elif var == "nmap_ports":
        global nmap_ports
        nmap_ports = value
    elif var == "verbose":
        global verbose
        verbose = value
    elif var == "scan_type":
        global scan_type
        scan_type = value
    elif var == "display_filter":
        global display_filter
        display_filter = value
    elif var == "capture_filter":
        global capture_filter
        capture_filter = value
    elif var == "protocol_filter":
        global protocol_filter
        protocol_filter = value
    elif var == "count":
        global count
        count = value
    elif var == "default_gateway":
        global default_gateway
        default_gateway = value
    elif var == "target_ip":
        global target_ip
        target_ip = value
    elif var == "driftnet_check":
        global driftnet_check
        driftnet_check = value
    elif var == "mac_address":
        global mac_address
        mac_address = value
    elif var == "change_type":
        global change_type
        change = value
    elif var == "BIA":
        global BIA
        BIA = value

# Get value of global var
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
    elif var == "nmap_ips":
        global nmap_ips
        return nmap_ips
    elif var == "nmap_ports":
        global nmap_ports
        return nmap_ports
    elif var == "verbose":
        global verbose
        return verbose
    elif var == "scan_type":
        global scan_type
        return scan_type
    elif var == "display_filter":
        global display_filter
        return display_filter
    elif var == "capture_filter":
        global capture_filter
        return capture_filter
    elif var == "protocol_filter":
        global protocol_filter
        return protocol_filter
    elif var == "count":
        global count
        return count
    elif var == "default_gateway":
        global default_gateway
        return default_gateway
    elif var == "target_ip":
        global target_ip
        return target_ip
    elif var == "driftnet_check":
        global driftnet_check
        return driftnet_check
    elif var == "change_type":
        global change_type
        return change_type
    elif var == "mac_address":
        global mac_address
        return mac_address
    elif var == "BIA":
        global BIA
        return BIA
# Grabs banner of a port
def grab_banner(ip, port):
    connect = socket.socket()
    connect.settimeout(3.0)

    try:
        connect.connect((ip, port))
        banner = connect.recv(10240)
        banner = banner.decode('utf-8')
    except socket.timeout:
        banner = f"{port} was unresponsive!"
    except socket.error as e:
        banner = f"{ip} returned {e}"
    connect.close()
    banners.append(banner)

# Scan type selection
def scan_type_selection():
    print("(1) Syn Scan -sS")
    print("(2) Ack scan -sA")
    print("(3) Null scan -sN")
    print("(4) UDP scan -sU")
    print("(5) TCP scan -sT")
    print("(6) XMAS scan -sX")
    print("(7) Back")
    scan_choice = input("Please pick a scan type (by number): ")
    if scan_choice == "1":
        change_global("scan_type", "-sS")
        print("Scan set to -sS")
        time.sleep(1)
        cls()
        nmap_scan()
    elif scan_choice == "2":
        change_global("scan_type", "-sA")
        print("Scan set to -sA")
        time.sleep(1)
        cls()
        nmap_scan()
    elif scan_choice == "3":
        change_global("scan_type", "-sN")
        global scan_type
        print(f"Scan set to -sN")
        time.sleep(1)
        cls()
        nmap_scan()
    elif scan_choice == "4":
        change_global("scan_type", "-sU")
        global scan_type
        print("Scan set to -sU")
        time.sleep(1)
        cls()
        nmap_scan()
    elif scan_choice == "5":
        change_global("scan_type", "-sT")
        global scan_type
        print("Scan set to -sT")
        time.sleep(1)
        cls()
        nmap_scan()
    elif scan_choice == "6":
        change_global("scan_type", "-sX")
        global scan_type
        print("Scan set to -sX")
        time.sleep(1)
        cls()
        nmap_scan()
    elif scan_choice == "7" or scan_choice == "back":
        cls()
        nmap_scan()
    else:
        print("Please choose between 1 and 7")
        time.sleep(2)
        cls()
        scan_type_selection()

# Nmap scan
def nmap_scan():
    print("(1) Choose scan # Default auto")
    print("(2) Set IPs")
    print("(3) Set ports # Default top 1000")
    print("(4) Fast mode # Default False")
    print("(5) Verbose # Default off")
    print("(6) Scan")
    print("(7) Back")
    nmap_menu_choice = input("Please pick an option to set (by number): ")
    if nmap_menu_choice == "1":
        cls()
        scan_type_selection()
    elif nmap_menu_choice == "2":
        ips = input("Please enter the IPs you want to scan seperated by commas: ")
        ips_check = ips.split(",")
        valid_ips = True
        for ip in ips_check:
            if validate_ip(ip) is False:
                print("\nPlease enter a valid IP")
                time.sleep(3)
                cls()
                nmap_scan()
            else:
                valid_ips = True
        if valid_ips is True:
            print(f"IP(s) set to {ips}")
            change_global("nmap_ips", ips)
            time.sleep(2)
            cls()
            nmap_scan()
    elif nmap_menu_choice == "3":
        ports = input("Please enter the ports you want to scan, type * for all: ")
        if ports == "*":
            change_global("nmap_ports", "-")
            print("Nmap ports set to all")
            time.sleep(1)
            cls()
            nmap_scan()
        else:
            port_check = ports.slip(",")
            valid_ports = True
            for port in port_check:
                if 1 <= int(port) <= 65535:
                    valid_ports = True
                else:
                    print(f"{port} is invalid")
                    time.sleep(2)
                    cls()
                    nmap_scan()
            if valid_ports is True:
                change_global("nmap_ports", ports)
    elif nmap_menu_choice == "4":
        if check_global("fast") is False:
            change_global("fast", True)
            print("Fast mode enabled!")
            time.sleep(1)
            cls()
            nmap_scan()
        else:
            change_global("fast", False)
            print("Fast mode disabled!")
            time.sleep(1)
            cls()
            nmap_scan()
    elif nmap_menu_choice == "5":
        if check_global("verbose") is False:
            change_global("verbose", True)
            print("Verbose mode enabled!")
            time.sleep(1)
            cls()
            nmap_scan()
        else:
            change_global("verbose", False)
            print("Verbose mode disabled!")
            time.sleep(1)
            cls()
            nmap_scan()
    elif nmap_menu_choice == "6":
        global nmap_ips
        global scan_type
        global nmap_ports
        if nmap_ips == "":
            print("IPs were not set, please set IPs to scan!")
            time.sleep(2)
            cls()
            nmap_scan()
        else:
            if scan_type == "":
                if nmap_ports == "":
                    if fast is True:
                        if verbose is True:
                            os.system(f"nmap {nmap_ips} -F -v")
                        else:
                            os.system(f"nmap {nmap_ips} -F")
                    else:
                        if verbose is True:
                            os.system(f"nmap {nmap_ips} -v")
                        else:
                            os.system(f"nmap {nmap_ips}")
                else:
                    if fast is True:
                        if verbose is True:
                            os.system(f"nmap {nmap_ips} -p {nmap_ports} -F -v")
                        else:
                            os.system(f"nmap {nmap_ips} -p {nmap_ports} -F")
                    else:
                        if verbose is True:
                            os.system(f"nmap {nmap_ips} -p {nmap_ports} -v")
                        else:
                            os.system(f"nmap {nmap_ips} -p {nmap_ports}")
            else:
                if nmap_ports == "":
                    if fast is True:
                        if verbose is True:
                            os.system(f"nmap {scan_type} {nmap_ips} -F -v")
                        else:
                            os.system(f"nmap {scan_type} {nmap_ips} -F")
                    else:
                        if verbose is True:
                            os.system(f"nmap {scan_type} {nmap_ips} -v")
                        else:
                            os.system(f"nmap {scan_type} {nmap_ips}")
                else:
                    if fast is True:
                        if verbose is True:
                            os.system(f"nmap {scan_type} {nmap_ips} -p {nmap_ports} -F -v")
                        else:
                            os.system(f"nmap {scan_type} {nmap_ips} -p {nmap_ports} -F")
                    else:
                        if verbose is True:
                            os.system(f"nmap {scan_type} {nmap_ips} -p {nmap_ports} -v")
                        else:
                            os.system(f"nmap {scan_type} {nmap_ips} -p {nmap_ports}")

    elif nmap_menu_choice == "7" or nmap_menu_choice == "back":
        cls()
        port_scan()
    else:
        print("Please choose between 1 and 7")
        time.sleep(2)
        cls()
        nmap_scan()

# Net Discover (Option 1)
def net_discover():

    print("""
     __ _ ____ ___   ___  _ ____ ____ ____ _  _ ____ ____
     | \| |===  |    |__> | ==== |___ [__]  \/  |=== |--<
    """)
    print("(1) IP range # Default auto")
    print("(2) Interface # Default eth0")
    print("(3) Fast mode")
    print("(4) Passive mode")
    print("(5) Start scan")
    print("(6) Back")
    netdiscover_menu_choice = input("Please pick an option to set (by number): ")
    if netdiscover_menu_choice == "1":
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
    elif netdiscover_menu_choice == "2":
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
            time.sleep(1)
            cls()
            net_discover()
        else:
            print(f"Invalid NIC: {NIC_Choice}")
            time.sleep(2)
            cls()
            net_discover()
    elif netdiscover_menu_choice == "3":
        if check_global("fast") is False:
            change_global("fast", True)
            print("Fast mode enabled!")
            time.sleep(1)
            cls()
            net_discover()
        else:
            change_global("fast", False)
            print("Fast mode disabled!")
            time.sleep(1)
            cls()
            net_discover()
    elif netdiscover_menu_choice == "4":
        if check_global("passive") is False:
            change_global("passive", True)
            print("Passive mode enabled!")
            time.sleep(1)
            cls()
            net_discover()
        else:
            change_global("passive", False)
            print("Passive mode disabled!")
            time.sleep(1)
            cls()
            net_discover()
    elif netdiscover_menu_choice == "5":
        if fast is True and passive is True:
            print("Passive and fast cannot be active at the same time!")
            time.sleep(1)
            cls()
            net_discover()
        else:
            NIC_Choice = check_global("NIC_Choice")
            print("This may take a while to run. Please be patient!\n")
            if fast is False:
                if passive is False:
                    ip_range = check_global("ip_range")
                    if ip_range == "":

                        print(f"Starting scan on {NIC_Choice}")
                        time.sleep(3)
                        os.system(f"netdiscover -i {NIC_Choice}")
                    else:
                        os.system(f"netdiscover -i {NIC_Choice} -r {ip_range}")
                else:
                    os.system(f"netdiscover -i {NIC_Choice} -p")
            else:
                os.system(f"netdiscover -i {NIC_Choice} -f")
    elif netdiscover_menu_choice == "6" or netdiscover_menu_choice == "back":
        cls()
        main()
    else:
        print("\nPlease choose from 1 - 6")
        time.sleep(2)
        cls()
        net_discover()

# Port scan (Option 2)
def port_scan():
    print("""
    8888PPPp, 88888888   ,dbPPPp 888888888   88888888  doooooo ,8b.     888  ,d8 888  ,d8    8888 888  ,d8 888PPP8b
    8888    8 888  888   d88ooP'    '88d     88ooooPp  d88     88'8o    888_dPY8 888_dPY8    8888 888_dPY8 d88    `
    8888PPPP' 888  888 ,88' P'     '888             d8 d88     88PPY8.  8888' 88 8888' 88    8888 8888' 88 d8b PPY8
    888P      888oo888 88  do    '88p        8888888P  d888888 8b   `Y' Y8P   Y8 Y8P   Y8    8888 Y8P   Y8 Y8PPPPPP
    _  _
    """)
    print("(1) NMAP")
    print("(2) Banner Grab")
    print("(3) Back")
    scan_menu_choice = input("Please pick a scanner to use: ")
    if scan_menu_choice == "1":
        cls()
        nmap_scan()
    elif scan_menu_choice == "2":
        ip = input("Please enter an IP to scan or a list seperated by commas: ")
        ips = ip.split(",")
        for ip in ips:
            if validate_ip(ip) is False:
                valid_ips = False
                print("Invalid IP, please enter valid IP addresses ")
                time.sleep(2)
                cls()
                port_scan()
                break
            else:
                valid_ips = True
        if valid_ips is True:
            ports = input("Please enter a list of ports seperated by commas (80, 443, 22): ")
            ports = ports.split(",")
            ports = list(map(int, ports))
            threads = []
            no_of_ports = len(ports)
            i = 1
            for ip in ips:
                while i != no_of_ports:
                    t = threading.Thread(target=grab_banner, args=(ip, ports[i - 1]))
                    t.start()
                    threads.append(t)
                    i += 1

            for thread in threads:
                thread.join()
            for banner in banners:
                if len(banner) == 0:
                    banner = "Port responded but no banner given"
                else:
                    for port in ports:
                        print(f"{ip}:{port}     {banner}\n")
                time.sleep(5)
        else:
            print("Please enter a valid IP!")
    elif scan_menu_choice == "3" or scan_menu_choice == "back":
        cls()
        main()
    else:
        print("Please pick between 1 and 4")
        time.sleep(2)
        cls()
        port_scan()

# Packet sniffer (Option 3)
def packet_sniff():
    print("""
  ____            _        _     ____        _  __  __
 |  _ \\ __ _  ___| | _____| |_  / ___| _ __ (_)/ _|/ _|
 | |_) / _` |/ __| |/ / _ \\ __| \\___ \\| '_ \\| | |_| |_
 |  __/ (_| | (__|   <  __/ |_   ___) | | | | |  _|  _|
 |_|   \\__,_|\\___|_|\\_\\___|\\__| |____/|_| |_|_|_| |_|

    """)
    print("(1) Set NIC # Default eth0 ")
    print("(2) Set display filter")
    print("(3) Set capture filter")
    print("(4) Set protocol")
    print("(5) Set packet count # Default infinite")
    print("(6) Sniff packets")
    print("(7) Back")
    packet_sniff_menu_check = input("Please pick an option to set (By number): ")
    if packet_sniff_menu_check == "1":
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
            time.sleep(1)
            cls()
            packet_sniff()
        else:
            print(f"Invalid NIC: {NIC_Choice}")
            time.sleep(2)
            cls()
            packet_sniff()
    elif packet_sniff_menu_check == "2":
        display_filter = input("Please enter a display filter: ")
        change_global("display_filter", display_filter)
        print(f"Display filter changed to {display_filter}")
        time.sleep(1)
        cls()
        packet_sniff()
    elif packet_sniff_menu_check == "3":
        capture_filter = input("Please enter an capture filter type: ")
        change_global("capture_filter", capture_filter)
        print(f"Capture filter changed to {capture_filter}")
        time.sleep(1)
        cls()
        packet_sniff()
    elif packet_sniff_menu_check == "4":
        protocol_filter = input("Please enter a protocol filter: ")
        change_global("protocol_filter", protocol_filter)
        print(f"Protocol filter changed to {protocol_filter}")
        time.sleep(1)
        cls()
        packet_sniff()
    elif packet_sniff_menu_check == "5":
        count = input("Please enter the number of packets you want to sniff: ")
        count = int(count)
        change_global("count", count)
        print(f"Count changed to {count}")
        time.sleep(1)
        cls()
        packet_sniff()
    elif packet_sniff_menu_check == "6":
        NIC_Choice = check_global("NIC_Choice")
        display_filter = check_global("display_filter")
        protocol_filter = check_global("protocol_filter")
        packet_count = check_global("packet_count")
        capture_filter = check_global("capture_filter")
        count = check_global("count")
        if display_filter == "":  # No display filter
            if protocol_filter == "":  # No protocol filter
                if capture_filter == "":  # No capture filter
                    if count == "":  # No count
                        os.system(f"tshark -i {NIC_Choice} -P --color -w out.pcapng")
                    else:  # No filters with count
                        os.system(f"tshark -i {NIC_Choice} -c {packet_count} -P --color -w out.pcapng")
                else:  # Cpature filter set
                    if count == "":  # No count
                        os.system(f"tshark -i {NIC_Choice} -f {capture_filter} -P --color -w out.pcapng")
                    else:  # With count
                        os.system(f"tshark -i {NIC_Choice} -f {capture_filter} -c {count} -P --color -w out.pcapng")
            else:  # Protocol filter
                if capture_filter == "":  # Protocl filter, no capture filter
                    if count == "":  # Protcol filter, no count
                        os.system(f"tshark -i {NIC_Choice} -J {protocol_filter} -P --color -w out.pcapng")
                    else:  # # Protcol filter, count
                        os.system(f"tshark -i {NIC_Choice} -J {protocol_filter} -c {count} -P --color -w out.pcapng")
                else:  # Protcol filter, capture filter, count
                    if count == "":
                        os.system(f"tshark -i {NIC_Choice} -J {protocol_filter} -f {capture_filter} -P --color -w out.pcapng")
                    else:  # Protcol filter, capture filter, count
                        os.system(f"tshark -i {NIC_Choice} -J {protocol_filter} -f {capture_filter} -P -c {count} --color -w out.pcapng")
        else:
            if protocol_filter == "":  # No protocol filter
                if capture_filter == "":  # No capture filter
                    if count == "":  # No count
                        os.system(f"tshark -i {NIC_Choice} -Y {display_filter} -P --color -w out.pcapng")
                    else:  # No filters with count
                        os.system(f"tshark -i {NIC_Choice} -c {packet_count} -Y {display_filter} -P --color -w out.pcapng")
                else:  # Cpature filter set
                    if count == "":  # No count
                        os.system(f"tshark -i {NIC_Choice} -f {capture_filter} -Y {display_filter} -P --color -w out.pcapng")
                    else:  # With count
                        os.system(f"tshark -i {NIC_Choice} -f {capture_filter} -c {count} -Y {display_filter} -P --color -w out.pcapng")
            else:  # Protocol filter
                if capture_filter == "":  # Protocl filter, no capture filter
                    if count == "":  # Protcol filter, no count
                        os.system(f"tshark -i {NIC_Choice} -J {protocol_filter} -Y {display_filter} -P --color -w out.pcapng")
                    else:  # # Protcol filter, count
                        os.system(f"tshark -i {NIC_Choice} -J {protocol_filter} -c {count} -Y {display_filter} -P --color -w out.pcapng")
                else:  # Protcol filter, capture filter, count
                    if count == "":
                         os.system(f"tshark -i {NIC_Choice} -J {protocol_filter} -f {capture_filter} -Y {display_filter} -P --color -w out.pcapng")
                    else:  # Protcol filter, capture filter, count
                        os.system(f"tshark -i {NIC_Choice} -J {protocol_filter} -f {capture_filter} -c {count} -Y {display_filter} -P --color -w out.pcapng")

    elif packet_sniff_menu_check == "7" or packet_sniff_menu_check == "back":
        cls()
        main()
    else:
        print("Please choose between 1 and 5")
        time.sleep(2)
        cls()
        packet_sniff()

# Arp spoof (Option 4)
def arp_spoof():
    print("""
         (   (      (
   (     )\\ ))\\ )   )\\ )                (
   )\\   (()/(()/(  (()/(                )\\ )
((((_)(  /(_))(_))  /(_))`  )   (    ( (()/(
 )\\ _ )\\(_))(_))   (_))  /(/(   )\\   )\\ /(_))
 (_)_\\(_) _ \\ _ \\  / __|((_)_\\ ((_) ((_|_) _|
  / _ \\ |   /  _/  \\__ \\| '_ \\) _ \\/ _ \\|  _|
 /_/ \\_\\|_|_\\_|    |___/| .__/\\___/\\___/|_|
                        |_|
    """)
    print("(1) Set your local IP (ifconfig)")
    print("(2) Set target IP")
    print("(3) Set NIC # Default eth0")
    print("(4) Use driftnet for listening # Default True")
    print("(5) Start spoofing")
    print("(6) Back")
    arp_spoof_menu_choice = input("Please choose an option (by number): ")
    if arp_spoof_menu_choice == "1":
        default_gateway = input("Please enter your default gateway IP: ")
        if validate_ip(default_gateway) is False:
            print("Please enter a valid IP ")
            time.sleep(2)
            cls()
            arp_spoof()
        else:
            change_global("default_gateway", default_gateway)
            print(f"Default gateway set to {default_gateway}")
            time.sleep(1)
            cls()
            arp_spoof()
    elif arp_spoof_menu_choice == "2":
        target_ip = input("Please enter the target IP: ")
        if validate_ip(target_ip) is False:
            print("Please enter a valid IP ")
            time.sleep(2)
            cls()
            arp_spoof()
        else:
            change_global("target_ip", target_ip)
            print(f"Target IP set to {target_ip}")
            time.sleep(1)
            cls()
            arp_spoof()
    elif arp_spoof_menu_choice == "3":
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
            time.sleep(1)
            cls()
            packet_sniff()
        else:
            print(f"Invalid NIC: {NIC_Choice}")
            time.sleep(2)
            cls()
            packet_sniff()
    elif arp_spoof_menu_choice == "4":
        driftnet_check = check_global("driftnet_check")
        if driftnet_check is True:
            print("Driftnet disabled!")
            change_global("driftnet_check", False)
            time.sleep(1)
            cls()
            arp_spoof()
        else:
            print("Driftnet enabled!")
            change_global("driftnet_check", True)
            time.sleep(1)
            cls()
            arp_spoof()
    elif arp_spoof_menu_choice == "5":
        default_gateway = check_global("default_gateway")
        target_ip = check_global("target_ip")
        driftnet_check = check_global("driftnet_check")
        NIC_Choice = check_global("NIC_Choice")
        if default_gateway == "" or target_ip == "":
            print("Make sure to set a default gateway and target IP")
            time.sleep(3)
            cls()
            arp_spoof()
        else:
            if driftnet_check is True:
                os.system(f"driftnet -i {NIC_Choice} &")
                os.system(f"arpspoof -i {NIC_Choice} -t {target_ip} {default_gateway}")
            else:
                os.system(f"arpspoof -i {NIC_Choice} -t {target_ip} {default_gateway}")
    elif arp_spoof_menu_choice == "6" or arp_spoof_menu_choice == "back":
        cls()
        main()
    else:
        print("Please choose from 1 - 5")
        time.sleep(2)
        cls()
        arp_spoof()

# Mac changer (Option 5)
def mac_changer():
    print("""
 __  __    __    ___     ___  _   _    __    _  _  ___  ____  ____
(  \\/  )  /__\\  / __)   / __)( )_( )  /__\\  ( \\( )/ __)( ___)(  _ \\
 )    (  /(__)\\( (__   ( (__  ) _ (  /(__)\\  )  (( (_-. )__)  )   /
(_/\\/\\_)(__)(__)\\___)   \\___)(_) (_)(__)(__)(_)\\_)\___/(____)(_)\\_)
    """)
    print("(1) Change type #Default fully random")
    print("(2) Set \"pretend to be burned-in-address\"")
    print("(3) Reset to default")
    print("(4) Choose NIC # Default eth0")
    print("(5) Change MAC address")
    print("(6) Back")
    mac_changer_menu_choice = input("Please choose an option (by number): ")
    if mac_changer_menu_choice == "1":
        print("(1) Random")
        print("(2) Change to random address by the same vendor")
        print("(3) Change to vendor of any kind")
        print("(4) Set the mac")
        print("(5) Back")
        change_type_choice = input("Please choose an option (by number): ")
        if change_type_choice == "1":
            change_global("change_type", "-r")
            time.sleep(1)
            cls()
            mac_changer()
        elif change_type_choice == "2":
            change_global("change_type", "-a")
            time.sleep(1)
            cls()
            mac_changer()
        elif change_type_choice == "3":
            change_global("change_type", "-A")
            time.sleep(1)
            cls()
            mac_changer()
        elif change_type_choice == "4":
            mac_address = input("Please enter tha MAC address you'd like to use")
            change_global("mac_address", mac_address)
            change_global("change_type", "-m")
            time.sleep(1)
            cls()
            mac_changer()
        elif change_type_choice == "5" or change_type_choice == "back":
            cls()
            mac_changer()
        else:
            print("Please choose between 1 and 5")
            time.sleep(2)
            cls()
            mac_changer()
    elif mac_changer_menu_choice == "2":
        BIA = check_global("BIA")
        if BIA is False:
            change_global("BIA", True)
            print("Pretend to be BIA is set")
            time.sleep(1)
            cls()
            mac_changer()
        else:
            change_global("BIA", False)
            print("Pretend to be BIA is unset")
            time.sleep(1)
            cls()
            mac_changer()
    elif mac_changer_menu_choice == "3":
        print("Changing to default")
        NIC_Choice = check_global("NIC_Choice")
        os.system(f"ip link set dev {NIC_Choice} down")
        os.system(f"macchanger -i {NIC_Choice} -p ")
        os.system(f"ip link set dev {NIC_Choice} up")
        cls()
        mac_changer()
    elif mac_changer_menu_choice == "4":
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
            time.sleep(1)
            cls()
            mac_changer()
        else:
            print("Please choose an NIC from the list")
            time.sleep(2)
            cls()
            mac_changer()

    elif mac_changer_menu_choice == "5":
        NIC_Choice = check_global("NIC_Choice")
        change_type = check_global("change_type")
        BIA = check_global("BIA")
        if BIA is False:
            if change_type == "":
                os.system(f"ip link set dev {NIC_Choice} down")
                os.system(f"macchanger -r {NIC_Choice}")
                os.system(f"ip link set dev {NIC_Choice} up")
                time.sleep(3)
                cls()
                main()
            else:
                if change_type == "-m":
                    mac_address = check_global("mac_address")
                    os.system(f"ip link set dev {NIC_Choice} down")
                    os.system(f"macchanger {change_type} {mac_address} {NIC_Choice}")
                    os.system(f"ip link set dev {NIC_Choice} up")
                    time.sleep(3)
                    cls()
                    main()
                else:
                    os.system(f"ip link set dev {NIC_Choice} down")
                    os.system(f"macchanger {change_type} {NIC_Choice}")
                    os.system(f"ip link set dev {NIC_Choice} up")
                    time.sleep(3)
                    cls()
                    main()
        else:
            if change_type == "":
                os.system(f"ip link set dev {NIC_Choice} down")
                os.system(f"macchanger -r --bia {NIC_Choice}")
                os.system(f"ip link set dev {NIC_Choice} up")
                time.sleep(3)
                cls()
                main()
            else:
                if change_type == "-m":
                    mac_address = check_global("mac_address")
                    os.system(f"ip link set dev {NIC_Choice} down")
                    os.system(f"macchanger --bia {change_type} {mac_address} {NIC_Choice}")
                    os.system(f"ip link set dev {NIC_Choice} up")
                    time.sleep(3)
                    cls()
                    main()
                else:
                    os.system(f"ip link set dev {NIC_Choice} down")
                    os.system(f"macchanger --bia {change_type} {NIC_Choice}")
                    os.system(f"ip link set dev {NIC_Choice} up")
                    time.sleep(3)
                    cls()
                    main()
    elif mac_changer_menu_choice == "6" or mac_changer_menu_choice == "back":
        cls()
        main()
    else:
        print("Please choose between 1 and 6")
        time.sleep(2)
        cls()
        mac_changer()
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
    print("(4) ARP spoof")
    print("(5) MAC changer")
    print("(6) Credits")
    print("(7) Exit")
    menu_choice = input("Please pick which tool you would like to use (by number): ")
    if menu_choice == "1":
        cls()
        net_discover()
    elif menu_choice == "2":
        cls()
        port_scan()
    elif menu_choice == "3":
        cls()
        packet_sniff()
    elif menu_choice == "4":
        cls()
        arp_spoof()
    elif menu_choice == "5":
        cls()
        mac_changer()
    elif menu_choice == "6":
        print("""
 ___  _                                  _  ___  _  ___
|  _><_>._ _ ._ _  ___ ._ _ _  ___ ._ _ / |<_  >/ |<_  >
| <__| || ' || ' |<_> || ' ' |/ . \| ' || | / / | | / /
`___/|_||_|_||_|_|<___||_|_|_|\___/|_|_||_|<___>|_|<___>

Github: https://github.com/Cinnamon1212
Discord: @Cinnamon#7617

        """)
    elif menu_choice == "7" or menu_choice == "exit":
        print("Goodbye!")
        time.sleep(1)
        cls()
        sys.exit()
    else:
        print("\nPlease pick a number between 1 and 8!")
        time.sleep(2)
        cls()
        main()


if __name__ == "__main__":
    cls()
    print("""
      _        _     _  _            ___  __      __  _  _   ___   ___
     | |      /_\   | \| |          | _ \ \ \    / / | \| | | __| | _ \\
     | |__   / _ \  | .` |          |  _/  \ \/\/ /  | .` | | _|  |   /
     |____| /_/ \_\ |_|\_|   ___    |_|     \_/\_/   |_|\_| |___| |_|_\\
                            |___|
      """)
    time.sleep(1)
    cls()
    main()
