from scapy.all import *
import os
import signal
import sys


def handle_exit(signal,frame):
    print("\n---------------------")
    print("CTRL+C pressed ABORTING")
    print("---------------------")
    os.system("kill -9 "+str(os.getpid()))
    sys.exit(1)

def signal_exit(signal,frame):
    print("Signal Exit")
    sys.exit(1)


def syntax_uage():
    if len(sys.argv) < 3:
        print("\n Correct Usage:")
        print("\t python main.py -i (interface)\n")
        sys.exit(1)


def sniff_packets(packet):
    try:
        DSTMAC = packet[0].addr1
        SRCMAC = packet[0].addr2
        BSSID = packet[0].addr3
    except:
        print("MAC Address unreadable")
        print(str(packet).encode("hex"))
        sys.exec_clear()

    try:
        SSIDSize = packet[0][Dot11Elt].len
        SSID = packet[0][Dott11Elt].info
    except:
        SSID=""
        SSIDSize=0

    if packet[0].type == 0:
        ST = packet[0][Dot11].subtype
        if str(ST) == "8" and SSID != "" and DSTMAC.lower() == "ff:ff:ff:ff:ff:ff":
            p=packet[0][Dot11Elt]
            cap=packet.sprintf("{Dot11Beacon:%Dot11Beacon.cap%}""{Dot11ProbeResp:%Dot11ProbeResp.cap%}").split("+")
            channel=None
            crypto=set()
    

def init_process():
    global ssid_list
    ssid_list={}
    global s
    s = conf.L2socket(iface=newiface)


def monitor_setup(iface):
    print("Setting up sniffing options...")
    os.system("if config "+iface+" down")
    try:
        os.system("iwconfig "+iface+" mode monitor")
    except:
        print("Failed to start up monitore moded PEAK ONE MATE")
        sys.exit(1)
    os.system("ifconfig "+iface+" up")
    return iface

def is_user_root_lmfao():
    if not os.geteuid() == 0:
        print("You must be root stoopid ass")
        exit(1)

if __name__ == "__main__":
    signal.signal(signal.SIGNIT, handle_exit)
    syntax_uage()
    is_user_root_lmfao
    parameters={sys.argv[1]:sys.argv[2]}
    if "mon" not in str(parameters["-i"]):
        newiface=monitor_setup(parameters["-i"])
    else:
        newiface=str(parameters["-i"])
    init_process()
    print("Starting this OP ASSS WyFy SNIFFER")
    print("Imma sniff "+str(newiface)+" just sit back and watch innit")
    sniff(iface=newiface, prn=sniff_packets, store=0)
