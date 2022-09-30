#Description: IpScan module is written in python language that takes target's cloudeflare behins IPS from censys and security trails when these were cached in censys and security trails databases then it scans all its open ports, icmp requests and running services.

#Here we are import require modules
import censys.ipv4
from sys import argv
import requests
import os
import subprocess
from subprocess import Popen, PIPE
import json

url = "https://api.securitytrails.com/v1/"
API_URL = "https://censys.io/api/v1"
UID = "5d358748-c491-4c1c-a723-afc1a856f643"
SECRET = "jN4TMG1YYLIrHheSNgnElmuTOJFB6CN4"

#Receving list type data and file name and storing it to given name of file
def writeFile(data,fileName):
        with open(fileName,"w") as fp:
                for line in data:
                        fp.write(line+"\n")
                fp.close()
#Find victim different ips from censys
def hosts(site):
    global ips
    try:
        print("Hosts: %s" % site)
        print("----------------------------------------------------Using Censys web----------------------------------------------------------------------------------")
        #Here UID and SECRET are censys's user id and secret key repectively.
        hostss = censys.ipv4.CensysIPv4(UID, SECRET)
        #Find victims different ips
        for host in hostss.search(site):
            ips = (host["ip"])
        print("----------------------------------------------------Using Securitytrails Web----------------------------------------------------------------------------------")
        #Using APIKEY of security trails site
        headers = {"Accept": "application/json", 'APIKEY': '9PtU7gUsIuULye6PJp2NiWz9BRbwGrXP'}
        response = requests.request("GET", url + "history/" + site + "/dns/a", headers=headers)
        #print(response.text)
        #print(json.dumps(response.text, indent=1))
        with open(site+"/sec_trails.json", 'w') as f:
            f.write(str(response.text))
        #Grep only ips from sec_trails.json which is in json format
        os.system("cat "+site+"/sec_trails.json | grep -E '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' -o  > "+site+"/temp.txt")
        #Grep ips save into temp.txt file
        with open(site+'/temp.txt') as f2:
            f2.write(ips)
    except:
        print("Not Found Any Hosts")
#Grep ips excluding cloudflare's ips
def filterCloudeFlareIp(ips):
    dataToWrite=[]
    for ip in ips:
        #Checking cloudflare's ips
        result = subprocess.Popen(["whois",ip], stdout=PIPE)
        out = result.communicate()
        if "CLOUDFLARENET" in str(out):
            print("\033[1;31;40m Cloudeflare Ip : \033[1;37;40m"+ip)
        else:
            #Ips which are without cloudflare
            print("\033[1;32;40m Without Cloudeflare Ip : \033[1;37;40m"+ip)
            dataToWrite.append(ip)
    return(dataToWrite)
#Check icmp requests
def check_ping(data):
    dataToWrite=[]
    for ip in data:
        if os.system("ping -c 2 -w 2 "+ip+" > /dev/null"):
            print("\033[1;31;40m Ping Not Allowed: \033[1;37;40m"+ip)
        else:
            print("\033[1;32;40m PING Allowd: \033[1;37;40m"+ip)
            dataToWrite.append(ip)
    return(dataToWrite)
#Scanning all ports of ips using rust scan
def rst_scan(data):
    dataToWrite=[]
    #Declare rust scan command --ulimit="Number of connection in a time"
    cmd = "rustscan --ulimit 5000 -g -a "
    for ip in data:
        #Running rustscan command with subprocess
        result = subprocess.Popen([cmd + ip], stdout=subprocess.PIPE, shell=True)
        #Getting result from rustscan output using communicate function
        (out, err) = result.communicate()
        res = out.decode("utf-8")
        print(res)
        dataToWrite.append(res)
    #Rust scan result is saving in rst_res.txt file
    writeFile(dataToWrite, "rst_res.txt")
    #Grep ip from rustscan result and save it on ip.txt file
    os.system("cat rst_res.txt | cut -d ' ' -f1 > "+site+"/ip.txt")
    #Grep ports from rustscan result and save it on ports.txt file
    os.system("cat rst_res.txt | cut -d ' ' -f3 | tr -d '[]' > "+site+"/ports.txt")
#Start nmap to find running services
def nmap_scan(ips,ports):
    i = 0
    #If nmap_result.txt file exists then delete it first
    subprocess.run(["rm",site+"/namp_result.txt"],shell=False,stdout=PIPE,stdin=PIPE,stderr=PIPE)
    while i < len(ips):
        if ports[i]:
            print("Scanning For: "+ips[i]+" and Ports : "+ports[i])
            #Checking ports running services against open ports and save it on nmap_result.txt
            os.system(f"nmap -sV {ips[i]} -p{ports[i]}" + " >> "+site+"/namp_result.txt")
        else:
            #Print message if no open ports found
            print("Scanning For: "+ips[i]+" and Ports : "+ports[i]+" No open port")
        i = i+1   
site = str(argv[1])
