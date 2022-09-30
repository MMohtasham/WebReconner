#Description: This script is use to get all possible information about target like
#1.Detail information about target
#2. Subdomain enumuration
#3. Look for live subdomains
#4. Get WAF information if any one is used by any live subdomains
#5. Take screenshoots of front pages of live subdomains
#6. Check for subdomian takeover if possible
#7. Find ip of all subdomains
#8. Try DNS zone Transfer if possible
#9. Find CNAME record of subdomains if possible
#10. Search on all subdomains which technologies used and there version also
#11. Directory Busting with given list and number of concurrent threads
#12. Crawl site with given depth
#13. Get from wayback machine
#14. Subdomain Brute forcing
#15. virtual Host Brute Forcing
#16. Ip behind cloudeflare
#17. Check ICMP status
#18. Open port scanner
#19. Services scaning

#importing modules 
import requests
import sys
import re
import os
import fileinput
import subprocess
from subprocess import Popen, PIPE
import time
import psutil
import socket
import dns.resolver
import dns.query
import dns.zone
from Wappalyzer import Wappalyzer, WebPage
import json
from multiprocessing import Pool
import concurrent.futures
from ipScanModule import *

#these are some global variable to handel crawling
#crawling done recursivly so we use this for saving output from every recusive call in global variable
global llinkJs 
#save js file name and path
llinkJs  = []
global llink
#all other links should save here
llink = []
#to stop repetaion of already crawled links
global done
done = []
#Looking For WAF used by all subdomains
def tergetWaf(fileName):
        try:
                #running wafw00f for firewall identification
                command = "wafw00f -i "+fileName+" -o "+site+"/firewall.txt"
                subprocess.run(command.split(), shell=False, stderr=PIPE )
        except:
                #if any error 
                print("firewall detection error for "+site)
#getting detailed information about site using theHarvester tool 
def tergetDetailinfo(site):
        try:
                #theHarvester command
                runCommand("theHarvester -d "+site+" -b baidu,bing,bingapi,bufferoverun,certspotter,crtsh,dnsdumpster,duckduckgo,exalead,github-code,google,hackertarget,hunter,intelx,linkedin,linkedin_links,netcraft,omnisint,otx,pentesttools,projectdiscovery,qwant,rapiddns,securityTrails,spyse,sublist3r,threatcrowd,threatminer,trello,twitter,urlscan,virustotal,yahoo -f ./"+site+"/detail_info")
                print("Result for info save in ./"+site+"/detail_info.html")
        except:
                print("Error in finding information "+site)
#Subdomain enumuration done here
def subdomainEnum(site):
        try:
                #Temp file for storing output of all parallel process
                log = open(site+'/temp.txt', 'a')
                #Initilizing list of command of tools for subdomain enumuration
                commands = ["amass enum -d "+site,
                "sublist3r -n -d "+site,
                "findomain-linux -t "+site,
                "assetfinder --subs-only "+site,
                "chaos -d  "+site,
                "subfinder -d "+site+" -t 50"]
                #declaring a set for stor runing parallel process state
                processes = set()
                #intilizing variable for number of parallel process
                max_processes = 5
                #for loop for runing one command one by one
                for command in commands:
                        try:
                                processes.add(subprocess.Popen(command.split(),stdout=log))
                        except:
                                print("Error In "+command)
                        #checking number of process are running
                        if len(processes) >= max_processes:
                                os.wait()
                                processes.difference_update(
                                [p for p in processes if p.poll() is not None])
                #Check if all the child processes were closed
                for p in processes:
                        if p.poll() is None:
                                p.wait()
                #closing log file
                log.close()
        except:
                print("Error in finding subdomain "+site)
#getting line from file which containg specific string
def lines_that_contain(string, fp):
        return [lines for lines in fp if string in lines]
#removing repeting data from list
def unique_list(data):
        return list(set(data))
#stroing given list to givien file
def store_to_file(data,fileName):
        #opening file in fp variable
        with open(fileName, "w") as fp:
                #loop through file
                for line in data:
                        #writing to file
                        fp.write(line)
#getting unique line from file which containg specific string
def filterFile(stringToFind,fileName):
        try:
                #opening file as fp
                with open(fileName, "r") as fp:
                        return(unique_list(lines_that_contain(stringToFind, fp)))
        except:
                print("Some Error encounter in finding in "+fileName)
#taking subdomain file and look if that are alive or not
def liveSubdomainFinder(data):
        liveDomain=list()
        #loop through each subdomain
        for line in data:
                #if gost command through some error pass it otherwise store this domain to live domain variable
                if runCommand("host "+line+" > /dev/null"):
                        pass
                else:
                        print("\033[1;32;40mlive: \033[1;37;40m"+line)
                        liveDomain.append(line)
        #returning variables
        return liveDomain     
#Function for running command
def runCommand(command):
        #runing os command 
        return os.system(command) 
#geting file of subdomain and try take screen shots of there front page                          
def screen_shoot(filename):
        #running command for aquatone
        runCommand("cat "+filename+" | aquatone -out "+site+"/ScreenShots/aquatone")
        #running command for eyewitness
        runCommand("~/tools/EyeWitness/Python/./EyeWitness.py -f "+filename+" --web --threads 10 -d "+site+"/ScreenShots/eywitness --no-prompt")
#receving file of subdomain and check if any of them avaliable for takeover
def subdomainTakeOver(fileName):
        #running command for subdomain takeover using tool subjack
       runCommand("subjack -w "+fileName+" -t 100 -timeout 30 -o "+site+"/TakeOver.json -ssl -v -c $HOME/go/src/github.com/haccer/subjack/fingerprints.json")
#subdomain bruteforcing looking for A and CNAME record if it found then domain is live
def subDomainBrute(subdomain):
        try:
                #looking for A record of subdomain
                if dns.resolver.resolve(subdomain+"."+site, 'A'):
                       print("\033[1;36;40mFound Subdomain: \033[1;37;40m "+subdomain+"."+site)
                       return
        except:
                pass
        try:
                #looking for CNAME of subdomain
                if dns.resolver.resolve(subdomain+"."+site, 'CNAME'):
                       print("\033[1;36;40mFound Subdomain: \033[1;37;40m "+subdomain+"."+site)
                       return
        except:
                pass
#virtual Host Bruteforing 
def virtualHostBruteForceing(subdomain):
        try:
                #requst domain with host header of subdomain/virtualHost
                r = requests.get("https://"+site, headers={"HOST":subdomain+"."+site})
                #looking for status code return by domain if 200 or 302 or 301 then it is alive you can add more status code in condition 
                if r.status_code == 200 or r.status_code == 302 or r.status_code == 301:
                        print("\033[1;36;40mFound Virtual Host: \033[1;37;40m "+subdomain+"."+site)
        except:
                pass  
#receving list of subdomain and looking for ip's 
def findIp(input):
        #variable to write data to file
        dataToWrite=[]
        #for loop for checking subdomain one by one
        for line in input:
                try:
                        #using socket module to find ip 
                        ip = socket.gethostbyname(line)
                        print(line+" : \033[1;34;40m"+ip+"\033[1;37;40m")
                        dataToWrite.append(ip)
                except:
                        pass
        #writing output to file
        return dataToWrite
#reaading file from file name and retrning list type data
def readFile(fileName):
        #opening file as f 
        with open(fileName) as f:
                #reading files into lines var
                lines = f.read().splitlines()
                #rturning file data
                return lines
#receving list type data and file name and storing it to given name of file
def writeFile(data,fileName):
        #opening file as fp
        with open(fileName,"w") as fp:
                #readeing given data list line by line
                for line in data:
                        #writing line to file
                        fp.write(line+"\n")
                #closing file
                fp.close()
#receving list type data and file name and appending it with given file
def appendToFile(data,fileName):
        #opening file in appending mode
        with open(fileName,"a") as fp:
                #reading data from list line by line
                for line in data:
                        #writing to file
                        fp.write(line+"\n")
                #closing file
                fp.close()
#Looking for dns zone transfer
def dnsZoneTransfer(site):
        #variable to write data to file
        dataToWrite=[]
        try:
                #looking for SOA record for getting dns
                soa_answer = dns.resolver.resolve(site, 'SOA')
                #looking for arecord of dns
                master_answer = dns.resolver.resolve(soa_answer[0].mname, 'A')
                #try to transfor zone
                z = dns.zone.from_xfr(dns.query.xfr(master_answer[0].address, site))
                #if zone tranfer success then appending all data to list
                for n in sorted(z.nodes.keys()):
                        dataToWrite.append(z[n].to_text(n))
                #storing result to file
                writeFile(dataToWrite,site+"/ZoneTransferRecord.txt")
        except:
                print("Zone Transfer Failed")
#looking for CNAME record of subdomains
def findCNAME(input):
        #variable to write data to file
        dataToWrite=[]
        for sites in input:
                try:
                        #query DNS for CNAME
                        answers = dns.resolver.resolve(sites, 'CNAME')
                        for rdata in answers:
                                print(sites+" \033[1;31;40m[CNAME] \033[1;37;40m "+str(rdata))
                                dataToWrite.append(sites+" | "+str(rdata))
                except:
                        pass
        #Writing results to file
        writeFile(dataToWrite,site+"/CNAMERecord.txt")
#looking for technologies and versions used by domain and subdomain
def webTechVersion(input):
        #variable to write data to file
        dataToWrite=[]
        #initilizing wappalyzer object
        wappalyzer = Wappalyzer.latest()
        for sites in input:                
                try:
                        #getting webpage
                        webpage = WebPage.new_from_url("https://"+sites)
                        #looking for technologies used in webpage
                        tech=wappalyzer.analyze_with_versions_and_categories(webpage)
                        print("                 \033[1;32;40m"+sites+"\033[1;37;40m")
                        dataToWrite.append("                 "+sites)
                        for key, value in tech.items():
                                for i in tech[key]:
                                        if "[]" in str(tech[key][i]):
                                                print(key)
                                                dataToWrite.append(key)
                                        else:              
                                                print(key+" \033[1;34;40m"+str(tech[key][i])+"\033[1;37;40m")
                                                dataToWrite.append(key+" : "+str(tech[key][i]))
                                        break
                except:
                        dataToWrite.append("                 "+sites)
        #writing to file
        writeFile(dataToWrite,site+"/TechnologiesVersion.txt")
#directory busting core logic
def bust(bustingList):
        try:
                #initlizing url with given path
                url = "https://"+site+"/"+bustingList
                #making request to site and storing response
                try:
                        response = requests.get(url, verify=False ,timeout=(3.5,5))
                except:
                        print("\033[1;31;40mrequest time out for : \033[1;37;40m "+url)
                #looking for response status code
                if response.status_code == 200:
                        var=bustingList+"    \033[1;34;40m["+str(response.status_code)+"]\033[1;37;40m"
                        print(var)
                else:
                        pass
        except:
                pass
#receving list for busting and number of threads you want 
def dirBusting(bustingList,thredes):
        #calling bust function with given threads 
        with concurrent.futures.ThreadPoolExecutor(max_workers=thredes) as executor:
                executor.map(bust,bustingList)
#crawling site receving site domain and depth
def crawling(site,depth):
        #using previously globly dclared valiable 
        global done
        #look if site already in done list then return
        if site in done:
                return
        #if not already in done then append to done list and process further
        done.append(site)
        #locavariable for newly founded links
        tempL = []
        tempLJS = []
        try:
                #making request to site and storing response
                response = requests.get(site)
                #regex for all finding all links in response and storing to a list
                links = re.findall("(src|href|srcset)(\s*=\s*)(\'|\")(.*)(\'|\")",response.text)
                #loop through list for some filtration and sepearte some js files
                for link in links:
                        resu = re.search("^.*?(\"|\'|$)",link[3])
                        result = re.sub("(\'|\")","",resu.group())
                        if re.search("("+site+"|^\/)",result):
                                if re.search("(\.js$|\.js\?)",result):
                                        tempLJS.append(result)
                                        print("\033[1;31;40m[javascript]: \033[1;37;40m"+result)
                                else:
                                        tempL.append(result)
                                        print("\033[1;32;40m[url]: \033[1;37;40m"+result)
        except:
                pass
        depth=depth-1
        global llink
        global llinkJs
        llinkJs = llinkJs + tempLJS
        llink = llink + tempL
        #handling depth using recursive calls
        if depth:
                for link in unique_list(tempL):
                        #ignor some files which we have not to look again
                        if re.search("^/|.png|.jpg|.jpeg|.png|.ttf|.woff|.svg|.png|.json|.css|.mp4",link):
                                pass
                        #look for inside javascript file 
                        elif re.search("(\.js$|\.js\?)", link):
                                crawlingInsideJS(link)
                        #else for all other links
                        else:
                                crawling(link, depth)
        else:
                return
#crawling inside javascript files
def crawlingInsideJS(url):
        response = requests.get(url)
        for quot in ("\'",'\"'):
                print(quot)
                links = re.findall("("+quot+")([^"+quot+"]*)("+quot+")",response.text)
                for link in links:
                        try:
                                resu = re.search("^.*?("+quot+"|$)",link[1])
                                result = re.sub("("+quot+")","",resu.group())
                                if re.search("^https://|^http://|^/",result):
                                        if re.search("(\.js$|\.js\?)",result):
                                                llinkJs.append(result+"\n")
                                                print("\033[1;31;40m[javascript]: \033[1;37;40m"+result)
                                        else:
                                                llink.append(result+"\n")
                                                print("\033[1;32;40m[url]: \033[1;37;40m"+result)  
                        except:
                                pass  
#get all url from wayback urls 
def wayBackUrl(site):
        url = "http://web.archive.org/cdx/search/cdx?url="+site+"*&output=json"
        response = requests.get(url)
        urls = re.findall("(http[^\"]*)",response.text)
        for uri in unique_list(urls) :
                if re.search("(\.js$|\.js\?)",uri):
                        print("\033[1;31;40m[javascript]: \033[1;37;40m"+uri)
                elif re.search("^/|.png|.jpg|.jpeg|.png|.ttf|.woff|.svg|.png|.json|.js|.css|.mp4",uri):
                        print("\033[1;36;40m[MultiMedia]: \033[1;37;40m"+uri)
                else:
                        print("\033[1;32;40m[url]: \033[1;37;40m"+uri)
        writeFile(unique_list(urls), site+"/wabackurl.txt")
#multi threading function 
def multiThreading(funcName,dataList,noOfThreads):
        with concurrent.futures.ThreadPoolExecutor(max_workers=noOfThreads) as executor:
                executor.map(funcName,dataList)


site = str(sys.argv[1])
#creating directory with sitename
runCommand("mkdir -p "+site)
#declaring and initilizing variables
tempFile=site+"/temp.txt"
fileNameSubdomain=site+"/subdomains_file.txt"
fileNameLive=site+"/live_subdomains_file.txt"
wordListPath="wordlist/dirbuster-quick.txt"
fileNameCrawling=site+"/crawlinkResult.txt"
fileNameCrawlingJS=site+"/crawlinkResultJS.txt"
FileSubdomainBrute="wordlist/subdomain.txt"
print("\033[1;32;40m----------------------------Looking for Detail information----------------------------\033[1;37;40m")
tergetDetailinfo(site)
print("\033[1;32;40m----------------------------Looking for Subdomains----------------------------\033[1;37;40m")
subdomainEnum(site)
store_to_file(filterFile(site,tempFile),fileNameSubdomain)
print("\033[1;32;40m----------------------------Filtring Live Subdomains----------------------------\033[1;37;40m")
liveDomain=liveSubdomainFinder(readFile(fileNameSubdomain))
writeFile(unique_list(liveDomain),fileNameLive)
print("\033[1;32;40m----------------------------Identifying WAF----------------------------\033[1;37;40m")
tergetWaf(fileNameLive)
print("\033[1;32;40m----------------------------Capturing Screen Shoots----------------------------\033[1;37;40m")
screen_shoot(fileNameLive)
print("\033[1;32;40m----------------------------Looking for Subdomain Takeover----------------------------\033[1;37;40m")
subdomainTakeOver(fileNameSubdomain)
print("\033[1;32;40m----------------------------Looking for DNS Zone Transfer----------------------------\033[1;37;40m")
dnsZoneTransfer(site)
print("\033[1;32;40m----------------------------Looking for CNAME----------------------------\033[1;37;40m")
findCNAME(readFile(fileNameLive))
print("\033[1;32;40m----------------------------Looking for Web Verssions and Technologies----------------------------\033[1;37;40m")
webTechVersion(readFile(fileNameLive))
print("\033[1;32;40m----------------------------Directory Busting USING---------------------------- \033[1;37;40m : "+wordListPath)
dirBusting(readFile(wordListPath),500)
print("\033[1;32;40m----------------------------Crawling----------------------------\033[1;37;40m")
crawling("https://"+site,1)
writeFile(unique_list(llink), fileNameCrawling)
writeFile(unique_list(llinkJs), fileNameCrawlingJS)
print("\033[1;32;40m----------------------------Looking for waybackurl----------------------------\033[1;37;40m")
wayBackUrl(site)
print("\033[1;32;40m----------------------------Subdomain Brute Forcing----------------------------\033[1;37;40m")
multiThreading(subDomainBrute, readFile(FileSubdomainBrute), 500)
print("\033[1;32;40m----------------------------Virtual Host Brute Forcing----------------------------\033[1;37;40m")
multiThreading(virtualHostBruteForceing, readFile(FileSubdomainBrute), 500)
print("\033[1;32;40m----------------------------Finding Ips----------------------------\033[1;37;40m")
writeFile(findIp(readFile(fileNameLive)),site+"/Ips.txt")
print("\033[1;32;40m----------------------------Detecting Cloudeflare Ips----------------------------\033[1;37;40m")
writeFile(unique_list(filterCloudeFlareIp(readFile(site+"/Ips.txt"))), site+"/WCip.txt")
print("\033[1;32;40m----------------------------Looking For Ips from Different Sources----------------------------\033[1;37;40m")
hosts(site)
print("\033[1;32;40m----------------------------Detecting Cloudeflare for new founded Ips----------------------------\033[1;37;40m")
appendToFile(unique_list(filterCloudeFlareIp(readFile(site+"/temp.txt"))), site+"/WCip.txt")
print("\033[1;32;40m----------------------------Detecting ping Status----------------------------\033[1;37;40m")
writeFile(unique_list(check_ping(readFile(site+"/WCip.txt"))), site+"/ip_ping.txt") 
print("\033[1;32;40m----------------------------Looking For Open Ports----------------------------\033[1;37;40m")
rst_scan(readFile(site+"/WCip.txt"))
print("\033[1;32;40m----------------------------Scanning With Nmap----------------------------\033[1;37;40m")
nmap_scan(readFile(site+"/ip.txt"),readFile(site+"/ports.txt"))
