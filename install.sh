#!/bin/bash -l
#Description: This script check all the necessary tools(rustscan, aquatone, subjack, eyewitness, subfinder, chaos, assetfinder, findomain-linux, amass, requests, psutil, builtwith, Wappalyzer, futures, censys) and python libraries, if not available then install these tools which are required to run Targetinfo.py 
apt update                    
#installing tools using apt
apt install -y python3 golang wafw00f python3-pip python-dnspython python-argparse host wget unzip sudo chromium-browser git nmap inetutils-ping whois
#declaring variable for shell
echo 'export GOROOT=/usr/lib/go' >> ~/.bash_profile
echo 'export GOPATH=$HOME/go'    >> ~/.bash_profile            
echo 'export PATH=$GOPATH/bin:$GOROOT/bin:$PATH' >> ~/.bash_profile    
echo 'export PATH=$PATH:$HOME/go/bin' >> ~/.bash_profile    
source ~/.bash_profile
#declaring go path for installer.sh
export PATH=$PATH:$HOME/go/bin
#TheHarvester for Email and employees info
mkdir -p ~/tools
cd ~/tools
#function to check avaliability of tool
function checkToolAvalibility(){
    if ! command -v $1 &> /dev/null
    then
        return 0
    else
        return 1
    fi
}
if checkToolAvalibility theHarvester;then
    git clone https://github.com/laramies/theHarvester
    cd theHarvester
    pip3 install -r requirements.txt
    python3 setup.py build
    python3 setup.py install
    cd ..
fi
if checkToolAvalibility sublist3r;then
#Sublist3r for Subdomains
    echo "[+] Installing Sublist3r"
    git clone https://github.com/aboul3la/Sublist3r.git
    cd Sublist3r*
    pip3 install -r requirements.txt
    python3 setup.py build
    python3 setup.py install
fi
cd ~/tools/
pip3 install requests
pip3 install dnspython
pip3 install argparse
echo "[+] Done"
if checkToolAvalibility amass; then
#Amass for Subdomains
    echo "[+] Installing amass."
    wget  https://github.com/OWASP/Amass/releases/download/v3.12.3/amass_linux_amd64.zip
    unzip amass_linux_amd64.zip
    mv amass_linux_amd64/amass /usr/bin
    echo "[+] Done"
fi
if checkToolAvalibility findomain-linux;then
#findomain-linux for subdomains
    echo "[+] Installing findSubdomains."
    wget https://github.com/Edu4rdSHL/findomain/releases/latest/download/findomain-linux
    chmod +x findomain-linux
    mv findomain-linux /usr/bin
    echo "[+] Done."
fi
if checkToolAvalibility assetfinder;then
#assetfinder for subdomains
    echo "[+] Installing assetfinder."
    go get -u github.com/tomnomnom/assetfinder
    echo "[+] Done."
fi
if checkToolAvalibility chaos;then
#chaos for subdomains
    echo "[+] Installing chaos."
    GO111MODULE=on go get  github.com/projectdiscovery/chaos-client/cmd/chaos
    echo "[+] Done."
fi
if checkToolAvalibility subfinder;then
#for subdomains
    echo "[+] Installing subfinder."
    GO111MODULE=on go get -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder
    echo "[+] Done."
fi
if checkToolAvalibility eyewitness;then
#for screen shoot of urls
    echo "[+] Installing eyewitness."
    git clone https://github.com/FortyNorthSecurity/EyeWitness.git
    echo "[+] Done."
fi
if checkToolAvalibility subjack;then
#for subdomain takeover
    echo "[+] Installing subjack."
    go get github.com/haccer/subjack
    echo "[+] Done."
fi
if checkToolAvalibility aquatone;then
#for screen shoots of url
    echo "[+] Installing aquatone."
    wget https://github.com/michenriksen/aquatone/releases/download/v1.7.0/aquatone_linux_amd64_1.7.0.zip
    unzip aquatone_linux_amd64_1.7.0.zip
    mv aquatone /usr/bin/
fi
#python pakages
    echo "[+] Installing python packages."
    pip3 install requests psutil builtwith Wappalyzer futures censys
    pip3 install python-wappalyzer
    echo "[+] Done."
#rustscan for open ports
if checkToolAvalibility rustscan;then
    echo "[+] Installing rustscan."
    wget https://github.com/RustScan/RustScan/releases/download/2.0.1/rustscan_2.0.1_amd64.deb
    dpkg -i rustscan_2.0.1_amd64.deb
    echo "[+] Done."
fi
