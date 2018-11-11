#!/usr/bin/python


#--- IMPORT LIB AND MODULES ---#
#------------------------------#
try:
   import hashlib,optparse,re,socket
   from time import sleep
   from os import system
   from copy import copy
   system("")
except ImportError:
	print("\033[91m[!]\033[32m:Some Modules is Missing In Your\033[m [\033[96mPYTHON\033[m].\n\033[96m[*]\033[91m:\033[32mPlease Update Your Python or redownload ")
	exit(1)
#------------------------------#

#------------------------------------------ From Core Tool Folder -----------------------------------------#
													   #
try:													   #
   from Core.banner import banner,colors,cor								   #
   from Core.examples import examples									   #
except ImportError:													   #
	print(cor[3]+"\n[!]:"+cor[5]+"The ["+cor[4]+" Core"+cor[5]+" ]"+cor[3]+"Tool Folder Is Missing!!") #
	exit(1)												   #
############################################################################################################

#----------------------== VERSION ==-----------------------#
							   #
ver = cor[5]+"\nTool Version: [ "+cor[2]+"2.5"+cor[5]+" ]" #
							   #
#----------------------------------------------------------#


##################################### ERROR IN INPUT HASH #####################################
											      #
def errorhash():									      #
     print(cor[4]+"\n[x]:ERROR"+cor[2]+":"+cor[3]+"Please Enter Any Hash From This Hashes:")  #
     print(cor[2]+"""--------------------------------------------->MD5
--------------------------------------------->SHA1
--------------------------------------------->SHA224
--------------------------------------------->SHA256
--------------------------------------------->SHA384
--------------------------------------------->SHA512 """)										      #
     pass		         							      #
###############################################################################################

#----------------------------------- DefaultBanner -----------------------------------#

defaultBanner = colors + """______  _____________________  __________      ________
___  / / /__    |_  ___/__  / / /_  ____/_____ ___  __/
__  /_/ /__  /| |____ \__  /_/ /_  /    _  __ `/_  /   
_  __  / _  ___ |___/ /_  __  / / /___  / /_/ /_  /    
/_/ /_/  /_/  |_/____/ /_/ /_/  \____/  \__,_/ /_/     
                                                 V[2.5]
"""
#-------------------------------------------------------------------------------------#

#@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@ MAKE OPTIONS TOOL @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@

parse = optparse.OptionParser(defaultBanner +cor[5]+ """Usage: python ./HASHCat.py [OPTIONS]
 _________________________________________________________________________________________________________
|           OPTIONS:			                   Description:					  |
+=========================================================================================================+
    -H <Multi Hash> -W <Wordlist>  |  Brute Force Attack On HASHES[MD5,SHA1,SHA224,SHA256,SHA384,SHA512]  |
				   +									  +
    -H <Multi Hash> --ON	   |  Online Cracking Hash Without Wordlist				  |
				   +									  +
    -H <HashName> -T <Set Text>    |  Encode Your Text To HASHES[MD5,SHA1,SHA224,SHA256,SHA384,SHA512]	  |
				   +									  +
    -H <HashName> -F <File Path>   |  Check File HashSum With Hashes[MD5,SHA1,SHA224,SHA256,SHA384,SHA512]|
                                   +                                                                      +
    -O --output <File Name>        |  Save The Result IN Output File.                                     |
==========================================================================================================+
    -v --version                   |  SHOW TOOL VERSION  ||
				   +			 ++
    -e --examples                  |  SHOW TOOL EXAMPLES ||
===========================================================
""",version=ver)

#@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@


def main():
	parse.add_option("-H","--HASH",dest="hash",type="string",
								help="\nHASH please !\n")
	parse.add_option("-W","-w",'--WORDLIST',"--wordlist",dest="wordlist",type="string",
								help="\nWordlist File Please!\n")
        parse.add_option("-T","-t","--text",'--TEXT',dest="dtext",type="string",
							        help="Enter Some Text To Encodeing To Your Hash\n")
	parse.add_option("--on",'--ON','--On','--online','--ONLINE',action="store_true",dest="ONC",default=False)

        parse.add_option('-f','-F','--file','--FILE',dest='Cfile',type='string')

	parse.add_option("-O","-o","--output",'--OUTPUT',dest="outfile",type="string",
								help="\nFile Name Please !\n")
	parse.add_option("-v","-V",action="store_true",dest="ShowVERSION",default=False,
								help="\nSHOW TOOL VERSION AND EXIT :)\n")
	parse.add_option("-e","-E","--examples",'--EXAMPLES',action="store_true",dest="ShowEXAMPLES",default=False,
								help="\nSHOW TOOL EXAMPLES\n")

	(options,args) = parse.parse_args()

#=-=-=-=-=-=-=-=-=-=-=-=-=- START =-=-=-=-=-=-=-=-=-=-=-=-=-:)

	if options.ShowVERSION:
		print(ver)
		exit(1)

	elif options.ShowEXAMPLES:
                system("cls||clear")
		examples()
		exit(1)

	def checkoutfile():
	  try:
	     if options.outfile !=None:
			       return True
	  except:
		pass
	  return False

	check = checkoutfile()

	if options.hash !=None and options.wordlist !=None:
		hash = options.hash
		wl = options.wordlist
		try:
		   file = open(wl, "r")
		except IOError:
		      print(cor[3]+"\n[!] Error:"+cor[5]+" No Such File[ "+cor[4]+wl+cor[5]+" ]"+cor[5]+" !!!")
		      exit(1)
		if len(hash) == 32: #MD5
			name = "MD5"
		elif len(hash) == 40: #SHA1
			name= "SHA1"
		elif len(hash) == 56: #SHA224
			name= "SHA224"
		elif len(hash) == 64: #SHA256
			name= "SHA256"
		elif len(hash) == 96: #SHA384
			name= "SHA384"
		elif len(hash) == 128: #SHA512
			name= "SHA512"
		else:
		     errorhash()
		     exit(1)
		loop = 1
		try:
                   system("cls||clear")
                   banner()
		   print(colors + "\n[+>]<====================> CONFIG <====================>[<+]\n"+cor[5])
		   print("\033[1;32m[\033[1;37m*\033[1;32m]\033[1;37m HASH NAME    :> [ \033[1;32m"+colors+name)
		   print("\033[1;32m[\033[1;37m+\033[1;32m]\033[1;37m HASH         :> [ \033[1;32m"+hash[:30]+"\033[1;33m-...")
		   print("\033[1;32m[\033[1;37m>\033[1;32m]\033[1;37m Wordlist     :> [ \033[1;32m"+wl)
		   sleep(1.2)
		   print(cor[2]+"\n[*]"+cor[5]+" Brute Forcing: "+cor[2]+"Enable"+cor[5]+"...\n")
		   sleep(1.7)
		   lines = 0
		   for passwd in file:
                           if not passwd.strip(): continue
                           passwd = passwd.strip()
			   if len(hash) == 32: #MD5
			      hashcat = hashlib.md5(passwd).hexdigest()
			   elif len(hash) == 40: #SHA1
		              hashcat = hashlib.sha1(passwd).hexdigest()
		           elif len(hash) == 56: #SHA224
		              hashcat = hashlib.sha224(passwd).hexdigest()
		           elif len(hash) == 64: #SHA256
		              hashcat = hashlib.sha256(passwd).hexdigest()
		           elif len(hash) == 96: #SHA384
		              hashcat = hashlib.sha384(passwd).hexdigest()
		           elif len(hash) == 128: #SHA512
		              hashcat = hashlib.sha512(passwd).hexdigest()
		           else:
				errorhash()
				break
# START BRUTE-FORCE ATTACK:...
			   if hash == hashcat:
				if check == True:
					 outfile = options.outfile
					 file = open(outfile, "w")
					 file.write("\n[+]:HASH CRACK!:\n[*]:INFO:\n----------\n[*]:HASH Name:[ "+name+" ]\n[+]:HASH:[ "+hash+" ]\n\n[#>]:HASH CAT:[ "+passwd.strip()+" ]\n")
					 print(cor[1]+"\n[+]"+cor[4]+":"+cor[2]+"HASH CRACKER: AND The INFO Save In [ "+cor[4]+outfile+cor[2]+" ] output file :)\n\033[1;32m[\033[1;37m*\033[1;32m] \033[1;37mCheck Out\033[1;32m :)")
					 file.close()
					 break
				else:
                                        print(cor[2]+"[+]"+cor[5]+" Trying Password"+cor[5]+"["+cor[2]+str(loop)+cor[5]+"]  : "+cor[2]+str(passwd)+cor[5]+" ===>"+cor[2]+" YES")
					print(cor[1]+"\n[+]"+cor[4]+":"+cor[2]+"HASH CRACK!:\n"+cor[1]+"[*]"+cor[4]+":"+cor[2]+"INFO:"+cor[5]+"\n----------"+cor[1]+"\n[*]"+cor[4]+":"+cor[2]+"HASH Name:[ "+cor[4]+name+cor[2]+" ] "+cor[1]+"\n[+]"+cor[4]+":"+cor[2]+"HASH:[ "+cor[4]+hash+cor[2]+" ]"+cor[1]+"\n\n[#>]"+cor[4]+":"+cor[2]+"HASH CAT:[ "+cor[4]+passwd.strip()+cor[2]+" ]\n")
					break
			   else:
			       print(cor[3]+"[-] Trying Password"+cor[5]+"["+cor[4]+str(loop)+cor[5]+"]  : "+cor[0]+str(passwd)+cor[3]+" ===>"+cor[4]+" NO")
			       loop +=1
		           lines+=1
		   else:
			print(cor[4]+"\n[-]:"+cor[3]+"I WAS TRY ["+cor[4]+str(lines)+cor[3]+"] "+cor[3]+"Passowrd From [ "+cor[4]+wl+cor[3]+" ] Wordlist")
			print(cor[4]+"[x!]"+cor[3]+":PASSWORD NOT FOUND IN:[ "+cor[4]+wl+cor[3]+" ] Wordlist\n"+cor[2]+"[*]"+cor[4]+":"+cor[3]+"Try Online Cracker Options Or try Other Wordlist :) ")
			exit(1)

		except KeyboardInterrupt:
			       print(cor[3]+"\n[!]:"+cor[4]+"Stoping Attack.....")
			       sleep(2)
			       print("Bye :)")
			       exit(1)

	elif options.hash !=None and options.dtext !=None:
		HASH = options.hash
		text = options.dtext
		HASHES = ["md5","MD5","sha1","SHA1","sha224","SHA224","sha256","SHA256","sha384","SHA384","sha512","SHA512"]
		if HASH in HASHES:
		   sleep(0.10)
		   banner()
                   print(colors + "\n[+>]<====================> CONFIG <====================>[<+]\n"+cor[5])
                   sleep(0.10)
                   print("[*]:HASH NAME    : "+colors+HASH+cor[5])
                   sleep(0.10)
		   print("[*]:Text         : "+colors+text+cor[5])
                   sleep(0.10)
		   print(cor[3]+"\n[*]\033[1;33m Hashing....["+cor[4]+text+"\033[1;33m]\n")
		   sleep(2.1)
		   if HASH == "md5" or HASH == "MD5":
			  hashte = hashlib.md5(text).hexdigest()
		   elif HASH == "sha1" or HASH == "SHA1":
                          hashte = hashlib.sha1(text).hexdigest()
                   elif HASH == "sha224" or HASH == "SHA224":
                          hashte = hashlib.sha224(text).hexdigest()
                   elif HASH == "sha256" or HASH == "SHA256":
                          hashte = hashlib.sha256(text).hexdigest()
                   elif HASH == "sha384" or HASH == "SHA384":
                          hashte = hashlib.sha384(text).hexdigest()
                   elif HASH == "sha512" or HASH == "SHA512":
                          hashte = hashlib.sha512(text).hexdigest()
		   if check == True:
			outfile = options.outfile
			file = open(outfile, "w")
			file.write("\n[*] ======== [{}]HASH Result========[*]\n |\n[T] Your Plain Text    :> [ {} \n[H] Hash Name Type     :> [ {} \n[E] {}-HASH.[ {} ] :> [ {} \n |\n[*]===================================[*]\n".format(HASH.upper(),text,copy(HASH.upper()),copy(HASH.upper()),copy(text),hashte))
			print("\n\033[1;32m[\033[1;37m*\033[1;32m] \033[1;37mYour Hashing Result Is Saved In :[\033[1;32m {}\033[1;37m ]\033[1;33m Output File. \n\033[1;32m[\033[1;37m*\033[1;32m]\033[1;37m Check Out \033[1;32m:)".format(outfile))
			file.close()
		   else:
			print("\033[1;33m[T]\033[1;35m Plain TEXT\033[1;32m=[\033[1;34m {}\033[1;32m ] \033[1;33m\n[H] \033[1;36m{}\033[1;32m-hash\033[1;35m===[ \033[1;31m{}\033[1;35m ]\n".format(text,HASH.upper(),hashte))
		else:
		   errorhash()
		   exit(1)

	elif options.hash !=None and options.ONC:
              try:
                import requests
              except ImportError:
	           print("\n\033[1;31m[\033[1;33m!\033[1;31m]\033[1;33m Error: [\033[1;32m Requests \033[1;37mLibrary\033[1;33m ] Is Not Exist \033[1;31m!!!")
	           print("\033[1;32m[\033[1;37m*\033[1;32m]\033[1;37m Please Install It Using This \033[1;33mCommand: \033[1;37mpip install requests")
		   exit(1)
              try:
                import json
              except ImportError:
	           print("\n\033[1;31m[\033[1;33m!\033[1;31m]\033[1;33m Error: [\033[1;32m Json \033[1;37mLibrary\033[1;33m ] Is Not Exist \033[1;31m!!!")
	           print("\033[1;32m[\033[1;37m*\033[1;32m]\033[1;37m Please Install It Using This \033[1;33mCommand: \033[1;37mpip install simplejson")
		   exit(1)
	      try:
		 from Core.api import ONCH as onc
	      except ImportError:
		 print("\n\033[1;31m[\033[1;33m!\033[1;31m]\033[1;33m Error: [\033[1;37m Core/api.py \033[1;33m] File Is Missing \033[1;31m !!!")
		 exit(1)
	      stop = 0
	      try:
		H = options.hash
		HASHES = [32,40,56,64,96,128]
		if len(H) not in HASHES:
			errorhash()
			stop+=1
		def check():
		  try:
		    ip = socket.gethostbyname('google.com')
		    con = socket.create_connection((ip, 80), 2)
		    return True
		  except:
			pass
		  return False
		if check() !=True:
			stop +=1
			print("\n\033[1;31m[\033[1;33m!\033[1;31m]\033[1;33m Error: Please Check Your Internet Connection \033[1;31m!!!")
			exit(1)
		url="http://hashtoolkit.com/reverse-hash?hash="+H
		con = requests.get(url)
		content = con.content
		cracked = re.findall("<span title=\"decrypted (md5|sha1|sha224|sha256|sha384|sha512) hash\">(.*)</span>", content)
		hashname=cracked[0][0]
		banner()
		print("\033[1;37m.::: \033[1;33mOnline Cracking Result \033[1;37m:::.")
		print("\n\033[1;37m[\033[1;32m>\033[1;37m] HASH     :> [\033[1;32m "+H[:30]+"\033[1;33m-...")
		print("\033[1;37m[\033[1;32m+\033[1;37m] HashName :> [\033[1;32m "+hashname.upper())
		print("\n\033[1;37m[\033[1;32m~\033[1;37m] HASH CAT :> [\033[1;32m "+cracked[0][1])
	      except:
		if stop >0:
		   exit(1)
                H = options.hash
                def check():
                  try:
                    ip = socket.gethostbyname('google.com')
                    con = socket.create_connection((ip, 80), 2)
                    return True
                  except:
                        pass
                  return False
                if check() !=True:
                        print("\n\033[1;31m[\033[1;33m!\033[1;31m]\033[1;33m Error: Please Check Your Internet Connection \033[1;31m!!!")
                        exit(1)
		if len(H) ==HASHES[0]:
			name = "MD5"
		elif len(H) ==HASHES[1]:
			name = "SHA1"
                elif len(H) ==HASHES[2]:
                        name = "SHA224"
                elif len(H) ==HASHES[3]:
                        name = "SHA256"
                elif len(H) ==HASHES[4]:
                        name = "SHA384"
                elif len(H) ==HASHES[5]:
                        name = "SHA512"
		banner()
                print("\033[1;37m .::: \033[1;33mOnline Cracking Result \033[1;37m:::.")
                print("\n\033[1;37m[\033[1;32m>\033[1;37m] HASH     :> [\033[1;32m "+H[:30]+"\033[1;33m-...")
                print("\033[1;37m[\033[1;32m+\033[1;37m] HashName :> [\033[1;32m "+name.upper())
		try:
                 print("\n\033[1;37m[\033[1;32m~\033[1;37m] HASH CAT :> [\033[1;32m "+onc(H))
		except:
		  print("\n\033[1;31m[\033[1;33m!\033[1;31m]\033[1;33m Error: Cracking Failed \033[1;31m !!!\n\033[1;37m[\033[1;32m*\033[1;37m] Try Brute Force Attack With Wordlist :)")

	elif options.hash !=None and options.Cfile !=None:   
             hashname = options.hash
             fname = options.Cfile
             def HASHme(fname,hashname):
               try:
                  test = open(fname, "r")
               except:
                 print("\n"+cor[0]+"["+cor[2]+"!"+cor[0]+"][ERROR] "+cor[2]+"! File["+cor[1]+fname+cor[2]+"] Is Not Found "+cor[0]+"!!!")
                 print(cor[0]+"["+cor[2]+"!"+cor[0]+"]"+cor[1]+" Please Check Your File Location "+cor[4]+"And Try Again "+cor[1]+":)")
                 exit(1)
	       hashs = ["md5","MD5","sha1","SHA1","sha224","SHA224","sha256","SHA256","sha384","SHA384","sha512","SHA512"]
               if hashname in hashs:
                  try:
                     if hashname =="md5" or hashname == "MD5":
                         hash_md5 = hashlib.md5()
                         with open(fname, "rb") as f:
                          for chunk in iter(lambda: f.read(4096), b""):
                             hash_md5.update(chunk)
                         return hash_md5.hexdigest()
                     elif hashname =="sha1" or hashname == "SHA1":
                         hash_sha1 = hashlib.sha1()
                         with open(fname, "rb") as f:
                          for chunk in iter(lambda: f.read(4096), b""):
                              hash_sha1.update(chunk)
                         return hash_sha1.hexdigest()
                     elif hashname =="sha224" or hashname == "SHA224":
                         hash_sha224 = hashlib.sha224()
                         with open(fname, "rb") as f:
                            for chunk in iter(lambda: f.read(4096), b""):
                               hash_sha224.update(chunk)
                         return hash_sha224.hexdigest()
		     elif hashname =="sha256" or hashname == "SHA256":
		      hash_sha256 = hashlib.sha256()
		      with open(fname, "rb") as f:
			 for chunk in iter(lambda: f.read(4096), b""):
			     hash_sha256.update(chunk)
		      return hash_sha256.hexdigest()
		     elif hashname =="sha384" or hashname == "SHA384":
		      hash_sha384 = hashlib.sha384()
		      with open(fname, "rb") as f:
			for chunk in iter(lambda: f.read(4096), b""):
			    hash_sha384.update(chunk)
		      return hash_sha384.hexdigest()
		     elif hashname =="sha512" or hashname == "SHA512":
		      hash_sha512 = hashlib.sha512()
		      with open(fname, "rb") as f:
			for chunk in iter(lambda: f.read(4096), b""):
			    hash_sha512.update(chunk)
		      return hash_sha512.hexdigest()
                  except:
                     print("\n"+cor[2]+"["+cor[0]+"!"+cor[2]+"] Something Went Wrong "+cor[0]+"!!!")
                     exit(1)
               else:
                   errorhash()
                   exit(1)

             banner()
             sleep(0.10)
             print("\n"+cor[2]+"["+cor[0]+"*"+cor[2]+"]"+cor[4]+" Hash: "+cor[1]+hashname)
             sleep(0.10)
             print(cor[2]+"["+cor[0]+"*"+cor[2]+"]"+cor[4]+" File: "+cor[1]+fname)
             sleep(0.10)
             print("\n"+cor[1]+"["+cor[2]+"*"+cor[1]+"] "+cor[1]+hashname+cor[0]+"sum: "+cor[5]+HASHme(fname,hashname))

	else:
		print(parse.usage)
		exit(1)

if __name__=='__main__':
	main()

##############################################################
#####################                #########################
#####################   END OF TOOL  #########################
#####################                #########################
##############################################################
#This Tool by Oseid Aldary
#Have a nice day :)
#GoodBye
