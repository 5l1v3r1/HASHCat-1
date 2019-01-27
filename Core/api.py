import requests,re

#Oline Cracking API PYTHON BY OSEID ALDARY :)
class hcat:
 def nitrxgen(self,HASH):
    if len(HASH) !=32: return False
    response = requests.get('http://www.nitrxgen.net/md5db/' + HASH).text
    if response : return str(response)
    else : return False
 def hashtoolkit(self,HASH):
     response = requests.get("http://hashtoolkit.com/reverse-hash?hash=" + HASH).content
     try:
        cracked = re.findall("<span title=\"decrypted (md5|sha1|sha224|sha256|sha384|sha512) hash\">(.*)</span>", response)
	return cracked[0][1]
     except Exception : return False
 def leakz(self,HASH):
    response = requests.get('https://lea.kz/api/hash/' + HASH)
    if response : return str(response.json()['password'])
    else : return False
 def md5decrypt(self,HASH):
	if len(HASH) ==32: hashType = 'md5'
	elif len(HASH) == 40: hashType = 'sha1'
	elif len(HASH) == 56: return False
	elif len(HASH) ==64: hashType = 'sha256'
	elif len(HASH) == 96: hashType = 'sha384'
	elif len(HASH) ==128: hashType = 'sha512'
	if hashType =='md5':
		response = requests.get('http://md5decrypt.net/Api/api.php?hash={}&hash_type={}&email=deanna_abshire@proxymail.eu&code=1152464b80a61728'.format(HASH, hashType)).text
		if len(response) != 0 : return str(response)
		else:
		  response = requests.get('http://md5decrypt.net/Api/api.php?hash={}&hash_type={}&email=deanna_abshire@proxymail.eu&code=1152464b80a61728'.format(HASH, 'md4')).text
		  if len(response) !=0 : return str(response)
		  else : return False
        else:
           response = requests.get('http://md5decrypt.net/Api/api.php?hash={}&hash_type={}&email=deanna_abshire@proxymail.eu&code=1152464b80a61728'.format(HASH, hashType)).text
	   if len(response) !=0 : return str(response)
	   else : return False
 def myaddr(self, HASH):
 	if len(HASH) !=32 : return False
 	data = {'md5': HASH}
 	headers = {'User-Agent':'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/534.24 (KHTML, like Gecko) RockMelt/0.9.58.494 Chrome/11.0.696.71 Safari/534.24'}
 	response = requests.post("http://md5.my-addr.com/md5_decrypt-md5_cracker_online/md5_decoder_tool.php", headers=headers, data=data).text
 	result = re.findall(r"Hashed string</span>:\s(.+?)</div>", response)
 	if result : return str(result[0])
 	else : return False
 def gromweb(self, HASH):
 	if len(HASH) ==32:
            headers = {'User-Agent':'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/534.24 (KHTML, like Gecko) RockMelt/0.9.58.494 Chrome/11.0.696.71 Safari/534.24'}
            params = {'md5': HASH}
            response = requests.get('https://md5.gromweb.com/', headers=headers,params=params).text
            if response.find(u"succesfully reversed") > 0: return str(re.findall(ur'<em class="long-content string">(.*?)</em>', response)[0])
            else:
                return False
 	elif len(HASH)==40:
            response = requests.get('https://sha1.gromweb.com/?hash='+HASH).text
            if response.find("succesfully reversed") > 0 : return str(re.findall(ur'<em class="long-content string">(.*?)</em>', response)[0])
            else : return False
        else : return False
hcat = hcat()
#---End OF API---#
