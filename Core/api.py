import requests,re

class hcat:
 def nitrxgen(self,HASH):
    response = requests.get('http://www.nitrxgen.net/md5db/' + HASH).text
    if response:
        return response
    else:
        return False

 def hashtoolkit(self,HASH):
     response = requests.get("http://hashtoolkit.com/reverse-hash?hash=" + HASH).content
     try:
        cracked = re.findall("<span title=\"decrypted (md5|sha1|sha224|sha256|sha384|sha512) hash\">(.*)</span>", response)
	return cracked[0][1]
     except Exception:
	return False

 def leakz(self,HASH):
    response = requests.get('https://lea.kz/api/hash/' + HASH)
    if response:
        return response.json()['password']
    else:
        return False

 def md5decrypt(self,HASH):
	if len(HASH) ==32:
		hashType = 'md5'
	elif len(HASH) == 40:
		hashType = 'sha1'
	elif len(HASH) == 56:
		return False
	elif len(HASH) ==64:
		hashType = 'sha256'
	elif len(HASH) == 96:
		hashType = 'sha384'
	elif len(HASH) ==128:
		hashType = 'sha512'

	if hashType =='md5':
		response = requests.get('http://md5decrypt.net/Api/api.php?hash={}&hash_type={}&email=deanna_abshire@proxymail.eu&code=1152464b80a61728'.format(HASH, hashType)).text
		if len(response) != 0:
			return response
		else:
		  response = requests.get('http://md5decrypt.net/Api/api.php?hash={}&hash_type={}&email=deanna_abshire@proxymail.eu&code=1152464b80a61728'.format(HASH, 'md4')).text
		  if len(response) !=0:
			return response
		  else:
		     return False
        else:
           response = requests.get('http://md5decrypt.net/Api/api.php?hash={}&hash_type={}&email=deanna_abshire@proxymail.eu&code=1152464b80a61728'.format(HASH, hashType)).text
	   if len(response) !=0:
		return response
	   else:
		return False

hcat = hcat()

