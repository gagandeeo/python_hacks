#!/usr/bin/python
import hashlib
from urllib.request import urlopen
import hashlib
from termcolor import colored
#########  HASHING VALUES ############
def value_md5(hashvalue):
	hashobj1 = hashlib.md5()
	hashobj1.update(hashvalue.encode())
	return(hashobj1.hexdigest())
def value_sha1(hashvalue):
	hashobj2 = hashlib.sha1()
	hashobj2.update(hashvalue.encode())
	return(hashobj2.hexdigest())
def value_shah224(hashvalue):
	hashobj3 = hashlib.sha224()
	hashobj3.update(hashvalue.encode())
	return(hashobj3.hexdigest())
def value_sha256(hashvalue):
	hashobj4 = hashlib.sha256()
	hashobj4.update(hashvalue.encode())
	return(hashobj4.hexdigest())
def value_sha512(hashvalue):
	hashobj5 = hashlib.sha512()
	hashobj5.update(hashvalue.encode())
	return(hashobj5.hexdigest())
######### MATCHING FUNCTIONS ###############
def ditto_url(sha1hash, url):	
	passlist = str(urlopen(url).read(),'utf-8')
	for password in passlist.split('\n'):
		hashguess = hashlib.sha1(bytes(password, 'utf-8')).hexdigest()
		if hashguess == sha1hash:
			return(str(password))
		else:
			print(colored("[-] Password guess " + str(password) + " does not match, trying next....", 'yellow'))
	print("password not in password list")
def ditto_list(sha1hash, list):
	passlist = list
	for password in passlist:
		hashguess = hashlib.sha1(bytes(password, 'utf-8')).hexdigest()
		if hashguess == sha1hash:
			return(str(password))
