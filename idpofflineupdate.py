###############################################################################################
########################### The purpose of this script is to check the latest IDP update#######
########################### Author mmahdy #####################################################
###############################################################################################
from lxml import etree
import urllib
import os
from ncclient import manager
from ncclient.xml_ import *
import getpass
import sys

#####################################################################
########## Grep Elements ############################################
#####################################################################

def sysarguments():
        if sys.argv[1] == "-h": 
                print "The correct use of the function is python idpofflineupdate.py -u <username> -o <outputfolder> -i 'file contains nodes'"
                print "-u : Username \n-o : The output folder \n-i : The node/nodes name or IP \n"
                sys.exit()
        for arg in sys.argv[1:]:
                if arg == "-u":
                        unameindex = sys.argv[1:].index(arg)+2
                        uname = sys.argv[unameindex]
                        username.append(uname)
                if arg == "-i":
                        nodeipindex = sys.argv[1:].index(arg)+2
                        nodeipfile = sys.argv[nodeipindex]
                        f = open(nodeipfile,"r")
                        for line in f:
                        	List_IPs.append(line.strip())                        
                if arg == "-o":
                        locaindex = sys.argv[1:].index(arg)+2
                        loc = sys.argv[locaindex]
                        location.append(loc)
                if arg == "-h":
			print "-u : Username \n-o : The output folder \n-i : The node/nodes name or IP \n"
			sys.exit(1)

        return()

########## The used functions ######################

def idpupdate(device, OS, location, build,currentversion,l):
	mk = "mkdir -p /var/tmp/IDPFiles/%s"%l
	os.system(mk)
	manifesturl = "https://signatures.juniper.net/cgi-bin/index.cgi?device=%s&feature=idp&detector=12.6.140170603&from=&to=latest&os=%s&build=%s&type=update" % (device, OS, build)
	urllib.urlretrieve(manifesturl, '/var/tmp/IDPFiles/%s/SignatureUpdate.xml.gz' %l)
	quickcommand="gzip -f -d /var/tmp/IDPFiles/%s/SignatureUpdate.xml.gz"%l
	os.system(quickcommand)
	signaturetree = etree.parse('/var/tmp/IDPFiles/%s/SignatureUpdate.xml' %l)
	element = signaturetree.xpath('/SignatureUpdate/UpdateNumber')
	for x in element:
		version = x.text
	version_List.append(version)
	#SIGDBURL = "https://signatures.juniper.net/xmlupdate/225/SignatureUpdates/%s/SignatureUpdate.xml.gz" %version
	#urllib.urlretrieve(SIGDBURL, '/var/tmp/IDPFiles/%s/SignatureUpdate.xml.gz' %l)
	#os.system(quickcommand)
	Files = ['ApplicationGroups', 'ApplicationGroups2', 'ApplicationSchema', 'Applications', 'Applications2','Detector','Groups', 'Heuristics', 'Libqmprotocols', 'Platforms','Templates']
	signaturetree = etree.parse('/var/tmp/IDPFiles/%s/SignatureUpdate.xml' %l)
	for x in Files:
		element2 = signaturetree.xpath('/SignatureUpdate/%s' % x)
        	for j in element2:
        		url = j.text
        		filename = url.split('/')[-1]
        		urllib.urlretrieve(url, '/var/tmp/IDPFiles/%s/%s' % (l, filename))
	loccommand = "/var/tmp/IDPFiles"+"/"+l+"/"+"*.gz"
	command = "gzip -f -d %s" % loccommand
	os.system(command)
	return ()

###############Automatically get the device information #######################################
##########This function will get device model, OS, build, idp security package version ########
###############################################################################################


def getdeviceinfo(l,location,password):
	conn =  manager.connect(host=l, port=22, username=username, password=password,hostkey_verify=False, device_params={'name':'junos'})
	c = new_ele('get-software-information')
	c2 = new_ele('get-idp-security-package-information')
	result = conn.rpc(c)
	result2 = conn.rpc(c2)	
	prodelement = result.xpath('//software-information/product-name')[0].text
	relelement = result.xpath('//software-information/package-information/comment')[0].text
	verelement = result2.xpath('//security-package-version')[0].text
	Currentversion_List.append(verelement[:verelement.index('(')])
	device.append(prodelement)
	OS.append(relelement[relelement.index('[')+1:relelement.index('X')])
	Build.append(relelement[relelement.index('D') + 1:relelement.index(']')])
	return ()

def movefiles_to_firewalls(username,pw,List_IPs):
	port = 22
	CPFILES = ["SignatureUpdate.xml","application_groups.xml","application_groups2.xml","applications.xsd","applications.xml","applications2.xml","libidp-detector.so.tgz.v","groups.xml","heuristics.bin","libqmprotocols.tgz","platforms.xml","templates.xml"]
	for l in List_IPs:
		transport = paramiko.Transport((l, port))
		# Auth
		transport.connect(username = username, password = pw)
		# Go!
		SFTP = paramiko.SFTPClient.from_transport(transport)
		
		# Upload
		try:
			SFTP.rmdir('/var/tmp/IDP')
		except:
			try:
				SFTP.mkdir('/var/tmp/IDP')
			except:
				SFTP.chdir('/var/tmp/IDP')
		for file in CPFILES:
			remotepath = '/var/tmp/IDP/%s'%file
			localpath = '/var/tmp/IDPFiles/%s/%s'%(l,file)
			SFTP.put(localpath, remotepath,callback=None, confirm=True)
		SFTP.close()
		transport.close()
	return ()



################# The code #########################
global device
global OS
global Build
global version
global unsername
global List_IPs
global Currentversion_List
global inputfile
global location
global version_List

location = []
inputfile = []
List_IPs = []
device = []
OS = []
Build = []
version = []
Currentversion_List = []
username = []
version_List = []

if len(sys.argv) > 1:
	sysarguments()
else:
	print "-u : Username \n-o : The output folder \n-i : The node/nodes name or IP \n"
	sys.exit(1)

password = getpass.getpass("Please enter the password: ")

for l in List_IPs:
	getdeviceinfo(l,location[0],password)

count = 0
for l in List_IPs:
    idpupdate(device[count], OS[count], location[0], Build[count],Currentversion_List[count],l)
    count +=1

movefiles_to_firewalls(username,password,List_IPs)

print "Completed, Files are moved to the firewall nodes"
