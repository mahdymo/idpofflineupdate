###############################################################################################
########################### The purpose of this script is to check the latest IDP update#######
########################### Author mmahdy #####################################################
###############################################################################################

from lxml import etree
import urllib
import os
import paramiko
import getpass


########## The used functions ######################

def idpupdate(device, OS, location, build,currentversion,l):

    manifesturl = "https://signatures.juniper.net/cgi-bin/index.cgi?type=manifest&device=%s&feature=ai&detector=0.0.0&" \
                  "to=latest&os=%s&build=%s" % (device, OS, build)
    urllib.urlretrieve(manifesturl, '%s/manifest.xml' % location)
    signaturetree = etree.parse('%s/manifest.xml' % location)
    element = signaturetree.xpath('/manifest/version')
    for x in element:
        version = x.text

    if version > currentversion:
    	print "Device : "+l
        print "The current version is "+ currentversion + " there's a newer version "+ version + " and it is being downloaded ... "
        SIGDBURL = "https://signatures.juniper.net/xmlupdate/225/SignatureUpdates/%s/SignatureUpdate.xml.gz" %version
        urllib.urlretrieve(SIGDBURL, '%s/SignatureUpdate.xml' % location)

        Files = ['ApplicationGroups', 'ApplicationGroups2', 'ApplicationSchema', 'Applications', 'Applications2',
                 'Detector',
                 'Groups', 'Heuristics', 'Libqmprotocols', 'Platforms']
        signaturetree = etree.parse('%s/SignatureUpdate.xml' % location)
        for x in Files:
            element = signaturetree.xpath('//SignatureUpdate/%s' % x)
            for j in element:
                url = j.text
                filename = l+"-"+url.split('/')[-1]
                urllib.urlretrieve(url, '%s/%s' % (location, filename))

    print "Download completed, unzip files ..."
    loccommand = location+"/"+"*.gz"
    command = "gzip -d %s" % loccommand
    os.system(command)
    return ()

###############Automatically get the device information #######################################
##########This function will get device model, OS, build, idp security package version ########
###############################################################################################


def getdeviceinfo(l,location):
    SRX = paramiko.SSHClient()
    SRX.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    SRX.connect(l, username=unsername, password=password)
    din, dout, derr = SRX.exec_command("show version detail | display xml| no-more")
    din, dout2, derr = SRX.exec_command("show security idp security-package-version | display xml | no-more")
    file2write = open("%s/tmpoutput.xml" %location, 'w')
    file2write.write(dout.read())
    file2write.close()
    signaturetree = etree.parse("%s/tmpoutput.xml" %location)
    prodelement = signaturetree.xpath('//software-information/product-name')
    relelement = signaturetree.xpath('//version-information/release')
    file2write = open("%s/tmpoutput.xml" %location, 'w')
    file2write.write(dout2.read())
    file2write.close()
    signaturetree = etree.parse("%s/tmpoutput.xml" %location)
    verelement = signaturetree.xpath('//security-package-version')
    version.append(verelement[0].text[:verelement[0].text.index('(')])
    device.append(prodelement[0].text)
    OS.append(relelement[0].text[:relelement[0].text.index('X')])
    Build.append(relelement[0].text[relelement[0].text.index('D') + 1:].split('.')[0])
    SRX.close()
    return ()




################# The code #########################
global device
global OS
global Build
global version

device = []
OS = []
Build = []
version = []
unsername = raw_input("Please provide your username: ")
password = getpass.getpass("Please enter the password: ")
location = raw_input('Where to save the files: ')

List_PoP = "You need to define the list of Devices you have in the Network here" ### <<<<<<<<<<< 
for l in List_PoP:
    getdeviceinfo(l,location)

count = 0
for l in List_PoP:

    idpupdate(device[count], OS[count], location, Build[count],version[count],l)
    count +=1


print "Completed, please copy the files to the firewall idp location"
