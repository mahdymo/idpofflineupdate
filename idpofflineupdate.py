###############################################################################################
########################### The purpose of this script is to check the latest IDP update#######
###############################################################################################

from lxml import etree
import urllib
import os


def idpupdate(device, OS, location, build):
    manifesturl = "https://signatures.juniper.net/cgi-bin/index.cgi?type=manifest&device=%s&feature=ai&detector=0.0.0&" \
                  "to=latest&os=%s&build=%s" % (device, OS, build)

    urllib.urlretrieve(manifesturl, '%s/manifest.xml' % location)

    ##### Remove tags##########
    tree = etree.parse('%s/manifest.xml' % location)
    notags = etree.tostring(tree, encoding='utf8', method='text')
    DB_List = notags.split()
    DB_List = map(lambda s: s.strip(), DB_List)

    ####Signature update get the url#######

    signatures = 'SignatureUpdate.xml.gz'
    index = DB_List.index(signatures)
    urlindex = index + 5
    SIGDBURL = DB_List[urlindex]
    urllib.urlretrieve(SIGDBURL, '%s/SignatureUpdate.xml' % location)

    ######Check the IDP Version############
    signaturetree = etree.parse('%s/SignatureUpdate.xml' % location)
    element = signaturetree.xpath('//SignatureUpdate/UpdateNumber')
    for i in element:
        version = i.text

    Cont_Update = raw_input("The available version is %s do you wish to proceed (y or n): " % version)
    Cont_Update = Cont_Update.upper()

    Files = ['ApplicationGroups', 'ApplicationGroups2', 'ApplicationSchema', 'Applications', 'Applications2',
             'Detector',
             'Groups', 'Heuristics', 'Libqmprotocols', 'Platforms']

    if Cont_Update == 'Y':
        for x in Files:
            element = signaturetree.xpath('//SignatureUpdate/%s' % x)
            for j in element:
                url = j.text
                filename = url.split('/')[-1]
                urllib.urlretrieve(url, '%s/%s' % (location, filename))

    print "Download completed, unzip files ..."
    loccommand = location+"/"+"*.gz"
    command = "gzip -d %s" % loccommand

    os.system(command)

    return ()


device = raw_input('Please provide the device model(srx1400, srx5400, srx5800): ')
OS = raw_input('Please provide the current version of the FW(15.1 , 12.3 , etc..): ')
build = raw_input('Please provide the current build of the FW(44, 70 , 80): ')
location = raw_input('Where to save the files: ')
idpupdate(device, OS, location, build)

print "Completed, please copy the files to the firewall idp location"
