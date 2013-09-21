import sqlite3
import csv
import os
import re
import subprocess
import hashlib
import urllib
import urllib2
import simplejson
import time

def md5sum(filename):
    md5 = hashlib.md5()
    with open(filename, 'rb') as f:
        for chunk in iter(lambda: f.read(128 * md5.block_size), b''):
            md5.update(chunk)
    return md5.hexdigest()

def multScan(fileDirectory,output):
    if not os.path.exists("/usr/bin/clamscan"):
        print "ClamAV does not seem to be installed on this machine"
        sys.exit()
    print "Running clamAV and Yara on all dumped DLLS, VADS, Processes, and modules."
    #print " output is: " , output
    for x in fileDirectory:
        #scanning all dumpDir with ClamAV	
	#print x
        clamCommand = "clamscan -r --no-summary " + x  + " -l " + output + "/clamAVScan.txt"
        subprocess.call(clamCommand, stdout=open(os.devnull, "w"), stderr=open(os.devnull, "w"), shell=True)

        #now scanning with yara
        yaraCommand = "yara -r /usr/local/etc/capabilities.yara " + x + " >> " + output + "/YaraHits.txt"
        subprocess.call(yaraCommand, shell=True)

def VirusTotalSubmission(filename,output):
    print output
    VTResultsPath = os.path.join(os.path.abspath(output), "VirusTotalResults.txt")
    VTResults = open(VTResultsPath, 'a')
    f = file(filename, "rb")
    for line in f.readlines():
        newline = "\n"
        line = line.rstrip()
        VTResults.write(line)
        VTResults.write(newline)
        hashValue = md5sum(line)
        #print hashValue
        #first check and see if there is any response from uploading the MD5
        url = "https://www.virustotal.com/vtapi/v2/file/report"
        parameters = {"resource": hashValue,
		      "apikey": "<API_KEY>"}
        data = urllib.urlencode(parameters)
        req = urllib2.Request(url, data)
        response = urllib2.urlopen(req)
        json = response.read()
        

        response_dict = simplejson.loads(json)
        toot = response_dict.get("positives")
        #print toot
        if str(toot) == "None":
            errorStatement = "Hash not found in VirusTotal Database... may need to upload\n\n"
            VTResults.write(errorStatement)
            time.sleep(15)
        else:
            Symantec = response_dict.get("scans", {}).get("Symantec", {}).get("result")
            Microsoft = response_dict.get("scans", {}).get("Microsoft", {}).get("result")
            McAfee = response_dict.get("scans", {}).get("McAfee", {}).get("result")
            Kaspersky = response_dict.get("scans", {}).get("Kaspersky", {}).get("result")
            permalink = response_dict.get("permalink", {})

            numberHits = "Number of positive hits: " + str(toot) + "\n"
            link = "Link: " + str(permalink) + "\n"
            mcAfeeStr = "McAfee says its " + str(McAfee) + "\n"
            symantecStr = "Symantec says its " + str(Symantec) + "\n"
            microsoftStr = "Microsoft says its " + str(Microsoft) + '\n'
            kasperskyStr = "Kaspersky says its " + str(Kaspersky) + "\n\n"
            VTResults.write(numberHits)
            VTResults.write(link)
            VTResults.write(mcAfeeStr)
            VTResults.write(symantecStr)
            VTResults.write(microsoftStr)
            VTResults.write(kasperskyStr)

            time.sleep(15)

    VTResults.close()

def TeamCymruUpload(listOfFiles,output):
    CymruList = []
    f = file(listOfFiles, "rb")
    for line in f.readlines():
        newline = "\n"
        line = line.rstrip()
        hashValue = md5sum(line)
        CymruList.append(hashValue)
    CymruList = sorted(set(CymruList))
    CymruList.insert(0, "begin")
    CymruList.append("end")
    

    f = open('/tmp/CymruUpload.txt', 'w')
    for x in CymruList:
        f.write(x)
        f.write('\n')
    f.close()

    filename = "Cymru_results.txt"
    final_output = os.path.join(os.path.abspath(output), filename)
    finalCommand = "netcat " + "hash.cymru.com " + "43 < /tmp/CymruUpload.txt >> " + final_output
    subprocess.call(finalCommand, stdout=open(os.devnull, "w"), shell=True)

    #clean the tmp directory
    os.remove('/tmp/CymruUpload.txt')

def investigationCommands(output, volatilityPath, filename, memProfile, SQLdb):
#if -i switch is enabled
    print "Investigation Enabled!"
    #print "output is..." , output
    command_to_output_dir = [
    		('dlldump', 'DLLDump'),
    		('vaddump', 'VADDump'),
    		('procexedump', 'ProcDump'),
    		('moddump', 'ModDump'),
    		('malfind', 'malfind'),
	]
    #toot = os.path.abspath(output)
    #print toot
    multScan([os.path.join(output, dir) for _, dir in command_to_output_dir],output)

    #This will grep for the word FOUND in the ClamAV file
    #print "Results are saved to " + output + "/clamAVScan.txt"
    f = open('/tmp/avfiles', 'w')
    ClamAVDump = os.path.join(output,"clamAVScan.txt")
    q = subprocess.Popen(("grep", "FOUND", ClamAVDump), stdout=f)
    q.wait()

    #now only return the file names please from that
    HitOnAV = open('/tmp/hitsOnAV.txt', 'w')
    with open('/tmp/avfiles', 'r') as f:
        for line in f.readlines():
            line = line.split(":")[0]
            HitOnAV.write(line)
            HitOnAV.write('\n')

    HitOnAV.close()

    #ok now submit MD5 to VirusTotal
    AVLocation = "/tmp/hitsOnAV.txt"

    #submit to Team Cymru and VirusToal
    print "Submitting ClamAV to Team Cymru"
    TeamCymruUpload(AVLocation,output)

    print "Submitting ClamAV to VirusTotal"
    VirusTotalSubmission(AVLocation,output)

    #OK on to YARA!
    #First we need to split the lines, a space will work here (hopefully)
    yaraHits = os.path.join(output, "YaraHits.txt")
    f = open(yaraHits, 'r')
    w = open('/tmp/yarafiles.txt', 'w')
    for line in f.readlines():
        line = line.partition(' ')[2] #this fixes the space issue observed
        w.write(line)

    w.close()
    f.close()

    #next we need to sort and then run uniq on the files, so we do not deal with repeats
    command1 = "sort /tmp/yarafiles.txt > /tmp/temp"
    subprocess.call(command1, stdout=subprocess.PIPE, shell=True)
    time.sleep(10)

    command2 = "uniq /tmp/temp > /tmp/yaraSorted"
    subprocess.call(command2, stdout=subprocess.PIPE, shell=True)

    #throwing the Yara things to VirusTotal
    print "Submitting Yara to Team Cymru"
    YaraLocation = "/tmp/yaraSorted"

    TeamCymruUpload(YaraLocation,output)

    print "Submitting Yara to VirusTotal"
    VirusTotalSubmission(YaraLocation,output)

    ClamAVParse(output,"clamAVScan.txt", SQLdb)
    CymruParse(output,"Cymru_results.txt", SQLdb)	
    YaraParse(output,"YaraHits.txt", SQLdb)

    #cleanup
    os.remove('/tmp/temp')
    os.remove('/tmp/yaraSorted')
    os.remove('/tmp/hitsOnAV.txt')
    os.remove('/tmp/avfiles')

def ClamAVParse(output,fileLocation,DBName):
	print "Adding ClamAV to Database"
	output = os.path.join(output,fileLocation)

	fileHandle = open(output, "rb")	
	fileList = fileHandle.readlines()

	conn = sqlite3.connect(DBName)
	c = conn.cursor()
	c.execute('''create table clamAVResults (fileName text, InfectionName text)''')

	for line in fileList:
		if 'FOUND' in line:
			line=line.rstrip()
			line = re.sub('FOUND', "", line)
			line = line.replace(' ', '')			
			ClamAVList1 = line.split(":")
			conn.execute("insert into clamAVResults (fileName, InfectionName) values (?,?)", ClamAVList1)

	conn.commit()
	c.close()
	print "ClamAV Results Added to Database!"

def CymruParse(output,fileLocation,DBName):
	output = os.path.join(output,fileLocation)
	#print output

	fileHandle = open(output, "rb")	
	fileList = fileHandle.readlines()

	conn = sqlite3.connect(DBName)
	c = conn.cursor()
	c.execute('''create table teamCymruResults (MD5hash text, timestampUnixEpoch text, detectionPercentage text)''')

	for line in fileList:
		if '#' in line:
			pass
		else:
			line=line.rstrip()			
			CymruList = line.split(" ")
			#print CymruList
			conn.execute("insert into teamCymruResults (MD5hash, timestampUnixEpoch, detectionPercentage) values (?,?,?)", CymruList)

	conn.commit()
	c.close()
	print "Cymru Results Added to Database!"

def YaraParse(output,fileLocation,DBName):

	output = os.path.join(output,fileLocation)
	#print output

	fileHandle = open(output, "rb")	
	fileList = fileHandle.readlines()

	conn = sqlite3.connect(DBName)
	c = conn.cursor()
	c.execute('''create table YaraResults (YaraHit text, file text)''')

	for line in fileList:
		line=line.rstrip()			
		YaraList = line.split(" ",1)
		conn.execute("insert into YaraResults (YaraHit, file) values (?,?)", YaraList)

	conn.commit()
	c.close()
	print "Yara Results Added to Database!"
			
