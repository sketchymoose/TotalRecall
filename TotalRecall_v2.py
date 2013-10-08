#Volatility Script
#By sk3tchymoos3
#Much thanks to Tom Goldsmith, Dani F., and a Canadian guy for the guidance!

import os
import sys
import argparse
import hashlib
import time
import subprocess
import csv
import sqlite3
import basicParse1
import investigationParse
import timelineParse

#<--- Declare variables here --->
volatilityPath = "/home/remnux/svn/trunk/vol.py" 

# <--- BEGIN FUNCTIONS --->

def md5sum(filename):
    md5 = hashlib.md5()
    with open(filename, 'rb') as f:
        for chunk in iter(lambda: f.read(128 * md5.block_size), b''):
            md5.update(chunk)
    return md5.hexdigest()

#<--- END FUNCTIONS --->

parser = argparse.ArgumentParser(description='Grabs information from a memory dump')
parser.add_argument('-d', '--directory', metavar="PATH", help='Directory to save the output of the commands to.',
                    required=True)
parser.add_argument('-f', '--filename', help='The memory dump you wish to analyse.', required=True)
parser.add_argument('-p', '--profile', help='The profile of the memory dump being analysed', required=True)
parser.add_argument('-v', '--volatility', help='The full path to vol.py, default is /home/remux/svn/trunk/vol.py')
parser.add_argument('-i', '--investigation', action="store_true",
                    help='Enable investigation of dumped items with yara and clamav')
parser.add_argument('-t', '--timeline', action="store_true", help="Attempt to pull timeline artefacts")

args = vars(parser.parse_args())

localtime = time.localtime(time.time())
print "Start time :", localtime

#ensure path to vol.py is valid
if args['volatility']:
    volatilityPath = args['volatility']
    if not os.path.exists(volatilityPath):
        print "vol.py does not exist at location, trying default."
        volatilityPath = "/usr/local/bin/vol.py"
        if not os.path.exists(volatilityPath):
            print "vol.py does not exist at default, check path."
            sys.exit()

#ensure the file to be parsed exists!
filename = args['filename']
if not os.path.exists(filename):
    print "File does not exist... try again!"
    sys.exit()

#ensure the directory where the output is going exists, if not, create it
directory = args['directory']
if not os.path.exists(directory):
    os.makedirs(directory)

#grab profile
memProfile = args['profile']

output = os.path.join(directory)
output = os.path.abspath(output)
print "File to be analysed: ", filename
print "[+] Saving to: ", os.path.abspath(output)

#check to see if the DB already exists, we are using the hash of the memoryDump as the DB name
hash=md5sum(filename)
print "MD5 of the memory dump is " + hash +". Checking to see if it already exists..."
#I am putting the DB into a different directory, this way you can have multiple DB files in one location without mixing up the text file outputs!
SQLdb= os.path.join("/home/remnux/", hash)


#if the DB is found, query the info table to see what has been done before
if os.path.isfile(SQLdb):
	conn = sqlite3.connect(SQLdb)
	c = conn.cursor()	
	c.execute("SELECT * FROM info")
	rows = c.fetchall()
	for i in rows:		
		investigationToggle=i[0]
		timelineToggle=i[1]
		profileToggle=str(i[2])
		basicToggle=i[3]
	if basicToggle == 1:
		if args['investigation'] and (investigationToggle == 1):
			print "We already did the investigation piece for this... please change your parameters"
			sys.exit()
		if args['investigation'] and (investigationToggle != 1):
			print "Updating info table for investigation..."
			c.execute("update info set investigation=1 where basic=1")
			conn.commit()
			c.close()
			print "We are in investigation loop... output is ", output
			investigationParse.investigationCommands(output, volatilityPath, filename, memProfile, SQLdb)
        	if args['timeline'] and (timelineToggle == 1):                
			print "We already did the timeline piece for this... please change your parameters"
			sys.exit()
		if args['timeline'] and (timelineToggle != 1): 
			print "Updating info table for timeline...."			
			c.execute("update info set timeline=1 where basic=1")
			conn.commit()
			c.close()
			timelineParse.timelineCommands(output, volatilityPath, filename, memProfile, SQLdb)
		else:
			print "We already did the basics piece..."
			sys.exit()
	conn.commit()
	c.close()

#New memory dump is given...
else:		
        print "Database does not exist, creating!"
	conn = sqlite3.connect(SQLdb)
	c = conn.cursor()		
	c.execute('create table info (investigation integer, timeline integer, profile text, basic integer)')
	c.execute('insert into info (basic) values (1)')    
	test="""update info set profile=('%s') where basic=1""" % memProfile
	c.execute(test)
	conn.commit()
	print "Database created in location: " + SQLdb + ". Moving on...."	
	basicParse1.basicCommands (output, volatilityPath, filename, memProfile,SQLdb)     
	if args['investigation']:
                c.execute("update info set investigation=1 where basic=1")
		conn.commit()
		conn.close()		
		investigationParse.investigationCommands (output, volatilityPath, filename, memProfile, SQLdb)		
        if args['timeline']:                
		conn = sqlite3.connect(SQLdb)
		c = conn.cursor()		
		c.execute("update info set timeline=1 where basic=1") 
		conn.commit()
		c.close()
		timelineParse.timelineCommands(output, volatilityPath, filename, memProfile, SQLdb)
	else:
		print "Done!"
		localtime = time.localtime(time.time())
		print "End Time :", localtime
		sys.exit()		

