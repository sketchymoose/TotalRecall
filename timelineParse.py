import os
import sys
import sqlite3
import subprocess
import csv

def timelineCommands(output, volatilityPath, filename, memProfile, SQLdb):
    print "Timeline Enabled!"
    #registry (normal), timeliner (vol 2.3), userassist (2.3), shimcache (2.3), shellbags(2.3) MFT (2.3), event logs (2.3 - xp/2k3 ONLY), iehistory (2.3)

    #create directory
    directory = "Timeline"
    directory = os.path.join(os.path.abspath(output), directory)
    if not os.path.exists(directory):
        os.makedirs(directory)

    commands = ['userassist',
                'shimcache',
                'iehistory'
    ]

    second_command_to_popen_map = {}

    for cmd in commands:
        output_filepath = os.path.join(directory, cmd + ".txt")
        cmd_tuple = "python", volatilityPath, "-f", filename, "--profile=" + memProfile, cmd
        print "Running " + cmd + "..."
        popen_object = subprocess.Popen(cmd_tuple, stdout=open(output_filepath, "w"))
        second_command_to_popen_map[cmd] = popen_object

    #The rest of these will be done by hand.. different outputs, and calls
    timelineFiles = []
    commands = ['shellbags']
    for cmd in commands:
        output_filepath = os.path.join(directory, cmd + ".txt")
	#add this to the list timelineFiles
	timelineFiles.append(output_filepath)
        output_path = "--output-file=" + output_filepath
	cmd_tuple = "python", volatilityPath, "-f", filename, "--profile=" + memProfile, cmd, "--output=body", output_path
        print "Running " + cmd + "..."
        popen_object = subprocess.Popen(cmd_tuple, stdout=open(output_filepath, "w"))
        second_command_to_popen_map[cmd] = popen_object
    
    commands = ['mftparser']
    for cmd in commands:
        output_filepath = os.path.join(directory, cmd + ".txt")
	#add this to the list timelineFiles
	timelineFiles.append(output_filepath)
        output_path = "--output-file=" + output_filepath
	cmd_tuple = "python", volatilityPath, "-f", filename, "--profile=" + memProfile, cmd, "--output=body", output_path, "-C"
        print "Running " + cmd + "..."
        popen_object = subprocess.Popen(cmd_tuple, stdout=open(output_filepath, "w"))
        second_command_to_popen_map[cmd] = popen_object

    commands = ['timeliner']
    for cmd in commands:
        output_filepath = os.path.join(directory, cmd + ".txt")
	#add this to the list timelineFiles
	timelineFiles.append(output_filepath)
        output_path = "--output-file=" + output_filepath
        cmd_tuple = "python", volatilityPath, "-f", filename, "--profile=" + memProfile, cmd,"--output=body", output_path, "-R"
        print "Running " + cmd + "..."
        popen_object = subprocess.Popen(cmd_tuple, stdout=open(output_filepath, "w"))
        second_command_to_popen_map[cmd] = popen_object
	
    commands = ['evtlogs']
    for cmd in commands:
        if memProfile.startswith('WinXP') or memProfile.startswith('Win2k3'):
            cmd_tuple = "python", volatilityPath, "-f", filename, "--profile=" + memProfile, cmd, "-D", directory
            print "Running " + cmd + "..."
            popen_object = subprocess.Popen(cmd_tuple)
            second_command_to_popen_map[cmd] = popen_object
        else:
            print "Skipping evtlogs, the profile is not XP/2k3"

    print "Waiting for volatility plugins to finish..."
    for cmd, p in second_command_to_popen_map.iteritems():
        print "Waiting for %s" % cmd
        p.wait()

    print "creating Timeline with mftparser, timeliner, and shellbags..."
    bodyfile = os.path.join(directory, "rawBodyFile.txt")
	
    conn = sqlite3.connect(SQLdb)
    c = conn.cursor()
    c.execute('''create table timeline (date text, time integer, size integer, type text, mode text,UID integer,GID integer, meta integer, fileName text)''')

    #We are now appending all files which we use for timeline analysis (timeliner, shellbags, mftparser)	
    with open(bodyfile, 'w') as outfile:
    	for fname in timelineFiles:
        	with open(fname) as infile:
            		for line in infile:
                		outfile.write(line)
    
    #running mactime against the new file create	
    parsedBodyFile = os.path.join(directory, "parsedBodyFile.txt")
    print "Running Mactime.. results are in " + parsedBodyFile
    command = "mactime -b " + bodyfile + " -d > " + parsedBodyFile
    subprocess.call(command, stdout=subprocess.PIPE, shell=True)

    csvReader = csv.reader(open(parsedBodyFile), delimiter=',',skipinitialspace=True)
    next(csvReader)	
    for row in csvReader:
    	newlist = []
	newlist.append(row[0][4:15])
	newlist.append(row[0][16:24])

	for elem in row[1:]:
		newlist.append(elem)

	try:
		conn.execute("insert into timeline (date,time,size,type,mode,UID,GID,meta,fileName) values (?,?,?,?,?,?,?,?,?)", newlist)
	except sqlite3.ProgrammingError:
		print "*TIMELINE* Error at SQL" 
		continue 
    conn.commit()
    c.close()    
    print "Timeline Success!"
