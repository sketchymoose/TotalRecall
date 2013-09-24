import sqlite3
import csv
import os
import subprocess


linesToSkip=2

def basicCommands(output, volatilityPath, filename, memProfile, SQLdb):
#what volatility commands to do we want to run?
	#print "The memory profile is at: ",memProfile
	if ("Win7" or "Vista" or "2008") in memProfile:
		#print "1st loop"		
		if "64" in memProfile:
			#print "64 bit of 1st loop"
			commands = ['pslist',
	        		'psscan',
	        	   	'dlllist',
	        	 	'driverscan',
	        	    	'ldrmodules',
	        	  	'modules',
	        	  	'ssdt',
				'netscan'
				]
		else:
			#print "32 bit of 1st loop" 	
			commands = ['pslist',
	            		'psscan',
        	    		'apihooks',
       		    		'callbacks',
        	   		'dlllist',
        	    		'driverscan',
        	    		'ldrmodules',
        	    		'modules',
        	    		'ssdt',
				'netscan'
				]		
	else:
		#print "2nd loop"
		commands = ['pslist',
        		'psscan',
        	 	'apihooks',
        	        'callbacks',
		        'connections',
        	        'connscan',
        	        'dlllist',
        	        'driverscan',
        	        'ldrmodules',
        	        'modules',
        	        'ssdt',
        	        'sockscan',
			]

	command_to_popen_map = {}
	
	for cmd in commands:
    		output_filepath = os.path.join(os.path.abspath(output), cmd + ".txt")
    		#cmd_tuple = "python", volatilityPath, "-f", filename, "--profile=" + memProfile, cmd, "output-file=" + output_filepath
		cmd_tuple = "python", volatilityPath, "-f", filename, "--profile=" + memProfile, cmd,
    		print "Running " + cmd + "..."
		#print cmd_tuple
		#print "output for ", cmd, " is at: ", output_filepath     		
		popen_object = subprocess.Popen(cmd_tuple, stdout=open(output_filepath, "w"))
		#subprocess.call(cmd_tuple, stdout=open(os.devnull, "w"), stderr=open(os.devnull, "w"), shell=True)    		
		command_to_popen_map[cmd] = popen_object


#command -> output_dir map
	command_to_output_dir = [
    		('dlldump', 'DLLDump'),
    		('vaddump', 'VADDump'),
    		('procexedump', 'ProcDump'),
    		('moddump', 'ModDump'),
    		('malfind', 'malfind'),
	]

#create directory
	for _, directory in command_to_output_dir:
    		directory = os.path.join(os.path.abspath(output), directory)
		#print "Checking for directory: ", directory
    		if not os.path.exists(directory):
        		os.makedirs(directory)
			#print "Directory created: ", directory

#went back to the old school method of doing things
	for (dmpcmd, output_dir) in command_to_output_dir:
		output_dir=os.path.join(os.path.abspath(output), output_dir)
	    	#output_dir = os.path.join(output, output_dir)
		#print "Output directory for dump commands is: " + output_dir
    		finalCommand = "python " + volatilityPath + " -f " + filename + " " + "--profile=" + memProfile + " " + dmpcmd + " -D " + output_dir
		#print "finalCommand is: " , finalCommand    		
		print "Running " + dmpcmd + "..."
    		subprocess.call(finalCommand, stdout=open(os.devnull, "w"), stderr=open(os.devnull, "w"), shell=True)

	print "Waiting for volatility plugins to finish..."
	for cmd, p in command_to_popen_map.iteritems():
    		print "Waiting for %s" % cmd
    		p.wait()

	if ("Win7" or "Vista" or "2008") in memProfile:
		#print "1st loop"		
		if "64" in memProfile:
			print "Adding Win7/Vista 64-bit modules to DB"
			pslistFile(output,'pslist.txt',SQLdb)
        		psscanFile(output, 'psscan.txt', SQLdb)
       	   		dllList(output,'dlllist.txt',SQLdb)
            		driverscanFile(output, 'driverscan.txt', SQLdb)
     		      	modulesFile(output, 'modules.txt', SQLdb)
     		   	netscanFile(output, 'netscan.txt', SQLdb)
		else:
			print "Adding Win7/Vista 32-bit modules to DB" 	
			pslistFile(output,'pslist.txt',SQLdb)
        		psscanFile(output, 'psscan.txt', SQLdb),
        		apihooksFile(output, 'apihooks.txt', SQLdb)
        		callbacksFile(output, 'callbacks.txt', SQLdb)
			dllList(output,'dlllist.txt',SQLdb)
        	    	driverscanFile(output, 'driverscan.txt', SQLdb)
        	   	modulesFile(output, 'modules.txt', SQLdb)
        		netscanFile(output, 'netscan.txt', SQLdb)		
	else:
		print "Adding XP/2003 items to DB"	
		pslistFile(output,'pslist.txt',SQLdb)
		connscanFile(output, 'connscan.txt', SQLdb)
		connectionsFile(output, 'connections.txt', SQLdb)
		sockscanFile(output, 'sockscan.txt', SQLdb)
		driverscanFile(output, 'driverscan.txt', SQLdb)
		psscanFile(output, 'psscan.txt', SQLdb)
		modulesFile(output, 'modules.txt', SQLdb)
		apihooksFile(output, 'apihooks.txt', SQLdb)
		callbacksFile(output, 'callbacks.txt', SQLdb)
		dllList(output,'dlllist.txt',SQLdb)	
	
def pslistFile(output,fileLocation,DBName):
	output=os.path.join(output,fileLocation)
	f = open(output,"rb")

	conn = sqlite3.connect(DBName)
	c = conn.cursor()
	c.execute('''create table pslist (offset text, name text, pid integer,ppid integer,threads integer, handles integer, sessions text, wow64 text, startDate text, startTime text, startTimezone text, endDate text, endTime text, endTimezone text)''')
	
	for line in f.readlines()[linesToSkip:]:
		line=" ".join(line.split())
		newLine=line.split(" ",13)
		newLineLength=len(newLine)
		while (newLineLength < 14):
			newLine.append("blank")	
			newLineLength=len(newLine)
			#print newLine	
		try: 
        		conn.execute('insert into pslist (offset, name, pid, ppid, threads, handles, sessions, wow64, startDate, startTime, startTimezone, endDate, endTime, endTimezone) values (?,?,?,?,?,?,?,?,?,?,?,?,?,?)', newLine)
		except sqlite3.ProgrammingError:
			print "*PSLIST* Error at SQL" 
			continue 
	conn.commit()
	c.close()
	print "pslist output added to database!"

def connscanFile(output,fileLocation,DBName):	
	output=os.path.join(output, fileLocation)
	f = open(output,"rb")
	
	conn = sqlite3.connect(DBName)
	c = conn.cursor()
	c.execute('''create table connscan (offset text, srcAddress text, dstAddress text,pid integer)''')

	for line in f.readlines()[linesToSkip:]:
		line=" ".join(line.split())
		newLine=line.split(" ")		
		try: 
			#print row
	        	conn.execute('insert into connscan (offset, srcAddress, dstAddress, pid) values (?,?,?,?)', newLine)
		except sqlite3.ProgrammingError:
			print "*CONNSCAN* Error at SQL"
			continue 
	conn.commit()
	c.close()
	print "Connscan output added to database!"

def connectionsFile(output,fileLocation,DBName):
	output=os.path.join(output,fileLocation)
	f = open(output,"rb")

	conn = sqlite3.connect(DBName)
	c = conn.cursor()
	c.execute('''create table connections (offset text, srcAddress text, dstAddress text,pid integer)''')
	
	for line in f.readlines()[linesToSkip:]:
		line=" ".join(line.split())
		newLine=line.split(" ")		
		try: 
        		conn.execute('insert into connections (offset, srcAddress, dstAddress, pid) values (?,?,?,?)', newLine)
		except sqlite3.ProgrammingError:
			print "*CONNECTIONS* Error at SQL" 
			continue 
	conn.commit()
	c.close()
	print "Connections output added to database!"

def sockscanFile(output,fileLocation,DBName):	
	output=os.path.join(output, fileLocation)
	f = open(output,"rb")
	
	conn = sqlite3.connect(DBName)
	c = conn.cursor()
	c.execute('''create table sockscan (offset text, pid integer, port integer,protoNum integer, protocol text, address text, createDate text, createTime text, createTimezone text)''')

	for line in f.readlines()[linesToSkip:]:	
		line=' '.join(line.split())
		newLine=line.split(" ")
		
		try:
			conn.execute('insert into sockscan (offset, pid, port, protoNum, protocol, address, createDate, createTime, createTimezone) values (?,?,?,?,?,?,?,?,?)', newLine)
				
		except sqlite3.ProgrammingError:
			print "*SOCKSCAN* Error at SQL"
			continue 
	conn.commit()
	c.close()
	print "sockscan output added to database!"

def driverscanFile(output,fileLocation,DBName):
	output=os.path.join(output,fileLocation)
	f = open(output,"rb")

	conn = sqlite3.connect(DBName)
	c = conn.cursor()
	c.execute('''create table driverscan (offset text, numPointers integer,numHandles integer, startAddress text, size integer, serviceKey text, name text, driverName text)''')

	for line in f.readlines()[linesToSkip:]:
		line=' '.join(line.split())	
		newLine=line.split(" ",7)
		newLineLength=len(newLine)
	
		if (newLineLength < 8):
			newLine.append("blank")
		try:
			conn.execute('insert into driverscan (offset, numPointers, numHandles, startAddress, size, serviceKey, name, driverName) values (?,?,?,?,?,?,?,?)', newLine)

		except sqlite3.ProgrammingError:
			print "*DRIVERSCAN* Error at SQL"
			continue 	
	conn.commit()
	c.close()
	print "driverscan output added to database!"

def psscanFile(output,fileLocation,DBName):
	output=os.path.join(output, fileLocation)
	f = open(output,"rb")
	#toot = f.readline()
	#firstLine=toot.split()
	fieldsMaster = 11
	numDelim = 10

	conn = sqlite3.connect(DBName)
	c = conn.cursor()

	c.execute('''create table psscan (offset text, name text, pid text, ppid text, PDB text, createDate text, createTime text, createTimezone text, exitDate text, exitTime text, exitTimezone)''')
	
	for line in f.readlines()[linesToSkip:]:	
		line=' '.join(line.split())
		newLine=line.split(" ",numDelim)
		fieldsRow=len(newLine)
		if fieldsRow < fieldsMaster:
		#print ("We have", fieldsRow, " columns, but we need, ", fieldsMaster)
			difference = fieldsMaster - fieldsRow
		#print ("The difference is ", difference)
			countAppend= 0
			while countAppend < difference:		
				newLine.append('blank')
				countAppend = countAppend + 1
			#print countAppend
	#print newLine	
		try:
		        conn.execute('insert into psscan (offset, name, pid, ppid, PDB, createDate, createTime, createTimezone, exitDate, exitTime, exitTimezone) values (?,?,?,?,?,?,?,?,?,?,?)', newLine)

		except sqlite3.ProgrammingError:
			print "*PSSCAN* Error at SQL"
			continue 	
	conn.commit()
	c.close()
	print "psscan output added to database!"


def modulesFile(output,fileLocation,DBName):
	output=os.path.join(output,fileLocation)
	f = open(output,"rb")
	#toot = f.readline()
	#firstLine=toot.split()
	#fields = len(firstLine)
	#print ("We are working with ", fields, " fields")
	numDelim = 4 

	conn = sqlite3.connect(DBName)
	c = conn.cursor()
	c.execute('''create table modules (offset text, file text, base text, size text, name text)''')

	for line in f.readlines()[linesToSkip:]:	
		line=' '.join(line.split())
		newLine=line.split(" ",numDelim)
		for w in newLine:		
			w.replace("\00","--")	 
		#newLine=newLine.replace("\00", "--")

		try:
			conn.execute('insert into modules (offset, file, base, size, name) values (?,?,?,?,?)', newLine)

		except sqlite3.ProgrammingError:
			print "*MODULES* Error at SQL"
			continue 	
	conn.commit()
	c.close()
	print "Modules output added to database!"
	

def apihooksFile(output,fileLocation,DBName):
	output=os.path.join(output, fileLocation)
	#print "Creating APIHooks table..."
	conn = sqlite3.connect(DBName)
	c = conn.cursor()
	c.execute('''create table APIhooks (hookMode text, hookType text, processTarget text, victimModule text, function text, hookAddress text, hookingModule text)''')
	z = open(output, "rb")	
	flist = z.readlines()

	aList = []
	hook= []
	for line in flist:
		#This goes down the file... 				
		if 'Hook mode' in line:
			line=line.rstrip()
			aList = line.split(":")
			hook.append(str(aList[1]).replace(' ', ''))
			aList=[]
		elif 'Hook type' in line: 
			line=line.rstrip()
			aList = line.split(":")
			hook.append(str(aList[1]).replace(' ', ''))
			aList=[] 	
		elif 'Process' in line:
			line=line.rstrip()
			aList = line.split(":")
			hook.append(str(aList[1]).replace(' ', ''))
			aList=[]		
		elif 'Victim module' in line:
			line=line.rstrip()
			aList = line.split(":")
			hook.append(str(aList[1]).replace(' ', ''))
			aList=[]
		elif 'Function' in line:
			line=line.rstrip()
			aList = line.split(":")
			hook.append(str(aList[1]).replace(' ', ''))
			aList=[]
		elif 'Hook address' in line:
			line=line.rstrip()
			aList = line.split(":")
			hook.append(str(aList[1]).replace(' ', ''))
			aList=[]
		elif 'Hooking module' in line:
			line=line.rstrip()
			aList = line.split(":")
			hook.append(str(aList[1]).replace(' ', ''))		
			aList=[] 
		else:
			pass
	#Ok... now to throw in the database
	#print hook
	lengthHook = len(hook)
	#print lengthHook
	while lengthHook > 0:
		count = 0
		if count < 7:
			hookSection = []
			hookSection.append(hook.pop(0))
			hookSection.append(hook.pop(0))
			hookSection.append(hook.pop(0))
			hookSection.append(hook.pop(0))
			hookSection.append(hook.pop(0))
			hookSection.append(hook.pop(0))
			hookSection.append(hook.pop(0))
			count = 6
			testLength= len(hook)
			if (len(hook) < 7):
				#print "Hook has: " ,hook
				#print "We are within the length < 7 loop"
				#print " The length of hook is: ", testLength
				difference = 7 - testLength			
				while testLength < 7:
					hookSection=[]				
					count = 1
					while count <= testLength:					
						hookSection.append(hook.pop(0))
						count = count +1
						#print hookSection
					count = 0
					while count < difference:				
						hookSection.append("blank")
						testLength = len(hookSection)
						#print hookSection
						count = count + 1					
			try:
	        		conn.execute('insert into APIhooks (hookMode, hookType, processTarget, victimModule, function, hookAddress, hookingModule) values (?,?,?,?,?,?,?)', hookSection)

			except sqlite3.ProgrammingError:
				print "*APIHOOKS* Error at SQL"
				continue 
		lengthHook = len(hook)
		#print "Now we are at: ", lengthHook	
		conn.commit()
		c.close()
	print "apihooks output added to database!"

def callbacksFile(output,fileLocation,DBName):
	output=os.path.join(output,fileLocation)
	#print "Creating CallBacks table..."
	
	conn = sqlite3.connect(DBName)
	c = conn.cursor()
	c.execute('''create table callbacks (type text, callback text, ownerModule text, details text)''')

	f = open(output,"rb")
	toot = f.readline()
	#firstLine=toot.split()
	#fields = len(firstLine)
	#print ("We are working with ", fields, " fields")
	numDelim = 3 

	for line in f.readlines()[linesToSkip:]:	
		line=' '.join(line.split())
		newLine=line.split(" ",numDelim)

		try:
			conn.execute('insert into callbacks (type, callback, ownerModule, details) values (?,?,?,?)', newLine)
		except sqlite3.ProgrammingError:
			print "*CALLBACKS* Error at SQL" 
			continue 

	conn.commit()
	c.close()
	print "callbacks output added to database!"

def netscanFile(output, fileLocation, DBName):
	output=os.path.join(output, fileLocation)
	z = open(output, "rb")	
	
	numDelim = 7	
	conn = sqlite3.connect(DBName)
	c = conn.cursor()
	c.execute('''create table netscan (offset text, protocol text, localAddress text, foreignAddress text, state test, pid integer, owner text, created text)''')

	for line in z.readlines()[1:]:	
		line=' '.join(line.split())
		newLine=line.split(" ",numDelim)
		length = len(newLine)
		if length < 8:
			newLine.append("blank")
		try:
			conn.execute('insert into netscan (offset, protocol, localAddress, foreignAddress, state, pid, owner, created) values (?,?,?,?,?,?,?,?)', newLine)
		except sqlite3.ProgrammingError:
			print "*NETSCAN* Error at SQL" 
			continue 

	conn.commit()
	c.close()
	print "Netscan output added to database!"
	
def dllList(output,fileLocation,DBName):
	output=os.path.join(output, fileLocation)
	z = open(output, "rb")	
	flist = z.readlines()
	
	processNum = 1

	aPid = []
	bPid= []
	cFiller =[]
	d= []
	eCommandLine = []
	fAddress= []
	for line in flist:
		#This goes down the file... 		
		#We first need to look for the PID and put that in a list (bPid)		
		if 'pid' in line:
			line=line.rstrip()
			aPid = line.split(":")
			bPid.append(str(aPid[1]).replace(' ', ''))
			# print bPid
		#If we see the word 'PEB' it means its a terminated process so there will be nothing in terms of command line... but we need to account for it so we associate none to cFiller  	
		elif 'PEB' in line:
			cFiller.append("none")
		#Looks for the command line invocation of the pid and put that in cFiller, we will link bPid and cFiller together (pid x has a command invocation of y)		
		elif 'Command line' in line:
			line=line.rstrip()
			eCommandLine = line.partition(":")
			cFiller.append(str(eCommandLine[2]).replace(' ',''))
			# print cFiller
		#next we look for the DLLs and append into d, we firstly append the PID with the dlls so we can associate it later in the database		
		elif '0x' in line:
			line=line.rstrip()
			fAddress = line.split( )
			d.append(str(aPid[1]).replace(' ',''))
			d.append(str(fAddress[0]).replace(' ',''))
			d.append(str(fAddress[1]).replace(' ',''))
			d.append(str(fAddress[2]).replace(' ',''))
			d.append(str(fAddress[3]).replace(' ',''))
		else:
			pass

	#ok now we start the first loop
	count=0
	lengthOfList=len(bPid)
	conn = sqlite3.connect(DBName)
	c = conn.cursor()
	c.execute('''create table dllListOne (pid integer, CommandLine text)''')
	c.execute("create table dllListTwo (pid integer, base text, size text, loadCount text, location text)")  
 
	while (count < lengthOfList):
		#puts the command line and pid into one table 
		#executeStatement="INSERT INTO dllListOne (pid) values (?)"
		#conn.execute(executeStatement,str((bPid[count])))		
		conn.execute("insert into dllListOne (pid) values ('%s')" % bPid[count])
		
		executeStatement= "UPDATE dllListOne set CommandLine=? where pid=?"	
		conn.execute(executeStatement, (cFiller[count],bPid[count]))
		#add 1 to the counter and keep going!
		count = count + 1
	
	#OK... and now the 2nd table associated with dllList!
	count = 0 
	lengthOfList2=len(d)
	
	while (count < lengthOfList2):
		executeStatement= "INSERT INTO dllListTwo (pid, base, size, loadCount, location) VALUES (?,?,?,?,?)"
		conn.execute(executeStatement,(str(d[count]),str(d[count+1]),str(d[count+2]),str(d[count+3]),str(d[count+4])))	
		count = count + 5 

	print "Both Tables of DLLlist added!"
	conn.commit()
	c.close()


