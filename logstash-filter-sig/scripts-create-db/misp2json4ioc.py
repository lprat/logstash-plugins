#Parse misp result to json format for logstash filter ioc.rb 
#https://github.com/MISP/PyMISP
#Contact: lionel.prat9@gmail.com
#put file result.json and types.list
#remove alexa top 100 of IOC
import ujson
import sys
import re
import os
from pprint import pprint

#ARGV
if len(sys.argv) < 5:
    print("Syntaxe: ioc_parse.py original_ioc_json output.json type.list blacklist.json")
    sys.exit(0)

exclude_type = ["yara","snort","link","comment"]
ndata = {}
data = []
i=0
if os.path.exists(sys.argv[1]):
	with open(sys.argv[1]) as data_file:
		content = data_file.readlines()
		for line in content:
			data.append(ujson.loads(line))
	data_file.close()
else:
	exit

bldata = {}
if os.path.exists(sys.argv[4]):
	with open(sys.argv[4]) as data_file:
		bldata=ujson.load(data_file)
	data_file.close()
else:
	exit

#get 100 list url alexa
os.system('wget -qO- http://s3.amazonaws.com/alexa-static/top-1m.csv.zip | bsdtar -xvf- -O | head -100 |awk -F \',\' \'{print $2}\' > /tmp/top100uri')
#wget -qO- http://s3.amazonaws.com/alexa-static/top-1m.csv.zip | bsdtar -xvf- -O | head -100 |awk -F ',' '{print $2}' > /tmp/top100uri
topdom = []
if os.path.exists("/tmp/top100uri"):
	#load file array
	with open("/tmp/top100uri", "r") as ins:
		for line in ins:
			line=line.rstrip('\n')
			line=line.lower()
			topdom.append(line)
else:
	exit
			
for datax in data :
    i=i+1
    if datax['Event']['Attribute']:
        if type(datax['Event']['Attribute']) is not dict:
            for elem in datax['Event']['Attribute']:
                if str("External analysis") != str(elem['category']) and str(elem['type']) not in exclude_type:
                    if str(elem['type']) not in ndata.keys():
                        ndata[str(elem['type'])] = []
                    ndata[str(elem['type'])].append(elem['value'])
        else:
            for key,elem in datax['Event']['Attribute'].items():
                if str("External analysis") != str(elem['category']) and str(elem['type']) not in exclude_type:
                    if str(elem['type']) not in ndata.keys():
                        ndata[str(elem['type'])] = []
                    ndata[str(elem['type'])].append(elem['value'])
    if datax['Event']['ShadowAttribute']:
        if type(datax['Event']['ShadowAttribute']) is not dict:
            for elem in datax['Event']['ShadowAttribute']:
                if str("External analysis") != str(elem['category']) and str(elem['type']) not in exclude_type:
                    if str(elem['type']) not in ndata.keys():
                        ndata[str(elem['type'])] = []
                    ndata[str(elem['type'])].append(elem['value'])
        else:
            for key,elem in datax['Event']['ShadowAttribute'].items():
                if str("External analysis") != str(elem['category']) and str(elem['type']) not in exclude_type:
                    if str(elem['type']) not in ndata.keys():
                        ndata[str(elem['type'])] = []
                    ndata[str(elem['type'])].append(elem['value'])
#change key name, add subfix 'ioc_'
xdata = {}

for key,elem in ndata.items():
	if str(key) == "ip-dst" or str(key) == "ip-src":
		if 'ioc_ip' in xdata.keys():
			#elem = [element.lower() for element in elem]
			#10.x.x.x, 192.168.x.x, 172.16.0.0 - 172.31.255.255
			if 'ioc_ip' in bldata.keys():
				for list_bl in bldata['ioc_ip']:
					regex = re.compile(list_bl)
					elem = [x for x in elem if not regex.match(x)]
			regex = re.compile(r'(127\.[0-9]+\.[0-9]+\.[0-9]+|10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.([1-2][0-9]|0|30|31)\.\d+\.\d+|255\.255\.255\.\d+)')
			elem = [x for x in elem if not regex.match(x)]
			xdata['ioc_ip'] = list(set(xdata['ioc_ip'] + elem))
		else:
			#elem = [element.lower() for element in elem]
			if 'ioc_ip' in bldata.keys():
				for list_bl in bldata['ioc_ip']:
					regex = re.compile(list_bl)
					elem = [x for x in elem if not regex.match(x)]
			regex = re.compile(r'(127\.[0-9]+\.[0-9]+\.[0-9]+|10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.([1-2][0-9]|0|30|31)\.\d+\.\d+|255\.255\.255\.\d+)')
			elem = [x for x in elem if not regex.match(x)]
			xdata['ioc_ip'] = list(set(elem))
	elif str(key) == "email-attachment" or str(key) == "attachment":
		if 'ioc_attachment' in xdata.keys():
			#elem = [element.lower() for element in elem]
			if 'ioc_attachment' in bldata.keys():
				for list_bl in bldata['ioc_attachment']:
					regex = re.compile(list_bl)
					elem = [x for x in elem if not regex.match(x)]
			xdata['ioc_attachment'] = list(set(xdata['ioc_attachment'] + elem))
		else:
			#elem = [element.lower() for element in elem]
			if 'ioc_attachment' in bldata.keys():
				for list_bl in bldata['ioc_attachment']:
					regex = re.compile(list_bl)
					elem = [x for x in elem if not regex.match(x)]
			xdata['ioc_attachment'] = list(set(elem))
	elif str(key) == "email-dst" or str(key) == "email-src":
		if 'ioc_emailaddr' in xdata.keys():
			elem = [element.lower() for element in elem]
			if 'ioc_emailaddr' in bldata.keys():
				for list_bl in bldata['ioc_emailaddr']:
					regex = re.compile(list_bl)
					elem = [x for x in elem if not regex.match(x)]
			xdata['ioc_emailaddr'] = list(set(xdata['ioc_emailaddr'] + elem))
		else:
			elem = [element.lower() for element in elem]
			if 'ioc_emailaddr' in bldata.keys():
				for list_bl in bldata['ioc_emailaddr']:
					regex = re.compile(list_bl)
					elem = [x for x in elem if not regex.match(x)]
			xdata['ioc_emailaddr'] = list(set(elem))
	elif str(key) == "url" or str(key) == "uri":
		if 'ioc_uri' in xdata.keys():
			#elem = [element.lower() for element in elem]
			#elem = [w.replace('\\', '') for w in elem]
			elem = [w.replace('hxxp://', 'http://') for w in elem]
			elem = [w.replace('hxxps://', 'https://') for w in elem]
			if 'ioc_uri' in bldata.keys():
				for list_bl in bldata['ioc_uri']:
					regex = re.compile(list_bl)
					elem = [x for x in elem if not regex.match(x)]
			xdata['ioc_uri'] = list(set(xdata['ioc_uri'] + elem))
		else:
			#elem = [element.lower() for element in elem]
			#elem = [w.replace('\\', '') for w in elem]
			elem = [w.replace('hxxp://', 'http://') for w in elem]
			elem = [w.replace('hxxps://', 'https://') for w in elem]
			if 'ioc_uri' in bldata.keys():
				for list_bl in bldata['ioc_uri']:
					regex = re.compile(list_bl)
					elem = [x for x in elem if not regex.match(x)]
			xdata['ioc_uri'] = list(set(elem))
	elif str(key) == "domain":
		elem = [element.lower() for element in elem]
		elem = [x for x in elem if not x in topdom]
		if 'ioc_domain' in bldata.keys():
			for list_bl in bldata['ioc_domain']:
				regex = re.compile(list_bl)
				elem = [x for x in elem if not regex.match(x)]
		xdata['ioc_domain'] = list(set(elem))
	elif str(key) == "hostname":
		elem = [element.lower() for element in elem]
		if 'ioc_hostname' in bldata.keys():
			for list_bl in bldata['ioc_hostname']:
				regex = re.compile(list_bl)
				elem = [x for x in elem if not regex.match(x)]
		xdata['ioc_hostname'] = list(set(elem))
	elif str(key) == "user-agent":
		#elem = [element.lower() for element in elem]
		if 'ioc_user-agent' in bldata.keys():
			for list_bl in bldata['ioc_user-agent']:
				regex = re.compile(list_bl)
				elem = [x for x in elem if not regex.match(x)]
		xdata['ioc_user-agent'] = list(set(elem))
	elif str(key) == "email-subject":
		#elem = [element.lower() for element in elem]
		if 'ioc_email-subject' in bldata.keys():
			for list_bl in bldata['ioc_email-subject']:
				regex = re.compile(list_bl)
				elem = [x for x in elem if not regex.match(x)]
		xdata['ioc_email-subject'] = list(set(elem))
	elif str(key) == "AS":
		#elem = [element.lower() for element in elem]
		if 'ioc_as' in bldata.keys():
			for list_bl in bldata['ioc_as']:
				regex = re.compile(list_bl)
				elem = [x for x in elem if not regex.match(x)]
		xdata['ioc_as'] = list(set(elem))
with open(sys.argv[2]+'.all', 'w') as outfile:
    ujson.dump(ndata, outfile)
outfile.close()
with open(sys.argv[2], 'w') as outfile:
    ujson.dump(xdata, outfile)
outfile.close()
with open(sys.argv[3], 'w') as outfile:
    for key in xdata.keys():
        outfile.write(key+"\n")
outfile.close()    
#pprint(xdata)
print "Event count:"+str(len(data))


