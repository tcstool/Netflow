#!/usr/bin/python

import elasticsearch
import smtplib
from email.mime.text import MIMEText

def checkBadIPs ():
	ipData = {}
	es = elasticsearch.Elasticsearch(['http://localhost:9200']) #put your own elasticsearch IP in here
	print 'Checking Blocklist.de known bots against Netflow database...'

	try:
		with open('/tmp/blocklist_bots.txt') as f:
			blocklistDeBots = f.readlines()

	except Exception,e:
		print 'Error opening Blocklist.de IP data.'


	for badIP in blocklistDeBots:
		if ':' not in badIP: #Ignore IPv6 addresses since we don't use.
			match = es.count(index='logstash-*',q=badIP.rstrip() )

			if match['count'] > 0:
				ipData[badIP.rstrip()] = match['count']

	with open('/tmp/mailout.txt','w') as f: 
		f.write('\n\n-Blocklist.de known bot matches-\n')
	sortIPOutput(ipData)
	#print ipData	
	f.close()

	print 'Checking Feodo Tracker Trojan known bad IP list...'
	
	try:
		with open('/tmp/feodoipblock.txt') as f:
			feodoBots = f.readlines()

	except Exception,e:
		print e
		print 'Error opening Feodobot IP data.'
		pass

	for badIP in feodoBots:
		if '#' not in badIP and badIP.rstrip() != '0':
			match = es.count(index='logstash-*',q=badIP.rstrip() )

			if match['count'] > 0:
				ipData[badIP.rstrip()] = match['count']

	with open('/tmp/mailout.txt','a') as f:
		f.write('\n\n-Feodo/Cridex/Bugat Trojan Activity-\n')
	sortIPOutput(ipData)
	f.close()

	print 'Checking AlientVault IP Reputation Data...'

	try:
		with open('/tmp/avbots.txt') as f:
			alienVaultRep = f.readlines()

	except Exception,e:
		print e
		print 'Error opening AlienVault reputation data.'
	
	scanDict = {}
	maliciousDict = {}
	malwareDict = {}
	cAndcDict = {}
	otherDict = {}
	spamDict = {}

	for badIP in alienVaultRep:
		match = es.count(index = 'logstash-*',q=badIP.split('#')[0].rstrip() )
		
		if match['count'] > 0:
			if 'Scanning' in badIP.split('#')[3]:
				scanDict[badIP.split('#')[0] ] = match['count']

			if 'Malicious' in badIP.split('#')[3]:
				maliciousDict[badIP.split('#')[0] ] = match['count']
	
			if 'Malware' in badIP.split('#')[3]:
				malwareDict[badIP.split('#')[0] ] = match['count']

			if 'C&C' in badIP.split('#')[3]:
				cAndcDict[badIP.split('#')[0] ] = match['count']

			if 'Spamming' in badIP.split('#')[3]:
				spamDict[badIP.split('#')[0] ] = match['count']



	with open('/tmp/mailout.txt','a') as f:
		f.write('\n\n-AlienVault Reputation List-Malicious Hosts-\n')
	sortIPOutput(maliciousDict)

	with open('/tmp/mailout.txt','a') as f:
		f.write('-AlienVault Reputation List-Malware Domains-\n')
	sortIPOutput(malwareDict)

	with open('/tmp/mailout.txt','a') as f:
		f.write('\n\n-AlienVault Reputation List-Command And Control IPs-\n')
	sortIPOutput(cAndcDict)

	with open('/tmp/mailout.txt','a') as f:
		f.write('\n\n-AlientVault Reputation List-Spamming-\n')
	sortIPOutput(spamDict)

	with open('/tmp/mailout.txt','a') as f:
		f.write('-\n\nAlienVault Reputation List-Scanners-\n')
	sortIPOutput(scanDict)

	

	sendReport('localhost') #put your mail server IP in here

def sendReport(mailServer):
	report = open('/tmp/mailout.txt','rb')
	msg = MIMEText(report.read() )
	report.close()

	#Specify your sender and recipients here
	msg['Subject'] = 'Daily Threat Intelligence Summary'
	msg['From'] = 'threattel@me.com'
	msg['To'] = 'incidentresponse@me.com'

	s = smtplib.SMTP(mailServer)
	s.sendmail('threattel@me.com','incidentresponse@me.com',msg.as_string() ) #send the message here
	return


def sortIPOutput (ipArray):
	while len(ipArray) > 0:
		with open('/tmp/mailout.txt', 'a') as outFile:
			outFile.write(max(ipArray, key=ipArray.get) + ',' + str(ipArray[max(ipArray, key=ipArray.get)]) + '\n' )
		del ipArray[max(ipArray, key=ipArray.get)]
	return



def main():
	checkBadIPs()

if __name__ == '__main__':
        main()

