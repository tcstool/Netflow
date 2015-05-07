#!/usr/bin/python
import urllib

def main():
	downloadFeeds()

def downloadFeeds():
	print 'Fetching blocklist.de botlist...'

	try:
		urllib.urlretrieve('http://www.blocklist.de/lists/bots.txt','/tmp/blocklist_bots.txt')

	except:
		print 'Could not retrive the blocklist.de bots list.'
		pass

	print 'Fetching AlientVault IP Reputation Data...'
	
	try:
		urllib.urlretrieve('http://reputation.alienvault.com/reputation.data','/tmp/avbots.txt')

	except:
		print 'Could not retrieve AlienVault reputation data.'
		pass


	print 'Fetching Feodotracker botnet domain list...'

	try:
		urllib.urlretrieve('https://feodotracker.abuse.ch/blocklist/?download=ipblocklist','/tmp/feodoipblock.txt')

	except Exception,e:
		print e
		print 'Could not retrieve Feodotracker ip block list'
		pass


if __name__ == '__main__':
	main()
