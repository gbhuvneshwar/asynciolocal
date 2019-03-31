
import time
import urllib.request
import asyncio
import aiohttp

URL = 'https://api.github.com/events'
MAX_CLIENTS = 3

def fetch_sync(pid):
	print("Fetch sync process {} started".format(pid))
	start = time.time()
	response = urllib.request.urlopen(URL)
	datetime = response.getheader('Date')

	print("process {}: {}, took: {:.2f} seconds".format(pid, datetime, time.time()-start))

	return datetime



def synchronous():
	start = time.time()

	for i  in range(1, MAX_CLIENTS+1):
		fetch_sync(i)

	print("process took: {:.2f} seconds".format(time.time()-start))