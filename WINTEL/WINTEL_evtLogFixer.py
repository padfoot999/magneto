#Disclaimer: Does not work if Classic Event Log is empty originally (64kb)

import re
import struct
import binascii
import argparse
import os
import logging
logger = logging.getLogger('root')

def traverseDirectory(directory):
	unprocessedlist = []
	for root, dirs, files in os.walk(directory):
		for filename in files:
			if filename.endswith(('.evt', '.Evt')):
				if str(os.path.join(root,filename)) not in unprocessedlist:             
					unprocessedlist.append(os.path.join(root,filename))

	for rawFile in unprocessedlist:
		logger.debug(rawFile)
		fixEventLog(rawFile)

def fixEventLog(file):
	pattern = "\x11\x11\x11\x11\x22\x22\x22\x22\x33\x33\x33\x33\x44\x44\x44\x44"
	regex = re.compile(pattern)

	with open(file, 'r+b') as f:
		data = f.read()
		for match_obj in regex.finditer(data):
			offset = match_obj.start() + 16

		f.seek(offset)
		data = f.read(16)

		f.seek(16)
		f.write(data)

		f.seek(36)
		f.write('\x00')

def main():
	parser = argparse.ArgumentParser(description="Fixes Classic Event Logs to be viewed by Event Viewer")
	files = parser.add_mutually_exclusive_group(required=True)
	files.add_argument('-d', dest='directory', type=str, help="Directory containing evidence files")
	files.add_argument('-f', dest='file', type=str, help="Path to single evidence file")
	args = parser.parse_args()

	if args.directory:
		traverseDirectory(args.directory)
	else:
		fixEventLog(args.file)

if __name__ == '__main__':
	main()