#!/usr/bin/python

#
# creates git's "empty tree" and "empty blob" hashes
# depends on `printf` and `openssl` in the path.
#

import os
import re

hashes = [ "sha1", "sha224", "sha256", "sha512-224", "sha512-256",
		   "sha512", "sha3-224", "sha3-256", "sha3-384", "sha3-512" ]

def hex_hash(hash,str):
	stream = os.popen('printf "%s" | openssl %s' % (str,hash))
	output = stream.read()
	return re.findall('=\s([a-f0-9]+)',output)[0]

def macroize(str):
	return str.upper().replace('-','_')

def escape_hex(hex):
	s = ""
	for i in range(len(hex)):
		if i % 20 == 0 and i != 0:
			s += '" \\\n	"'
		if i % 2 == 0:
			s += '\\x'
		s += hex[i]
	return s

def create_hash(h,t,s):
	print('#define %s_%s_%s \\\n	"%s"' %
		(macroize(t), macroize(h), 'BIN_LITERAL', escape_hex(hex_hash(h,s))))

for h in hashes:
	create_hash(h,'empty-tree', 'tree 0\\0')
print("")
for h in hashes:
	create_hash(h,'empty-blob', 'blob 0\\0')