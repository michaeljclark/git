#!/bin/sh

#
# create exemplar hashes for t/t0015-hash.sh using openssl
#

HASHES="sha224 sha512-224 sha512-256 sha512 sha3-224 sha3-256 sha3-384 sha3-512"

for hash in ${HASHES}; do
	echo ${hash}
	openssl ${hash} < /dev/null
	printf "a" | openssl ${hash}
	printf "abc" | openssl ${hash}
	printf "message digest" | openssl ${hash}
	printf "abcdefghijklmnopqrstuvwxyz" | openssl ${hash}
	perl -e "$| = 1; print q{aaaaaaaaaa} for 1..100000;" | openssl ${hash}
	perl -e "$| = 1; print q{abcdefghijklmnopqrstuvwxyz} for 1..100000;" | openssl ${hash}
	printf "blob 0\0" | openssl ${hash}
	printf "blob 3\0abc" | openssl ${hash}
	printf "tree 0\0" | openssl ${hash}
done
