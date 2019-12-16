#!/bin/sh

test_description='test basic hash implementation'
. ./test-lib.sh


test_expect_success 'test basic SHA-1 hash values' '
	test-tool sha1 </dev/null >actual &&
	grep da39a3ee5e6b4b0d3255bfef95601890afd80709 actual &&
	printf "a" | test-tool sha1 >actual &&
	grep 86f7e437faa5a7fce15d1ddcb9eaeaea377667b8 actual &&
	printf "abc" | test-tool sha1 >actual &&
	grep a9993e364706816aba3e25717850c26c9cd0d89d actual &&
	printf "message digest" | test-tool sha1 >actual &&
	grep c12252ceda8be8994d5fa0290a47231c1d16aae3 actual &&
	printf "abcdefghijklmnopqrstuvwxyz" | test-tool sha1 >actual &&
	grep 32d10c7b8cf96570ca04ce37f2a19d84240d3a89 actual &&
	perl -e "$| = 1; print q{aaaaaaaaaa} for 1..100000;" | \
		test-tool sha1 >actual &&
	grep 34aa973cd4c4daa4f61eeb2bdbad27316534016f actual &&
	printf "blob 0\0" | test-tool sha1 >actual &&
	grep e69de29bb2d1d6434b8b29ae775ad8c2e48c5391 actual &&
	printf "blob 3\0abc" | test-tool sha1 >actual &&
	grep f2ba8f84ab5c1bce84a7b441cb1959cfc7093b7f actual &&
	printf "tree 0\0" | test-tool sha1 >actual &&
	grep 4b825dc642cb6eb9a060e54bf8d69288fbee4904 actual
'

test_expect_success 'test basic SHA-256 hash values' '
	test-tool sha256 </dev/null >actual &&
	grep e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 actual &&
	printf "a" | test-tool sha256 >actual &&
	grep ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb actual &&
	printf "abc" | test-tool sha256 >actual &&
	grep ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad actual &&
	printf "message digest" | test-tool sha256 >actual &&
	grep f7846f55cf23e14eebeab5b4e1550cad5b509e3348fbc4efa3a1413d393cb650 actual &&
	printf "abcdefghijklmnopqrstuvwxyz" | test-tool sha256 >actual &&
	grep 71c480df93d6ae2f1efad1447c66c9525e316218cf51fc8d9ed832f2daf18b73 actual &&
	# Try to exercise the chunking code by turning autoflush on.
	perl -e "$| = 1; print q{aaaaaaaaaa} for 1..100000;" | \
		test-tool sha256 >actual &&
	grep cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0 actual &&
	perl -e "$| = 1; print q{abcdefghijklmnopqrstuvwxyz} for 1..100000;" | \
		test-tool sha256 >actual &&
	grep e406ba321ca712ad35a698bf0af8d61fc4dc40eca6bdcea4697962724ccbde35 actual &&
	printf "blob 0\0" | test-tool sha256 >actual &&
	grep 473a0f4c3be8a93681a267e3b1e9a7dcda1185436fe141f7749120a303721813 actual &&
	printf "blob 3\0abc" | test-tool sha256 >actual &&
	grep c1cf6e465077930e88dc5136641d402f72a229ddd996f627d60e9639eaba35a6 actual &&
	printf "tree 0\0" | test-tool sha256 >actual &&
	grep 6ef19b41225c5369f1c104d45d8d85efa9b057b53b14b4b9b939dd74decc5321 actual
'

test_expect_success 'test basic SHA-512/224 hash values' '
	test-tool sha512-224 </dev/null >actual &&
	grep 6ed0dd02806fa89e25de060c19d3ac86cabb87d6a0ddd05c333b84f4 actual &&
	printf "a" | test-tool sha512-224 >actual &&
	grep d5cdb9ccc769a5121d4175f2bfdd13d6310e0d3d361ea75d82108327 actual &&
	printf "abc" | test-tool sha512-224 >actual &&
	grep 4634270f707b6a54daae7530460842e20e37ed265ceee9a43e8924aa actual &&
	printf "message digest" | test-tool sha512-224 >actual &&
	grep ad1a4db188fe57064f4f24609d2a83cd0afb9b398eb2fcaeaae2c564 actual &&
	printf "abcdefghijklmnopqrstuvwxyz" | test-tool sha512-224 >actual &&
	grep ff83148aa07ec30655c1b40aff86141c0215fe2a54f767d3f38743d8 actual &&
	# Try to exercise the chunking code by turning autoflush on.
	perl -e "$| = 1; print q{aaaaaaaaaa} for 1..100000;" | \
		test-tool sha512-224 >actual &&
	grep 37ab331d76f0d36de422bd0edeb22a28accd487b7a8453ae965dd287 actual &&
	perl -e "$| = 1; print q{abcdefghijklmnopqrstuvwxyz} for 1..100000;" | \
		test-tool sha512-224 >actual &&
	grep 6a312ce7c451ef28bf9ad33f5ce85ddf2d9f07097660160dbcb5c4c4 actual &&
	printf "blob 0\0" | test-tool sha512-224 >actual &&
	grep a86d3c63339860445607d6cfd3551292a6fb049f0faa222a7c10027b actual &&
	printf "blob 3\0abc" | test-tool sha512-224 >actual &&
	grep 9d6948b51bccf6b9814288d3e8cbca42f5e31b825ec613b23a45a546 actual &&
	printf "tree 0\0" | test-tool sha512-224 >actual &&
	grep aaff3ab067b151d0bc3130277d64a11eb257e0feca74e0dcb7e38303 actual
'

test_expect_success 'test basic SHA-512/256 hash values' '
	test-tool sha512-256 </dev/null >actual &&
	grep c672b8d1ef56ed28ab87c3622c5114069bdd3ad7b8f9737498d0c01ecef0967a actual &&
	printf "a" | test-tool sha512-256 >actual &&
	grep 455e518824bc0601f9fb858ff5c37d417d67c2f8e0df2babe4808858aea830f8 actual &&
	printf "abc" | test-tool sha512-256 >actual &&
	grep 53048e2681941ef99b2e29b76b4c7dabe4c2d0c634fc6d46e0e2f13107e7af23 actual &&
	printf "message digest" | test-tool sha512-256 >actual &&
	grep 0cf471fd17ed69d990daf3433c89b16d63dec1bb9cb42a6094604ee5d7b4e9fb actual &&
	printf "abcdefghijklmnopqrstuvwxyz" | test-tool sha512-256 >actual &&
	grep fc3189443f9c268f626aea08a756abe7b726b05f701cb08222312ccfd6710a26 actual &&
	# Try to exercise the chunking code by turning autoflush on.
	perl -e "$| = 1; print q{aaaaaaaaaa} for 1..100000;" | \
		test-tool sha512-256 >actual &&
	grep 9a59a052930187a97038cae692f30708aa6491923ef5194394dc68d56c74fb21 actual &&
	perl -e "$| = 1; print q{abcdefghijklmnopqrstuvwxyz} for 1..100000;" | \
		test-tool sha512-256 >actual &&
	grep b8803f7dc283e57eeb6340a3ba9d9a2098125500008b5bfdfeeb6ddd0582d2b8 actual &&
	printf "blob 0\0" | test-tool sha512-256 >actual &&
	grep 6576668d3acf022c9c77920c8349ed6ccd8fc596845e87c38b9e749016c984b3 actual &&
	printf "blob 3\0abc" | test-tool sha512-256 >actual &&
	grep 815d5a4e692c971eea251f5e8d86b42953640027d8f1163d9f33adeb5e1f7a7a actual &&
	printf "tree 0\0" | test-tool sha512-256 >actual &&
	grep 2cfe78f8ea2fa9d219374868e7aa1fe491622bcb5815dcf3ad12f308be7959db actual

'

test_expect_success 'test basic SHA-512 hash values' '
	test-tool sha512 </dev/null >actual &&
	grep cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e actual &&
	printf "a" | test-tool sha512 >actual &&
	grep 1f40fc92da241694750979ee6cf582f2d5d7d28e18335de05abc54d0560e0f5302860c652bf08d560252aa5e74210546f369fbbbce8c12cfc7957b2652fe9a75 actual &&
	printf "abc" | test-tool sha512 >actual &&
	grep ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f actual &&
	printf "message digest" | test-tool sha512 >actual &&
	grep 107dbf389d9e9f71a3a95f6c055b9251bc5268c2be16d6c13492ea45b0199f3309e16455ab1e96118e8a905d5597b72038ddb372a89826046de66687bb420e7c actual &&
	printf "abcdefghijklmnopqrstuvwxyz" | test-tool sha512 >actual &&
	grep 4dbff86cc2ca1bae1e16468a05cb9881c97f1753bce3619034898faa1aabe429955a1bf8ec483d7421fe3c1646613a59ed5441fb0f321389f77f48a879c7b1f1 actual &&
	# Try to exercise the chunking code by turning autoflush on.
	perl -e "$| = 1; print q{aaaaaaaaaa} for 1..100000;" | \
		test-tool sha512 >actual &&
	grep e718483d0ce769644e2e42c7bc15b4638e1f98b13b2044285632a803afa973ebde0ff244877ea60a4cb0432ce577c31beb009c5c2c49aa2e4eadb217ad8cc09b actual &&
	perl -e "$| = 1; print q{abcdefghijklmnopqrstuvwxyz} for 1..100000;" | \
		test-tool sha512 >actual &&
	grep daeddbe45570b154876086f66464a1a1ea6b623bd6bf53132a92f3326e0edb5cb8bf3eef58fe0b15c87526a226bd3242cad65f1f2025f1dbde0c30e41a9f8253 actual &&
	printf "blob 0\0" | test-tool sha512 >actual &&
	grep ba4d0bb3ec890fdc47a10df53a591a79852237d5e635455da90a3742d7482708b57de2ffabc7581f581ee8075fbab3476270942cdf87fa7dd6895daa6509896c actual &&
	printf "blob 3\0abc" | test-tool sha512 >actual &&
	grep 55abbe2a993e9d900dcd5e1315dbf5bc634af92500bf4242fd9c5bba38090ee043fc886018aab7fa7d855abf41162a1fcb49ef7bd56778fd6c0b9d1a7ba00a71 actual &&
	printf "tree 0\0" | test-tool sha512 >actual &&
	grep d51fd92fdd8b29d08f5cba261abb221529e6ffb1264c511be216d2f5306ecdcc38e2392de4f62c745607a97680fc7ccbbe73044dfc03d89ed95ba54967909195 actual

'

test_done
