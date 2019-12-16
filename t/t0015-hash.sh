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

test_expect_success 'test basic SHA3-224 hash values' '
	test-tool sha3-224 </dev/null >actual &&
	grep 6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7 actual &&
	printf "a" | test-tool sha3-224 >actual &&
	grep 9e86ff69557ca95f405f081269685b38e3a819b309ee942f482b6a8b actual &&
	printf "abc" | test-tool sha3-224 >actual &&
	grep e642824c3f8cf24ad09234ee7d3c766fc9a3a5168d0c94ad73b46fdf actual &&
	printf "message digest" | test-tool sha3-224 >actual &&
	grep 18768bb4c48eb7fc88e5ddb17efcf2964abd7798a39d86a4b4a1e4c8 actual &&
	printf "abcdefghijklmnopqrstuvwxyz" | test-tool sha3-224 >actual &&
	grep 5cdeca81e123f87cad96b9cba999f16f6d41549608d4e0f4681b8239 actual &&
	# Try to exercise the chunking code by turning autoflush on.
	perl -e "$| = 1; print q{aaaaaaaaaa} for 1..100000;" | \
		test-tool sha3-224 >actual &&
	grep d69335b93325192e516a912e6d19a15cb51c6ed5c15243e7a7fd653c actual &&
	perl -e "$| = 1; print q{abcdefghijklmnopqrstuvwxyz} for 1..100000;" | \
		test-tool sha3-224 >actual &&
	grep 165efebf793f03c7610d6d5e79462c5f9b7fbcb903f4448038eb35a2 actual &&
	printf "blob 0\0" | test-tool sha3-224 >actual &&
	grep f1e72935ac5c52d5c09b408842e207c42e5434424007364fdb468063 actual &&
	printf "blob 3\0abc" | test-tool sha3-224 >actual &&
	grep f83c608c9d424b858f66ec80a67ab42409bdc1aae8d7867e6b595e2a actual &&
	printf "tree 0\0" | test-tool sha3-224 >actual &&
	grep 1e04f23de0b2b7d1b85e6768fa997a99bd0119dec8158ae0ad07e183 actual

'

test_expect_success 'test basic SHA3-256 hash values' '
	test-tool sha3-256 </dev/null >actual &&
	grep a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a actual &&
	printf "a" | test-tool sha3-256 >actual &&
	grep 80084bf2fba02475726feb2cab2d8215eab14bc6bdd8bfb2c8151257032ecd8b actual &&
	printf "abc" | test-tool sha3-256 >actual &&
	grep 3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532 actual &&
	printf "message digest" | test-tool sha3-256 >actual &&
	grep edcdb2069366e75243860c18c3a11465eca34bce6143d30c8665cefcfd32bffd actual &&
	printf "abcdefghijklmnopqrstuvwxyz" | test-tool sha3-256 >actual &&
	grep 7cab2dc765e21b241dbc1c255ce620b29f527c6d5e7f5f843e56288f0d707521 actual &&
	# Try to exercise the chunking code by turning autoflush on.
	perl -e "$| = 1; print q{aaaaaaaaaa} for 1..100000;" | \
		test-tool sha3-256 >actual &&
	grep 5c8875ae474a3634ba4fd55ec85bffd661f32aca75c6d699d0cdcb6c115891c1 actual &&
	perl -e "$| = 1; print q{abcdefghijklmnopqrstuvwxyz} for 1..100000;" | \
		test-tool sha3-256 >actual &&
	grep 529a361bd6ebbb28deea5a78db2fd714c5b415499d608e37123c4ca130770e6d actual &&
	printf "blob 0\0" | test-tool sha3-256 >actual &&
	grep 5aadde7d8ca5b9b352c250ce9b799f5d818893fe89dc52b49f438c8a9ba0a545 actual &&
	printf "blob 3\0abc" | test-tool sha3-256 >actual &&
	grep 1a6437dda2a94af5c38246520fd1461886dc46b97ced88b04d43537c603cde6d actual &&
	printf "tree 0\0" | test-tool sha3-256 >actual &&
	grep 30211ed485c912e5bc285bd0bd8959ddbfb5875cafb0ae28e0abfa1077b2b214 actual

'

test_expect_success 'test basic SHA3-384 hash values' '
	test-tool sha3-384 </dev/null >actual &&
	grep 0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004 actual &&
	printf "a" | test-tool sha3-384 >actual &&
	grep 1815f774f320491b48569efec794d249eeb59aae46d22bf77dafe25c5edc28d7ea44f93ee1234aa88f61c91912a4ccd9 actual &&
	printf "abc" | test-tool sha3-384 >actual &&
	grep ec01498288516fc926459f58e2c6ad8df9b473cb0fc08c2596da7cf0e49be4b298d88cea927ac7f539f1edf228376d25 actual &&
	printf "message digest" | test-tool sha3-384 >actual &&
	grep d9519709f44af73e2c8e291109a979de3d61dc02bf69def7fbffdfffe662751513f19ad57e17d4b93ba1e484fc1980d5 actual &&
	printf "abcdefghijklmnopqrstuvwxyz" | test-tool sha3-384 >actual &&
	grep fed399d2217aaf4c717ad0c5102c15589e1c990cc2b9a5029056a7f7485888d6ab65db2370077a5cadb53fc9280d278f actual &&
	# Try to exercise the chunking code by turning autoflush on.
	perl -e "$| = 1; print q{aaaaaaaaaa} for 1..100000;" | \
		test-tool sha3-384 >actual &&
	grep eee9e24d78c1855337983451df97c8ad9eedf256c6334f8e948d252d5e0e76847aa0774ddb90a842190d2c558b4b8340 actual &&
	perl -e "$| = 1; print q{abcdefghijklmnopqrstuvwxyz} for 1..100000;" | \
		test-tool sha3-384 >actual &&
	grep 62c16d1d4366dd40a4c6995168c1e7b35e8e8103403274151a34c5838845a0f3d1a192dadbb0964af7d6941c50f0eb97 actual &&
	printf "blob 0\0" | test-tool sha3-384 >actual &&
	grep a53e088abe908d8c9458a8ba955690c417f768031ecf156a1662441faeda502e838f2660164b61a78b15ac75e0f8ded4 actual &&
	printf "blob 3\0abc" | test-tool sha3-384 >actual &&
	grep ba0eda34a4b47f9ec8ed996a260efadeb576e4f682b7d0d7d84b4781a210771da519e48f2542431882499fbd21d16935 actual &&
	printf "tree 0\0" | test-tool sha3-384 >actual &&
	grep 92e99ae9281a89dc332c9ce8f2831db50ecc54784d51c3ebd5c1151e8fd603fb408abbbb9dcf5713ed21566789ce8059 actual

'

test_expect_success 'test basic SHA3-512 hash values' '
	test-tool sha3-512 </dev/null >actual &&
	grep a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26 actual &&
	printf "a" | test-tool sha3-512 >actual &&
	grep 697f2d856172cb8309d6b8b97dac4de344b549d4dee61edfb4962d8698b7fa803f4f93ff24393586e28b5b957ac3d1d369420ce53332712f997bd336d09ab02a actual &&
	printf "abc" | test-tool sha3-512 >actual &&
	grep b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0 actual &&
	printf "message digest" | test-tool sha3-512 >actual &&
	grep 3444e155881fa15511f57726c7d7cfe80302a7433067b29d59a71415ca9dd141ac892d310bc4d78128c98fda839d18d7f0556f2fe7acb3c0cda4bff3a25f5f59 actual &&
	printf "abcdefghijklmnopqrstuvwxyz" | test-tool sha3-512 >actual &&
	grep af328d17fa28753a3c9f5cb72e376b90440b96f0289e5703b729324a975ab384eda565fc92aaded143669900d761861687acdc0a5ffa358bd0571aaad80aca68 actual &&
	# Try to exercise the chunking code by turning autoflush on.
	perl -e "$| = 1; print q{aaaaaaaaaa} for 1..100000;" | \
		test-tool sha3-512 >actual &&
	grep 3c3a876da14034ab60627c077bb98f7e120a2a5370212dffb3385a18d4f38859ed311d0a9d5141ce9cc5c66ee689b266a8aa18ace8282a0e0db596c90b0a7b87 actual &&
	perl -e "$| = 1; print q{abcdefghijklmnopqrstuvwxyz} for 1..100000;" | \
		test-tool sha3-512 >actual &&
	grep 06b2e52cc7595712651351cdc6726acdebba682844c7983f66089158433975e4d2caf6c0efc4c7018cd2da73df53047f19a79935941025db4aaf1bd876c49ad6 actual &&
	printf "blob 0\0" | test-tool sha3-512 >actual &&
	grep 4353a50d0d3d8edd231763fb0102116286aa6d760a772133e32c124a998a19467d789064dd763e57b547ff3a31882da3d2031378cfe0fa5774c12eea51055a51 actual &&
	printf "blob 3\0abc" | test-tool sha3-512 >actual &&
	grep 89de02c66a3beca3411b5a72699fe8389d574b7d59ca17d42cba7a83cd03423388b1c4248cd8a3cce73a0768948fe1a800c155c24378334f6ae2bb8c5bf48284 actual &&
	printf "tree 0\0" | test-tool sha3-512 >actual &&
	grep 8f86cb67ce0a8bc865b300733c27dade0ea8fe66299b4bc6368ec84f53134c367c66f0e3376261ab5a86d722ad0d98391a3c1c472d6791da464a7836006de12c actual

'

test_done
