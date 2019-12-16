#include "test-tool.h"
#include "cache.h"

int cmd__sha3_224(int ac, const char **av)
{
	return cmd_hash_impl(ac, av, GIT_HASH_SHA3_224);
}

int cmd__sha3_256(int ac, const char **av)
{
	return cmd_hash_impl(ac, av, GIT_HASH_SHA3_256);
}

int cmd__sha3_384(int ac, const char **av)
{
	return cmd_hash_impl(ac, av, GIT_HASH_SHA3_384);
}

int cmd__sha3_512(int ac, const char **av)
{
	return cmd_hash_impl(ac, av, GIT_HASH_SHA3_512);
}
