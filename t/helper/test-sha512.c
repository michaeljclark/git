#include "test-tool.h"
#include "cache.h"

int cmd__sha512(int ac, const char **av)
{
	return cmd_hash_impl(ac, av, GIT_HASH_SHA512);
}

int cmd__sha512_224(int ac, const char **av)
{
	return cmd_hash_impl(ac, av, GIT_HASH_SHA512_224);
}

int cmd__sha512_256(int ac, const char **av)
{
	return cmd_hash_impl(ac, av, GIT_HASH_SHA512_256);
}
