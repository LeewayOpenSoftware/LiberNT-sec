#define STANDALONE
#include <apitest.h>

extern void func_PnpAccessPolicy(void);
extern void func_ReenumerateDevNode(void);

const struct test winetest_testlist[] =
{
    { "PnpAccessPolicy", func_PnpAccessPolicy },
    { "ReenumerateDevNode", func_ReenumerateDevNode },
    { 0, 0 }
};
