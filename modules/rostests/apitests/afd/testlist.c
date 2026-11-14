#define STANDALONE
#include <apitest.h>

extern void func_ioctl(void);
extern void func_poll(void);
extern void func_send(void);
extern void func_windowsize(void);

const struct test winetest_testlist[] =
{
    { "ioctl", func_ioctl },
    { "poll", func_poll },
    { "send", func_send },
    { "windowsize", func_windowsize },
    { 0, 0 }
};
