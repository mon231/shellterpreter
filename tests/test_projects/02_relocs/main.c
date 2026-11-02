typedef int (*Fn)(void);

static int step1(void) { return 100; }
static int step2(void) { return 42; }

// function addresses stored as data force DIR64/HIGHLOW relocations in .reloc
static Fn g_fn = step1;

int step2_addr(void) { return g_fn != step1 ? 1 : 0; }

int main(void)
{
    int total = 0;
    for (int i = 0; i < 5; ++i)
        total += g_fn();
    total += step2();
    total += step2_addr();
    return total;
}
