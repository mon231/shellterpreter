// test C++ exception across call frames: helper throws, main catches
#include "../common/selfreg.h"

static void throwNumber() { throw 11; }

int main() {
    selfRegisterLayout();
    try { throwNumber(); } catch (int v) { return v; }
    return 99;
}
