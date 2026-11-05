// test C++ exception: catch the value that was thrown
#include "../common/selfreg.h"

int main() {
    selfRegisterLayout();
    try { throw 7; } catch (int) { return 7; }
    return 99;
}
