// test C++ exception across call frames: helper throws, main catches
static void throwNumber() { throw 11; }

int main() {
    try { throwNumber(); } catch (int v) { return v; }
    return 99;
}
