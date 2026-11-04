// test nested C++ exceptions: catch one, throw a different type from the handler
static int deep() { return 15; }
static void throwFromHandler() { throw (char)1; }

static int mid() {
    try { if (deep() == 15) throw 15; } catch (int) { throwFromHandler(); }
    return 99;
}

int main() {
    try { mid(); } catch (char) { return 15; }
    return 99;
}
