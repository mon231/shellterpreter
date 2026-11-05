// test C++ exception: catch the value that was thrown
int main() {
    try { throw 7; } catch (int) { return 7; }
    return 99;
}
