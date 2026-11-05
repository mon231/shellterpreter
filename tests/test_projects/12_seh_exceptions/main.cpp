// test structured exception handling: __try/__except with a code classifier
#include <windows.h>
#include "../common/selfreg.h"

int main() {
    selfRegisterLayout();
    __try {
        RaiseException(1, 0, 0, nullptr);
        return 98; // must not be reached: the raise must unwind here
    }
    __except (GetExceptionCode() == 1 ? EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH) {
        return 12;
    }
    return 99;
}
