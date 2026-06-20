#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include "wh_launcher.h"

int WINAPI WinMain(HINSTANCE, HINSTANCE, LPSTR, int) {
    return launcher::run();
}
