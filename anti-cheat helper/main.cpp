#include "Vac3/vac3_emulation.h"
#include "Vac3/hook_detector.h"
#include "utils/module_utils.h"
#include "gui/gui.h"

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE, LPSTR, int) {
    gui::run(hInstance);
    return 0;
}
