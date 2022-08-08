#include "TamperingSyscalls.h"

int main(){
    SetUnhandledExceptionFilter( OneShotHardwareBreakpointHandler );
    /* Code Here */
}