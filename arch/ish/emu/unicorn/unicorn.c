#include <linux/moduleparam.h>
#include "unicorn.h"

bool unicorn_trace;
module_param_named(trace, unicorn_trace, bool, 0);
