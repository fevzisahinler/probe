// probe eBPF programs. Each hook family lives in its own header; all are
// compiled into a single object sharing one ring buffer (see common.bpf.h).
#include "process.bpf.h"
#include "file.bpf.h"
#include "network.bpf.h"
