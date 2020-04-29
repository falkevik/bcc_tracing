#!/usr/bin/python
#

from __future__ import print_function
import bcc
from bcc.utils import printb
import sys
import time
import argparse
# arguments
examples = """examples:
       erl_trace -bp <path to beam> -fs <filter size>
       erl_trace -p 1234 -bp /path/to/beam.smp -fs 2000    
"""
parser = argparse.ArgumentParser(
    description="Trace and print erts beam allocations per process",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
parser.add_argument("-p", "--pid",
    type=int,
    help="trace this PID only")
parser.add_argument("-fs", "--filtersize", required=True,
    help="trace only allocations >= size")
parser.add_argument("-bp", "--beampath",   required=True,
    help="path to beam to be traced")
parser.add_argument("--debug", action='store_true',
    help="print debug info")
args = parser.parse_args()
beampath = args.beampath
filtersize = args.filtersize

if args.pid:
    tracepid = args.pid
else:
    tracepid = -1

# load BPF program
headers_txt = """

#include <uapi/linux/ptrace.h>
#include <bcc/proto.h>

#define TAG_PRIMARY_IMMED1 0x3
#define _TAG_PRIMARY_SIZE 2
#define _TAG_IMMED1_MASK 0xF
#define _TAG_IMMED1_PID TAG_PRIMARY_IMMED1
#define is_internal_pid(x) (((x) & _TAG_IMMED1_MASK) == _TAG_IMMED1_PID) 

typedef unsigned long long Eterm;
typedef unsigned int Uint;
typedef int Sint;

typedef Uint UWord;
typedef int SWord;

typedef UWord BeamInstr;

struct common {
    Eterm id;
};

struct process {
    struct common common;
    Eterm *htop;
    Eterm *stop;
    Eterm *heap;
    Eterm *hend;
    Eterm *abandoned_heap;
    Uint heap_sz;
    Uint min_heap_size;
    Uint min_Vheap_size;
    Uint max_heap_size;
    
    unsigned long fp_exception;
    
    Uint arity;
    Eterm *arg_reg;
    unsigned max_arg_reg;
    Eterm def_arg_reg[6];
    BeamInstr *i;

};

typedef struct process Process;

BPF_HASH(pids, u64, Process *, 512);
BPF_HASH(sizes, u64, unsigned int, 512);
BPF_HASH(in_gc_pids, u64, Process *, 512);

"""

print_pid_txt = """

static void print_pid(Process *p, unsigned int size) {
    int pidnr;
    int sernr;
    Process proc;

    if (!p)
        return;
    
    if(size < FILTERSIZE)
        return;
    bpf_probe_read(&proc, sizeof(Process), p);
    if(is_internal_pid(proc.common.id)) {
        pidnr = (((proc.common.id & 0xFFFFFFFF) >> 4) & ~(1<<15));
        sernr = (((proc.common.id & 0xFFFFFFFF) >> 19) & ~(1<<13));
        bpf_trace_printk("pid <0.%d.%d> %d\\n", pidnr, sernr, size);
    }
    return;
}

"""

functions_txt = """

static Process** get_pid() { 
    u64 tid;
    Process **p;
    tid = bpf_get_current_pid_tgid();
    p = pids.lookup(&tid);
    return p;
}

static unsigned int* get_size() {   
    u64 tid;
    unsigned int *s;

    tid = bpf_get_current_pid_tgid();
    s = sizes.lookup(&tid);
    return s;
}

int gc_called(struct pt_regs *ctx) {
    u64 tid;
    Process **p;
    tid = bpf_get_current_pid_tgid();
    
    if(!(p = get_pid()))
        return 0;

    in_gc_pids.update(&tid, p);
    pids.delete(&tid);
    return 0;
}

int gc_return(struct pt_regs *ctx) {
    u64 tid;
    Process **p;
    tid = bpf_get_current_pid_tgid();
    p = in_gc_pids.lookup(&tid);

    if (!p)
        return 0;

    pids.update(&tid, p);
    in_gc_pids.delete(&tid);
    
    return 0;
}

int set_pid(struct pt_regs *ctx) {
    u64 tid;
    Process *p;
    tid = bpf_get_current_pid_tgid();
    bpf_probe_read(&p, sizeof(Process *), &PT_REGS_RC(ctx));
    pids.update(&tid, &p);
    
    return 0;
}   

int size_arg3(struct pt_regs *ctx) {
    unsigned int size;
    Process **p;
    
    if (!(p = get_pid()))
        return 0;

    bpf_probe_read(&size, sizeof(size), &PT_REGS_PARM3(ctx));
    print_pid(*p, size);
    
    return 0;
}

int size_arg4(struct pt_regs *ctx) {
    unsigned int size;
    Process **p;
    
    if (!(p = get_pid()))
        return 0;

    bpf_probe_read(&size, sizeof(size), &PT_REGS_PARM4(ctx));
    print_pid(*p, size);
    
    return 0;
}

"""

bpf_text = headers_txt + print_pid_txt.replace('FILTERSIZE', filtersize) + functions_txt

if args.debug:
    print(bpf_text)


# initialize BPF
b = bcc.BPF(text=bpf_text)
b.attach_uretprobe(name=beampath, sym="erts_schedule", fn_name="set_pid", pid=tracepid)

b.attach_uprobe(name=beampath,    sym="garbage_collect", fn_name="gc_called", pid=tracepid)
b.attach_uretprobe(name=beampath, sym="garbage_collect", fn_name="gc_return", pid=tracepid)

b.attach_uprobe(name=beampath, sym="erts_alcu_alloc_thr_spec", fn_name="size_arg3", pid=tracepid)

b.attach_uprobe(name=beampath, sym="erts_alcu_alloc_thr_pref", fn_name="size_arg3", pid=tracepid)

b.attach_uprobe(name=beampath, sym="erts_alcu_realloc", fn_name="size_arg4", pid=tracepid)

# header
print("Exit with ctrl-c")

# format output
while 1:
    try:
        (task, pid, cpu, flags, ts, msg) = b.trace_fields()
    except ValueError:
        print("value error")
        continue
    except KeyboardInterrupt:
        exit()
    printb(msg)
