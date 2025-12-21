#include "breakpoint.h"
#include <sys/ptrace.h>
#include <cerrno>

BreakPoint::BreakPoint(uint64_t address, pid_t PrID){
    state = false;
    addr = address;
    pid = PrID;
}

bool BreakPoint:: get_state() const {  
    return state;
}

uint64_t BreakPoint::get_instr() const{
    return orig_instruction;
}

uint64_t BreakPoint::get_addr() const{
    return addr;
}

pid_t BreakPoint::get_pid() const{
    return pid;
}

void BreakPoint:: enable(){
    if(is_enabled()){
        return;
    }

    errno = 0;
    long data = ptrace(PTRACE_PEEKTEXT, pid, addr, 0);
    if (data == -1 && errno != 0) {
        return;
    }
    orig_instruction = static_cast<uint64_t>(data);

    uint64_t data_with_trap = 0;
#if defined(__aarch64__)
    data_with_trap = (orig_instruction & 0xFFFFFFFF00000000) | 0xd4200000;
#elif defined(__amd64__)
    data_with_trap = (orig_instruction & ~0xFFULL) | 0xCC;
#else
#error Unsupported architecture
#endif

    if (ptrace(PTRACE_POKETEXT, pid, addr, data_with_trap) == -1) {
        return;
    }

    state = true;
    
}

void BreakPoint:: disable(){
    if(!is_enabled()){
        return;
    }

    if (ptrace(PTRACE_POKETEXT, pid, addr, orig_instruction) == -1) {
        return;
    }

    state = false;
    
}

bool BreakPoint:: is_enabled() const{
    return state;
}
