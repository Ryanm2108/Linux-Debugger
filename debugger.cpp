#include <iostream>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <elf.h>
#include <sys/uio.h>
#include "breakpoint.h"
#include <string>
#include <iostream>
#include <sstream>
#include <unordered_map>
#include <cerrno>
#include <cstring>

using namespace std;

static bool parse_addr(const std::string &input, uint64_t &out_addr) {
    if (input.empty()) {
        return false;
    }

    std::string arg = input;
    if (arg[0] == '*') {
        arg = arg.substr(1);
    }

    int base = 10;
    if (arg.rfind("0x", 0) == 0 || arg.rfind("0X", 0) == 0) {
        base = 16;
    }

    size_t idx = 0;
    try {
        out_addr = std::stoull(arg, &idx, base);
    } catch (const std::exception &) {
        return false;
    }

    return idx == arg.size();
}

static bool parse_id(const std::string &input, uint64_t &out_id) {
    if (input.empty()) {
        return false;
    }
    for (char c : input) {
        if (c < '0' || c > '9') {
            return false;
        }
    }
    try {
        out_id = std::stoull(input, nullptr, 10);
    } catch (const std::exception &) {
        return false;
    }
    return true;
}

struct BreakpointEntry {
    uint64_t id;
    uint64_t addr;
    BreakPoint bp;
    BreakpointEntry(uint64_t id_in, uint64_t addr_in, pid_t pid_in)
        : id(id_in), addr(addr_in), bp(addr_in, pid_in) {}
};

int main(int argc, char** argv){
    if(argc != 2){
        cerr << "Wrong command" << endl;
        return -1;
    }

    const char* program = argv[1];

    pid_t child = fork();

    if( child == 0){
        ptrace(PTRACE_TRACEME, 0,0,0);
        execl(program, program, NULL);
    }
    else{
        int wait_status;
        waitpid(child, &wait_status, 0);
        printf("I am the debugger, waiting for child [PID]");

        string line;
        unordered_map<uint64_t, BreakpointEntry> breakpoints;
        unordered_map<uint64_t, uint64_t> addr_to_id;
        uint64_t next_bp_id = 1;

        // breakpoint lazy step over helper variables
        bool pending;
        uint64_t pending_id = 0;

        struct user_regs_struct regs;

        struct iovec iov;
        iov.iov_base = &regs;
        iov.iov_len = sizeof(regs);

        ptrace(PTRACE_GETREGSET, child, NT_PRSTATUS, &iov);

        // lambda for breakpoint handling
        auto handle_sigtrap = [&](user_regs_struct &regs) {

            uint64_t bp_addr = regs.pc - 4;
            auto id_it = addr_to_id.find(bp_addr);
            if (id_it == addr_to_id.end()) {
                return false;
            }
            auto it = breakpoints.find(id_it->second);
            if (it == breakpoints.end() || !it->second.bp.is_enabled()) {
                return false;
            }

            it->second.bp.disable();
            regs.pc = bp_addr;
            ptrace(PTRACE_SETREGSET, child, NT_PRSTATUS, &iov);

            pending_id = id_it->second;

            return true;
        };

        auto lazy_stepover_helper = [&](uint64_t bp_id){
            ptrace(PTRACE_SINGLESTEP, child, 0, 0);
            waitpid(child, &wait_status, 0);

            breakpoints[bp_id].bp.enable();

        };
            
        while(!WIFEXITED(wait_status)){
            if (!getline(cin, line)) {
                break;
            }
            istringstream iss(line);
            string cmd;
            string arg;
            if (!(iss >> cmd)) {
                continue; // empty line
            }
            if (!(iss >> arg)) {
                arg.clear(); // no argument provided
            }

            if(cmd == "b"){
                uint64_t addr = 0;

                if (!parse_addr(arg, addr)) {
                    cerr << "usage: b <addr>" << endl;
                    continue;
                }

                auto id_it = addr_to_id.find(addr);
                if (id_it == addr_to_id.end()) {
                    uint64_t id = next_bp_id++;
                    breakpoints.emplace(id, BreakpointEntry(id, addr, child));
                    addr_to_id.emplace(addr, id);
                    id_it = addr_to_id.find(addr);
                }

                auto it = breakpoints.find(id_it->second);
                if (it != breakpoints.end()) {
                    it->second.bp.enable();
                }
                continue;

            }
            else if(cmd == "c"){
                if(pending_id != 0){
                    lazy_stepover_helper(pending_id);
                    pending_id = 0;
                }
                
                ptrace(PTRACE_CONT, child, 0,0);
                waitpid(child, &wait_status, 0);

                if (WIFSTOPPED(wait_status) && WSTOPSIG(wait_status) == SIGTRAP) {
                    ptrace(PTRACE_GETREGSET, child, NT_PRSTATUS, &iov);
                    if (handle_sigtrap(regs)) {
                        continue; // return to prompt after breakpoint hit
                    }
                    continue; // other SIGTRAPs (e.g., step) also return to prompt
                }
            }
            else if(cmd == "s"){
                if(pending_id != 0){
                    lazy_stepover_helper(pending_id);
                    pending_id = 0;

                    continue; // this internal single step counts as one !
                }
                
                ptrace(PTRACE_SINGLESTEP, child, 0, 0);
                waitpid(child, &wait_status, 0);

                if (WIFSTOPPED(wait_status) && WSTOPSIG(wait_status) == SIGTRAP) {
                    ptrace(PTRACE_GETREGSET, child, NT_PRSTATUS, &iov);
                    if (handle_sigtrap(regs)) {
                        continue; // return to prompt after breakpoint hit
                    }
                    continue; // other SIGTRAPs (e.g., step) also return to prompt
                }
            }
            else if(cmd == "regs"){ 
                ptrace(PTRACE_GETREGSET, child, NT_PRSTATUS, &iov);
                printf("PC: %llx\n", regs.pc);

            }
            else if(cmd == "q"){
                ptrace(PTRACE_DETACH, child, 0, 0);
                break;
            }
            else if(cmd == "h"){
                cout << "Commands:\n";
                cout << "  b <addr>   set breakpoint\n";
                cout << "  bl         list breakpoints\n";
                cout << "  bd <id|addr>  disable breakpoint\n";
                cout << "  del <id|addr> delete breakpoint\n";
                cout << "  disable <id|addr>  disable breakpoint (alias)\n";
                cout << "  enable <id|addr>   enable breakpoint (alias)\n";
                cout << "  x <addr>   read memory\n";
                cout << "  regs       show registers (pc)\n";
                cout << "  c          continue\n";
                cout << "  s          single-step\n";
                cout << "  q          quit\n";
                cout << "  h          help\n";
            }
            else if (cmd == "bl"){
                if (breakpoints.empty()) {
                    std::cout << "no breakpoints\n";
                    continue;
                }
                for (const auto &entry : breakpoints) {
                    const auto &bp = entry.second;
                    std::cout << "id " << bp.id << " at 0x" << std::hex << bp.addr
                              << (bp.bp.is_enabled() ? " enabled" : " disabled")
                              << std::dec << "\n";
                }
            }
            else if (cmd == "bd"){
                uint64_t id = 0;
                uint64_t addr = 0;
                bool found = false;
                auto it = breakpoints.end();

                if (parse_id(arg, id)) {
                    it = breakpoints.find(id);
                    if (it != breakpoints.end()) {
                        found = true;
                    }
                }
                if (!found && parse_addr(arg, addr)) {
                    auto id_it = addr_to_id.find(addr);
                    if (id_it != addr_to_id.end()) {
                        it = breakpoints.find(id_it->second);
                        found = (it != breakpoints.end());
                    }
                }
                if (!found) {
                    cerr << "usage: bd <id|addr>" << endl;
                    continue;
                }
                it->second.bp.disable();
            }
            else if (cmd == "disable"){
                uint64_t id = 0;
                uint64_t addr = 0;
                bool found = false;
                auto it = breakpoints.end();

                if (parse_id(arg, id)) {
                    it = breakpoints.find(id);
                    if (it != breakpoints.end()) {
                        found = true;
                    }
                }
                if (!found && parse_addr(arg, addr)) {
                    auto id_it = addr_to_id.find(addr);
                    if (id_it != addr_to_id.end()) {
                        it = breakpoints.find(id_it->second);
                        found = (it != breakpoints.end());
                    }
                }
                if (!found) {
                    cerr << "usage: disable <id|addr>" << endl;
                    continue;
                }
                it->second.bp.disable();
            }
            else if (cmd == "del"){
                uint64_t id = 0;
                uint64_t addr = 0;
                bool found = false;
                auto it = breakpoints.end();

                if (parse_id(arg, id)) {
                    it = breakpoints.find(id);
                    if (it != breakpoints.end()) {
                        found = true;
                    }
                }
                if (!found && parse_addr(arg, addr)) {
                    auto id_it = addr_to_id.find(addr);
                    if (id_it != addr_to_id.end()) {
                        it = breakpoints.find(id_it->second);
                        found = (it != breakpoints.end());
                    }
                }
                if (!found) {
                    cerr << "usage: del <id|addr>" << endl;
                    continue;
                }
                if (it->second.bp.is_enabled()) {
                    it->second.bp.disable();
                }
                addr_to_id.erase(it->second.addr);
                breakpoints.erase(it);
            }
            else if (cmd == "enable"){
                uint64_t id = 0;
                uint64_t addr = 0;
                bool found = false;
                auto it = breakpoints.end();

                if (parse_id(arg, id)) {
                    it = breakpoints.find(id);
                    if (it != breakpoints.end()) {
                        found = true;
                    }
                }
                if (!found && parse_addr(arg, addr)) {
                    auto id_it = addr_to_id.find(addr);
                    if (id_it != addr_to_id.end()) {
                        it = breakpoints.find(id_it->second);
                        found = (it != breakpoints.end());
                    }
                }
                if (!found) {
                    cerr << "usage: enable <id|addr>" << endl;
                    continue;
                }
                it->second.bp.enable();
            }
            else if (cmd == "x"){
                // read mem( i didnt know what to check user_input with so I made it the else)
                uint64_t addr = 0;

                if (!parse_addr(arg, addr)) {
                    cerr << "usage: x <addr>" << endl;
                    continue;
                }

                errno = 0;
                long data = ptrace(PTRACE_PEEKDATA, child, addr, 0);
                if(data == -1 && errno != 0){
                    std::cerr << "peekdata failed: " << strerror(errno) << "\n";
                    continue;   
                }
                printf("0x%llx: 0x%lx\n", (unsigned long long)addr, data);
                // <addr> refers to the address at which mem is to be read from. it's passed in as an arg.
                // yet to be fixed
            }
            else{
                std::cerr << "unknown command: " << cmd << "\n";
            }
        }
   
    }

    return 0;
}
