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
#include "DWARF_parser.h"
#include <signal.h>
#include <dis-asm.h>
#include <bfd.h>
#include <functional>

const int max_depth = 32;

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

int read_memory_func(bfd_vma memaddr, bfd_byte *myaddr, unsigned int length, disassemble_info *info){
    pid_t pid = *(pid_t*)info->application_data;
    for(int i =0; i < length ; i++){
        uint64_t aligned_addr = (memaddr+i) & ~7UL;
       long data = ptrace(PTRACE_PEEKDATA, pid, aligned_addr, 0);
       if (data == (unsigned long long)-1 && errno != 0) return EIO;

       int byte_offset = (memaddr + i) & 7;
       
        myaddr[i] = (data >> (byte_offset * 8)) & 0xFF;
    }

    return 0;
}

// watchpoint helper

bool read_mem(pid_t pid, uint64_t addr, long* out_value){
    errno = 0;
    long data = ptrace(PTRACE_PEEKDATA, pid, addr, 0);
    if(data == -1 && errno != 0){
        return false;
    }
    else if (out_value == nullptr){
        return false;
    }
    else{
        *out_value = data;
        return true;
    }
}


struct BreakpointEntry {
    uint64_t id;
    uint64_t addr;
    BreakPoint bp;
    bool has_cond;
    string cond_reg;
    uint64_t cond_value;
    string cond_op;
    BreakpointEntry(uint64_t id_in, uint64_t addr_in, pid_t pid_in)
        : id(id_in), addr(addr_in), bp(addr_in, pid_in), has_cond(false), cond_reg(""), cond_value(0), cond_op("") {}
};

int main(int argc, char** argv){
    if(argc != 2){
        cerr << "Wrong command" << endl;
        return -1;
    }

    const char* program = argv[1];

    DwarfParser parser;
    parser.load_symbols(program);

    bfd_init();

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

        // watchpoints
        bool watch_active = false;
        uint64_t watch_addr = 0;
        long watch_value = 0;


        // breakpoint lazy step over helper variables
        bool pending;
        uint64_t pending_id = 0;

        struct user_regs_struct regs;

        struct iovec iov;
        iov.iov_base = &regs;
        iov.iov_len = sizeof(regs);

        ptrace(PTRACE_GETREGSET, child, NT_PRSTATUS, &iov);

        std::function<bool(user_regs_struct&)> handle_sigtrap;
        handle_sigtrap = [&](user_regs_struct &regs) -> bool {
            uint64_t bp_addr = regs.pc - 4;

            auto id_it = addr_to_id.find(bp_addr);
            if (id_it == addr_to_id.end()) {
                return false;
            }

            auto it = breakpoints.find(id_it->second);
            if (it == breakpoints.end() || !it->second.bp.is_enabled()) {
                return false;
            }

            // Helper to fetch register value by name
            auto get_reg_val = [&](const string& name, uint64_t &out) -> bool {
                if (name == "pc") { out = regs.pc; return true; }
                if (name == "sp") { out = regs.sp; return true; }
                if (name == "pstate") { out = regs.pstate; return true; }
                if (name.size() >= 2 && name[0] == 'x') {
                    string idx_str = name.substr(1);
                    for (char ch : idx_str) {
                        if (ch < '0' || ch > '9') return false;
                    }
                    int idx = stoi(idx_str);
                    if (idx < 0 || idx > 30) return false;
                    out = regs.regs[idx];
                    return true;
                }
                return false;
            };

            // If conditional, evaluate it
            if (it->second.has_cond) {
                uint64_t regval = 0;
                if (!get_reg_val(it->second.cond_reg, regval)) {
                    // invalid register name -> treat as no match, keep running
                    it->second.bp.enable();
                    ptrace(PTRACE_CONT, child, 0, 0);
                    waitpid(child, &wait_status, 0);
                    if (WIFSTOPPED(wait_status) && WSTOPSIG(wait_status) == SIGTRAP) {
                        ptrace(PTRACE_GETREGSET, child, NT_PRSTATUS, &iov);
                        return handle_sigtrap(regs);
                    }
                    return false;
                }

                bool cond_ok = false;
                const string &op = it->second.cond_op;
                uint64_t rhs = it->second.cond_value;

                if (op == "==") cond_ok = (regval == rhs);
                else if (op == "!=") cond_ok = (regval != rhs);
                else if (op == "<") cond_ok = (regval < rhs);
                else if (op == "<=") cond_ok = (regval <= rhs);
                else if (op == ">") cond_ok = (regval > rhs);
                else if (op == ">=") cond_ok = (regval >= rhs);

                if (!cond_ok) {
                    // Condition false: re-enable bp and keep running
                    it->second.bp.enable();
                    ptrace(PTRACE_CONT, child, 0, 0);
                    waitpid(child, &wait_status, 0);
                    if (WIFSTOPPED(wait_status) && WSTOPSIG(wait_status) == SIGTRAP) {
                        ptrace(PTRACE_GETREGSET, child, NT_PRSTATUS, &iov);
                        return handle_sigtrap(regs);
                    }
                    return false;
                }
            }

            // Condition true (or no condition): stop here
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

        disassemble_info dinfo;

        init_disassemble_info(&dinfo, stdout, (fprintf_ftype)fprintf, nullptr);

        dinfo.arch = bfd_arch_aarch64;
        dinfo.mach = bfd_mach_aarch64;

        dinfo.endian = BFD_ENDIAN_LITTLE;
        dinfo.read_memory_func = read_memory_func;
        dinfo.application_data = &child;
    

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

                if (arg.empty()) {
                    cerr << "usage: b <addr> [if <reg> <op> <value>]" << endl;
                    continue;
                }
                   
                if (!parse_addr(arg, addr)) {
                    addr = parser.get_function_addr(arg);
                    if(addr == 0){
                     cerr << "usage: b <addr> [if <reg> <op> <value>]" << endl;
                    continue;
                        }
                }
                

                // Optional condition parsing
                bool has_cond = false;
                string reg, op, valstr;
                uint64_t cond_value = 0;

                string kw;
                if (iss >> kw) {
                    if (kw != "if") {
                        cerr << "usage: b <addr> [if <reg> <op> <value>]" << endl;
                        continue;
                    }
                    if (!(iss >> reg >> op >> valstr)) {
                        cerr << "usage: b <addr> [if <reg> <op> <value>]" << endl;
                        continue;
                    }
                    if (op != "==" && op != "!=" && op != "<" && op != "<=" && op != ">" && op != ">=") {
                        cerr << "usage: b <addr> [if <reg> <op> <value>]" << endl;
                        continue;
                    }
                    if (!parse_addr(valstr, cond_value)) {
                        cerr << "usage: b <addr> [if <reg> <op> <value>]" << endl;
                        continue;
                    }
                    has_cond = true;
                }
               
                auto id_it = addr_to_id.find(addr);
                if (id_it == addr_to_id.end()) {
                    uint64_t id = next_bp_id++;
                    breakpoints.emplace(id, BreakpointEntry(id, addr, child));
                    addr_to_id.emplace(addr, id);
                    id_it = addr_to_id.find(addr);
                }

                auto it = breakpoints.find(id_it->second);

                it->second.has_cond = has_cond;
                it->second.cond_reg = reg;
                it->second.cond_op = op;
                it->second.cond_value = cond_value;

                if (it != breakpoints.end()) {
                    it->second.bp.enable();
                }
                continue;
                
            }
            else if(cmd == "c"){
                long out_val;

                if(pending_id != 0){
                    lazy_stepover_helper(pending_id);
                    pending_id = 0;
                }
                
                ptrace(PTRACE_CONT, child, 0,0);
                waitpid(child, &wait_status, 0);

                if(WIFSTOPPED(wait_status)){
                    if(watch_active){
                        if(!read_mem(child, watch_addr, &out_val)){
                        cerr << "mem couldn't be read.>" << endl;
                        continue;
                        }
                        if(out_val != watch_value){
                            printf("watchpoint hit at 0x%llu : old=0x%llu new=0x%llu", watch_addr, watch_value, out_val);
                            watch_value = out_val;
                        }
                    }
                }

                if (WIFSTOPPED(wait_status) && WSTOPSIG(wait_status) == SIGTRAP) {
                    ptrace(PTRACE_GETREGSET, child, NT_PRSTATUS, &iov);
                    if (handle_sigtrap(regs)) {
                        continue; // return to prompt after breakpoint hit
                    }
                    continue; // other SIGTRAPs (e.g., step) also return to prompt
                }
            }
            else if(cmd == "s"){
                long out_val;
                if(pending_id != 0){
                    lazy_stepover_helper(pending_id);
                    pending_id = 0;

                    continue; // this internal single step counts as one !
                }
                
                ptrace(PTRACE_SINGLESTEP, child, 0, 0);
                waitpid(child, &wait_status, 0);

                if(WIFSTOPPED(wait_status)){
                    if(watch_active){
                        if(!read_mem(child, watch_addr, &out_val)){
                        cerr << "mem couldn't be read.>" << endl;
                        continue;
                        }
                        if(out_val != watch_value){
                            printf("watchpoint hit at 0x%llu : old=0x%llu new=0x%llu", watch_addr, watch_value, out_val);
                            watch_value = out_val;
                        }
                    }
                }

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
                for(int i = 0; i < 31; i++){
                    printf("x%d : 0x%llx\n", i, (unsigned long long)regs.regs[i]);
                }
                 printf("sp: %llx\n", (unsigned long long)regs.sp);
                 printf("pc: %llx\n", (unsigned long long)regs.pc);
                 printf("pstate: %llx\n", (unsigned long long)regs.pstate);
            }
            else if(cmd == "q"){
                string ans;
                printf("The program is running. Quit anyway (and kill it)? (y or n)\n");
                if(!getline(cin, ans)){
                    break;
                }
                if(ans.empty() || (ans != "y" && ans != "Y")){
                    continue;
                }
                else{
                    ptrace(PTRACE_DETACH, child, 0, 0);
                    kill(child, SIGKILL);
                    waitpid(child, &wait_status, 0);
                    break;
                }
            }
            else if(cmd == "n"){
                long out_val;
                bool temp_created = false;

                if(pending_id != 0){
                    lazy_stepover_helper(pending_id);
                    pending_id = 0;
                }
                ptrace(PTRACE_GETREGSET, child, NT_PRSTATUS, &iov);
                auto next_addr = regs.pc + 4;

                auto id_it = addr_to_id.find(next_addr);
                if (id_it == addr_to_id.end()) {
                    temp_created = true; 
                    uint64_t id = next_bp_id++;
                    breakpoints.emplace(id, BreakpointEntry(id, next_addr, child));
                    addr_to_id.emplace(next_addr, id);
                    id_it = addr_to_id.find(next_addr);
                }

                auto it = breakpoints.find(id_it->second);
                if (it != breakpoints.end()) {
                    it->second.bp.enable();
                }


                ptrace(PTRACE_CONT, child, 0,0);
                waitpid(child, &wait_status, 0);

                if(WIFSTOPPED(wait_status)){
                    if(watch_active){
                        if(!read_mem(child, watch_addr, &out_val)){
                        cerr << "mem couldn't be read.>" << endl;
                        continue;
                        }
                        if(out_val != watch_value){
                            printf("watchpoint hit at 0x%llu : old=0x%llu new=0x%llu", watch_addr, watch_value, out_val);
                            watch_value = out_val;
                        }
                    }
                }

                if (WIFSTOPPED(wait_status) && WSTOPSIG(wait_status) == SIGTRAP) {
                    ptrace(PTRACE_GETREGSET, child, NT_PRSTATUS, &iov);
                    handle_sigtrap(regs);

                    auto it = breakpoints.find(id_it->second);
                    if (it != breakpoints.end()) {
                        if(temp_created == true){
                            it->second.bp.disable();
                            addr_to_id.erase(it->second.addr);
                            breakpoints.erase(it);
                        }
                    }
                }

            }
            else if(cmd == "h"){
                cout << "Commands:\n";
                cout << "  b <addr|func>   set breakpoint\n";
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
            else if (cmd[0] == 'x'){
                int count = 1;

               if (cmd.size() > 2 && cmd[0] == 'x' && cmd[1] == '/') {
                    string count_str = cmd.substr(2);
                    bool bad = false;
                    for (char ch : count_str) {
                        if (ch < '0' || ch > '9') { bad = true; break; }
                    }
                    if (bad) {
                        cerr << "usage: x/<count> <addr>" << endl;
                        continue;
                    }
                    count = stoi(count_str);
                }

                uint64_t addr = 0;

                if (!parse_addr(arg, addr)) {
                    cerr << "usage: x/<count> <addr>" << endl;
                    continue;
                }

                for(int i = 0; i < count; i++){
                    uint64_t cur = addr + i * sizeof(long);
                    errno = 0;
                    long data = ptrace(PTRACE_PEEKDATA, child, cur, 0);
                    if(data == -1 && errno != 0){
                    std::cerr << "peekdata failed: " << strerror(errno) << "\n";
                    continue;   
                    }
                    printf("0x%llx: 0x%lx\n", (unsigned long long)cur, data);
                }
            }
            else if(cmd == "bt"){
                int depth = 0;

                ptrace(PTRACE_GETREGSET, child, NT_PRSTATUS, &iov);
                unsigned long long r29 = regs.regs[29];
                unsigned long long ret = regs.regs[30];

                printf("#0 pc: %llx frame0: %llx\n", (unsigned long long)regs.pc, (unsigned long long)ret);

                while(r29 != 0 && depth < max_depth){
                    depth++;
                    uint64_t prev_fp = ptrace(PTRACE_PEEKDATA, child, r29, 0);
                    ret = ptrace(PTRACE_PEEKDATA, child, r29+8, 0);

                    string name = parser.get_function_name(ret);
                    if(name != ""){
                         printf("#%d name: %s ret: %llx\n", depth, name.c_str(), (unsigned long long)ret);
                    }
                    else{
                        printf("#%d ret: %llx\n", depth, (unsigned long long)ret);
                    }
                   

                    r29 = prev_fp;

                }
            }
            else if(cmd == "disasm"){
                disassembler_ftype disasm_fn;
                uint64_t addr;
                ptrace(PTRACE_GETREGSET, child, NT_PRSTATUS, &iov);
                if(arg == ""){
                    addr = regs.pc;
                }
                else{
                    if (!parse_addr(arg, addr)) {
                    addr = parser.get_function_addr(arg);
                    if(addr == 0){
                    cerr << "usage: disasm [addr|func]" << endl;
                    continue;
                    }
                    }
                }
            
                disasm_fn = disassembler(bfd_arch_aarch64, false, bfd_mach_aarch64, nullptr);
                for(int i =0; i < 10; i++){
                    printf("0x%lx:  ", addr);
                    int size = disasm_fn(addr, &dinfo);
                    addr += size;


                    printf("\n");
                }
               
            }
            // watch <addr>
            else if (cmd == "watch"){

                long out_val;

                uint64_t addr = 0;

                if(arg == ""){
                    cerr << "usage: watch <addr>" << endl;
                    continue;
                }

                if (!parse_addr(arg, addr)) {
                    cerr << "usage: watch <addr>" << endl;
                    continue;
                }

                if(!read_mem(child, addr, &out_val)){
                    cerr << "mem couldn't be read.>" << endl;
                    continue;
                }

                watch_active = true;
                watch_addr = addr;
                watch_value = out_val;

                printf("watching 0x%llu (value: 0x%llu)", watch_addr, watch_value);

            }
            else if(cmd == "wc"){
                long out_val;

                if(!watch_active){
                    printf("No watchpoints set");
                    continue;
                }

                while(true){
                    ptrace(PTRACE_SINGLESTEP, child, 0, 0);
                    waitpid(child, &wait_status, 0);

                    if(WIFEXITED(wait_status)){
                        break;
                    }


                    if(!read_mem(child, watch_addr, &out_val)){
                        cerr << "mem couldn't be read.>" << endl;
                        break;
                    }

                    if(watch_value != out_val){
                        printf("Value changed");
                        watch_value = out_val;
                        break;
                    }

                }

            }
            else{
                std::cerr << "unknown command: " << cmd << "\n";
            }
        }
   
    }

    return 0;
}
