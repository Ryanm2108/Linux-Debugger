#include <iostream>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <elf.h>
#include <sys/uio.h>

using namespace std;


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
        while(!WIFEXITED(wait_status)){
            struct user_regs_struct regs;

            struct iovec iov;
            iov.iov_base = &regs;
            iov.iov_len = sizeof(regs);

            ptrace(PTRACE_GETREGSET, child, NT_PRSTATUS, &iov);

            printf("PC: %llx\n", regs.pc);

            unsigned long long current_pc = regs.pc;

            long instruction = ptrace(PTRACE_PEEKTEXT, child, current_pc, 0);

            printf("Instruction at 0x%llx: 0x%lx\n", current_pc, instruction);

            unsigned long data_with_trap = (instruction & 0xFFFFFFFF00000000) | 0xd4200000;

            ptrace(PTRACE_POKETEXT, child, current_pc, data_with_trap);

            

            ptrace(PTRACE_CONT, child, 0,0);   
            waitpid(child, &wait_status, 0);
        }

    
        
    }

    return 0;
}