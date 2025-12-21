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

        string line;
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

            struct user_regs_struct regs;

                struct iovec iov;
                iov.iov_base = &regs;
                iov.iov_len = sizeof(regs);

                ptrace(PTRACE_GETREGSET, child, NT_PRSTATUS, &iov);

            if(cmd == "b"){
                // still have to implement addr functionality
                unsigned long long current_pc = regs.pc;

                long orig_instruction = ptrace(PTRACE_PEEKTEXT, child, current_pc, 0);

                unsigned long data_with_trap = (orig_instruction & 0xFFFFFFFF00000000) | 0xd4200000;

                ptrace(PTRACE_POKETEXT, child, current_pc, data_with_trap);
                ptrace(PTRACE_CONT, child, 0,0);
                waitpid(child, &wait_status, 0);

                    if(WIFSTOPPED(wait_status) && WSTOPSIG(wait_status)==SIGTRAP){
                        ptrace(PTRACE_GETREGSET, child, NT_PRSTATUS, &iov);
                        regs.pc -= 4;
                        ptrace(PTRACE_SETREGSET, child,  NT_PRSTATUS, &iov);

                        ptrace(PTRACE_POKETEXT, child, current_pc, orig_instruction);

                        ptrace(PTRACE_SINGLESTEP, child, 0, 0);
                        waitpid(child, &wait_status, 0);

                        ptrace(PTRACE_POKETEXT, child, current_pc, data_with_trap);
                        ptrace(PTRACE_CONT, child, 0,0);
                        waitpid(child, &wait_status, 0);
                        
                    }
                    else{
                        ptrace(PTRACE_CONT,child, 0, WSTOPSIG(wait_status));
                    }
            
            }
            else if(cmd == "c"){
                ptrace(PTRACE_CONT, child, 0,0);
            }
            else if(cmd == "s"){
                ptrace(PTRACE_SINGLESTEP, child, 0, 0);
            }
            else if(cmd == "regs"){ 

                printf("PC: %llx\n", regs.pc);
            }
            else if(cmd == "q"){
                // im not sure how to exit
            }
            else{
                // read mem( i didnt know what to check user_input with so I made it the else)
                ptrace(PTRACE_PEEKDATA, child, <addr>, 0);
                // <addr> refers to the address at which mem is to be read from. it's passed in as an arg.
                // yet to be fixed
            }
        }
   
    }

    return 0;
}