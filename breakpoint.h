#include <unistd.h>
#include <cstdint>

class BreakPoint {
    private:
        bool state; // enabled or disabled
        uint64_t orig_instruction;
        uint64_t addr;
        pid_t pid;

    public:
        BreakPoint(uint64_t addr, pid_t pid);
        bool get_state() const;
        uint64_t get_instr() const;
        uint64_t get_addr() const;
        pid_t get_pid() const;

        void enable();
        void disable();
        bool is_enabled() const;
};