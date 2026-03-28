#include <unordered_map>
#include <string>
#include <elf.h>
#include <libdwarf/libdwarf.h>

using namespace std;

class DwarfParser {

    unordered_map<string, uint64_t> hash_map;
    unordered_map<uint64_t, string> addr_to_name;
    int file_id;
    Dwarf_Debug pointer;

    public:
        DwarfParser();
        void load_symbols(const char* binary_path);
        uint64_t get_function_addr(string func_name);
        string get_function_name(uint64_t addr);

    private:
        void parse_compilation_unit(Dwarf_Die cu_die);
        void check_die(Dwarf_Die current_die);

};