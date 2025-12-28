#include <unordered_map>
#include <string>
#include <elf.h>
#include <libdwarf/libdwarf.h>
#include <DWARF_parser.h>
#include <fcntl.h>
#include <unistd.h>

DwarfParser:: DwarfParser() {
    file_id = -1;
    pointer = nullptr;
    hash_map.clear();
}

void DwarfParser::load_symbols(const char* binary_path) {
    Dwarf_Error error;
    Dwarf_Unsigned cu_header_length;
    Dwarf_Half version_stamp;
    Dwarf_Off abbrev_offset;
    Dwarf_Half address_size;
    Dwarf_Unsigned next_cu_header_offset;

    file_id = open(binary_path, O_RDONLY);
    dwarf_init(file_id, DW_DLC_READ, nullptr, nullptr, &pointer, &error);
    while(dwarf_next_cu_header(pointer, &cu_header_length, &version_stamp, &abbrev_offset, &address_size, &next_cu_header_offset, &error)){
        Dwarf_Die return_siblingdie;
        int cu_die = dwarf_siblingof(pointer, nullptr, &return_siblingdie, &error);
        parse_compilation_unit(return_siblingdie);
    
    }
}   


