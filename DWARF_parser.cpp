#include <unordered_map>
#include <string>
#include <elf.h>
#include <libdwarf/libdwarf.h>
#include <libdwarf/dwarf.h>
#include <DWARF_parser.h>
#include <fcntl.h>
#include <unistd.h>

DwarfParser:: DwarfParser() {
    file_id = -1;
    pointer = nullptr;
    hash_map.clear();
    addr_to_name.clear();
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


void DwarfParser::parse_compilation_unit(Dwarf_Die cu_die) {
    check_die(cu_die);
}

void DwarfParser::check_die(Dwarf_Die current_die){

    Dwarf_Error error;
    Dwarf_Half tag = 0;

    if(dwarf_tag(current_die, &tag, &error) != DW_DLV_OK){
    return;
    }

    if(tag == DW_TAG_subprogram){
        char* name = nullptr;
        Dwarf_Addr low_pc = 0;

        if (dwarf_diename(current_die, &name, &error) == DW_DLV_OK &&
            dwarf_lowpc(current_die, &low_pc, &error) == DW_DLV_OK) {
            hash_map[name] = static_cast<uint64_t>(low_pc);
            addr_to_name[static_cast<uint64_t>(low_pc)] = name;
        }
    }

    Dwarf_Die child = nullptr;
    if (dwarf_child(current_die, &child, &error) == DW_DLV_OK) {
        check_die(child);
    }

     Dwarf_Die sibling = child;
        while (dwarf_siblingof(pointer, sibling, &sibling, &error) == DW_DLV_OK) {
            check_die(sibling);
        }
    

}

uint64_t DwarfParser::get_function_addr(string func_name){

    auto it = hash_map.find(func_name);

    if(it == hash_map.end()){
        return 0;
    }

    return it->second;
}

string DwarfParser::get_function_name(uint64_t addr){

    auto it = addr_to_name.find(addr);

    if(it == addr_to_name.end()){
        return "";
    }

    return it->second;
}

