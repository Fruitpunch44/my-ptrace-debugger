#include "parse_elf_info.h"
#include "my_dbg.h"
#include "func_helpr.h"



 func_array do_something(const char *program){
    func_array my_funcs = create_func_array();
    ElfW(Ehdr) elf_header;
    FILE *elf_file;
    elf_file =fopen(program,"rb");
    if(!elf_file){
        fprintf(stderr,"error in reading file");
        exit(EXIT_FAILURE);
    }
    // Read ELF header
    if (fread(&elf_header, sizeof(elf_header), 1, elf_file) != 1) {
        perror("failed to read ELF header");
        exit(EXIT_FAILURE);
    }
    fseek(elf_file, elf_header.e_shoff, SEEK_SET);

    // Read section headers
    ElfW(Shdr) *section_headers = malloc(sizeof(ElfW(Shdr)) * elf_header.e_shnum);
    if (!section_headers) {
        perror("unable to allocate memory for section headers");
        exit(EXIT_FAILURE);
    }
    fread(section_headers, sizeof(ElfW(Shdr)), elf_header.e_shnum, elf_file);

    // Read section header string table
    ElfW(Shdr) *shstrtab_hdr = &section_headers[elf_header.e_shstrndx];
    char *shstrtab = malloc(shstrtab_hdr->sh_size);
    if (!shstrtab) {
        perror("unable to allocate memory for shstrtab");
        exit(EXIT_FAILURE);
    }
    fseek(elf_file, shstrtab_hdr->sh_offset, SEEK_SET);
    fread(shstrtab, shstrtab_hdr->sh_size, 1, elf_file);

    // Locate .text, .symtab, .strtab
    ElfW(Shdr) *text_section = NULL;
    ElfW(Shdr) *symtab_hdr = NULL;
    ElfW(Shdr) *strtab_hdr = NULL;
    for (int i = 0; i < elf_header.e_shnum; i++) {
        const char *section_name = shstrtab + section_headers[i].sh_name;
        if (strcmp(section_name, ".text") == 0) {
            text_section = &section_headers[i];
        } else if (strcmp(section_name, ".symtab") == 0) {
            symtab_hdr = &section_headers[i];
        } else if (strcmp(section_name, ".strtab") == 0) {
            strtab_hdr = &section_headers[i];
        }
    }
    if (!text_section) {
        fprintf(stderr, " .text section not found\n");
        exit(EXIT_FAILURE);
    }
    if (!symtab_hdr || !strtab_hdr) {
        fprintf(stderr, "symbol table or string table not found\n");
        exit(EXIT_FAILURE);
    }

    // Read .text section
    char *text_data = malloc(text_section->sh_size);
    if (!text_data) {
        fprintf(stderr,"unable to allocate memory for %s section",text_section);
        exit(EXIT_FAILURE);
    }
    fseek(elf_file, text_section->sh_offset, SEEK_SET);
    fread(text_data, text_section->sh_size, 1,elf_file);

    //read symbols
    int num_sym =symtab_hdr->sh_size/sizeof(ElfW(Sym));
    ElfW(Sym) *symbols = malloc(symtab_hdr->sh_size);
    if(!symbols){
        perror("unable to allocate memory for symbols");
        exit(EXIT_FAILURE);
    }
    fseek(elf_file,symtab_hdr->sh_offset,SEEK_SET);
    fread(symbols,sizeof(ElfW(Sym)),num_sym,elf_file);

    //read symbol table
    char *strtab = malloc(strtab_hdr->sh_size);
    if(!strtab){
        perror("unable to allocate memory for strtab");
        exit(EXIT_FAILURE);
    }
    fseek(elf_file,strtab_hdr->sh_offset,SEEK_SET);
    fread(strtab,strtab_hdr->sh_size,1,elf_file);
    func_info *func_info=malloc(sizeof(func_info));
    if(!func_info){
        fprintf(stderr,"unable to allocate memory for function info");
        exit(EXIT_FAILURE);
    }
    int found_func = 0;
    for(int i =0;i<num_sym;i++){
        if (ELF32_ST_TYPE(symbols[i].st_info) == STT_FUNC &&
            symbols[i].st_size > 0){
            const char *func_name = strtab + symbols[i].st_name;
            fprintf(stdout,"Function found: %s at address 0x%lx with size %lu\n",func_name,symbols[i].st_value,symbols[i].st_size);
            //get function name for later use in disassembly
            //stick with objdump for now
            func_info->name = strdup(func_name);
            func_info->address = symbols[i].st_value;
            func_info->size =symbols[i].st_size;
            add_array(&my_funcs,func_info);
            found_func = 1;
            }
    }
    if(!found_func){
        fprintf(stdout,"no func found \n");
    }
    free(func_info);
    free(text_data);
    free(symbols);
    free(strtab);
    free(shstrtab);
    free(section_headers);
    return my_funcs;
}


