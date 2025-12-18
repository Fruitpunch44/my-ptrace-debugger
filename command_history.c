#include"command_history.h"
#include"my_dbg.h"
#include"break_points.h"
//no idea if this will work but we'll see
//push and test later lol

COMMANDS various_commands[] = {
    {"break", breakpoint_command, "Set a breakpoint at a specified address."},
    {"continue", continue_command, "Continue execution until the next breakpoint."},
    {"step", step_command, "Execute the next instruction."},
    {"registers", registers_command, "List the current values of CPU registers."},
    {"disassemble", disassemble_command, "Disassemble a function by name."},
    {"list", list_b_command, "List all current breakpoints."},
    {"delete", delete_b_command, "Delete a breakpoint by its position."},
    {"rip", rip_command, "Get the current RIP instruction pointer."},
    {"modify reg", modify_reg_command, "Modify the value of a specified register."},
    {"exit", exit_command, "Exit the debugger."},
    {NULL, NULL}
};

void breakpoint_command(char *args, pid_t child_proc){
    if(args == NULL){
      fprintf(stderr,"no address provided for breakpoint\n");
      return;
    }
    args[strcspn(args,"\n")] =0;//remove newline if any
    uint64_t address = strtoull(args,NULL,16);
    set_break_point(child_proc,address);
    }
void continue_command(char *args, pid_t child_proc){
    if(args != NULL){
      fprintf(stderr,"continue command does not take arguments\n");
      return;
    }
    continue_dgb(child_proc);
}
void step_command(char *args, pid_t child_proc){
    if(args != NULL){
      fprintf(stderr,"step command does not take arguments\n");
      return;
    }
    next_instruction(child_proc);
}
void registers_command(char *args, pid_t child_proc){
    if(args != NULL){
      fprintf(stderr,"registers command does not take arguments\n");
      return;
    }
     args[strcspn(args,"\n")] =0;//remove newline if any
    list_registers(child_proc);
}
void disassemble_command(char *args, pid_t child_proc){
    if(args == NULL){
      fprintf(stderr,"no function name provided for disassemble\n");
      return;
    }
    args[strcspn(args,"\n")] =0;//remove newline if any
    char *func_name = strtok(args," ");
    disassemble_instruction(child_proc,func_name);
}
void list_b_command(char *args, pid_t child_proc){
    if(args != NULL){
      fprintf(stderr,"list b command does not take arguments\n");
      return;
    }
    args[strcspn(args,"\n")] =0;//remove newline if any
    print_break_points();
}
void delete_b_command(char *args, pid_t child_proc){
    if(args == NULL){
      fprintf(stderr,"no position provided for delete b\n");
      return;
    }
    args[strcspn(args,"\n")] =0;//remove newline if any
    int position = atoi(args);
    delete_break_point(child_proc,position);
}
void rip_command(char *args, pid_t child_proc){
    if(args != NULL){
      fprintf(stderr,"rip command does not take arguments\n");
      return;
    }
    get_current_rip(child_proc);
}
void modify_reg_command(char *args, pid_t child_proc){
    if(args == NULL){
      fprintf(stderr,"no arguments provided for modify reg\n");
      return;
    }
    args[strcspn(args,"\n")] =0;//remove newline if any
    char *reg = strtok(args," ");
    char *value_str = strtok(NULL," ");
    if(reg == NULL || value_str == NULL){
      fprintf(stderr,"insufficent arguments for this function\n");
      return;
    }
    uint64_t value = strtoull(value_str,NULL,16);
    modify_reg(child_proc,reg,value);
}
void exit_command(char *args, pid_t child_proc){
    if(args != NULL){
      fprintf(stderr,"exit command does not take arguments\n");
      return;
    }
    exit(EXIT_SUCCESS);
}