#ifndef COMMAND_H
#define COMMAND_H

#include<string.h>
#include<unistd.h>
#include<stdlib.h>
#include<stdio.h>
#include"my_dbg.h"
#include <readline/readline.h>
#include <readline/history.h>

//function pointer type for commands
typedef void(*command_func)(char *args, pid_t child_proc);

typedef struct commands{
    char *name;//command name
    command_func func;//function pointer for the commands
    char *doc;//documentation
}COMMANDS;

//varous commands supported by the debugger
COMMANDS various_commands[] = {
    {"break", breakpoint_command, "Set a breakpoint at a specified address."},
    {"continue", continue_command, "Continue execution until the next breakpoint."},
    {"step", step_command, "Execute the next instruction."},
    {"registers", registers_command, "List the current values of CPU registers."},
    {"disassemble", disassemble_command, "Disassemble a function by name."},
    {"list b", list_b_command, "List all current breakpoints."},
    {"delete b", delete_b_command, "Delete a breakpoint by its position."},
    {"rip", rip_command, "Get the current RIP instruction pointer."},
    {"modify reg", modify_reg_command, "Modify the value of a specified register."},
    {"exit", exit_command, "Exit the debugger."},
    {NULL, NULL}
};

void breakpoint_command(char *args, pid_t child_proc);
void continue_command(char *args, pid_t child_proc);
void step_command(char *args, pid_t child_proc);
void registers_command(char *args, pid_t child_proc);
void disassemble_command(char *args, pid_t child_proc);
void list_b_command(char *args, pid_t child_proc);
void delete_b_command(char *args, pid_t child_proc);
void rip_command(char *args, pid_t child_proc);
void modify_reg_command(char *args, pid_t child_proc);
void exit_command(char *args, pid_t child_proc);    


#endif