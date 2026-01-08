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
    char *short_hand;
    command_func func;//function pointer for the commands
    char *doc;//documentation
}COMMANDS;

//varous commands supported by the debugger
extern COMMANDS various_commands[];

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
void help_command(char *args, pid_t child_proc);
void handle_enter(char *args, pid_t child_proc);
void modify_addr_command(char *args,pid_t child_proc);


#endif