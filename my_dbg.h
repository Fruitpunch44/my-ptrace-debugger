#ifndef MY_DBG_H
#define MY_DBG_H
#include<stdlib.h>
#include<unistd.h>
#include<stdio.h>
#include<sys/user.h>
#include<sys/wait.h>
#include<sys/types.h>
#include<sys/ptrace.h>
#include<sys/personality.h> //for disabling aslr
#include<errno.h>
#include<string.h>


void list_registers(pid_t child);
void print_wait_status(int wait_status);
void set_break_point(pid_t child_proc,uint64_t address);
void load_program(const char *program);
void next_instruction(pid_t child_proc);
void modify_reg(pid_t child_proc,const char *reg,uint64_t value)
void dump_memory(pid_t child_proc,uint64_t address, uint64_t length);
void dissassemble_instruction(pid_t child_proc,char *func_name);



#endif
