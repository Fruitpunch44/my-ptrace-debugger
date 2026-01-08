#ifndef MY_DBG_H
#define MY_DBG_H
#include<stdlib.h>
#include<unistd.h>
#include<stdio.h>
#include<stdint.h>
#include<sys/user.h>
#include<sys/wait.h>
#include<sys/types.h>
#include<sys/ptrace.h>
#include<sys/personality.h> //for disabling aslr
#include<errno.h>
#include<string.h>
#include<strings.h>
#include<capstone/capstone.h>
#include<inttypes.h>

extern break_point*break_point_list;


void list_registers(pid_t child);
void print_wait_status(int wait_status);
void set_break_point(pid_t child_proc,uint64_t address);
void load_program(const char *program);
void next_instruction(pid_t child_proc);
void modify_reg(pid_t child_proc,const char *reg,uint64_t value);
void continue_dgb(pid_t child_proc);
void get_current_rip(pid_t child_proc);
void dump_bytes(uint64_t data);
void modify_address(pid_t child_proc,uint64_t address,uint64_t value);
void dissassemble_instruction(pid_t child_proc,char *func_name);
void delete_break_point(pid_t child_proc,int postion);



#endif
