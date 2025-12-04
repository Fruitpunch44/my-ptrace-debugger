#ifndef MY_DBG_H
#define MY_DBG_H
#include<stdlib.h>
#include<unistd.h>
#include<stdio.h>
#include<sys/user.h>
#include<sys/wait.h>
#include<sys/types.h>
#include<sys/ptrace.h>
#include<errno.h>
#include<string.h>

void list_registers(pid_t child);
void set_break_point(pid_t child_proc,uint64_t address);
void load_program(pid_t child_proc,const char *program);
void next_instruction(pid_t child_proc);
void modify_reg(pid_t child_proc,uint64_t reg,uint64_t value);





#endif
