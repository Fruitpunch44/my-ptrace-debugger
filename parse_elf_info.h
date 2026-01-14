#ifndef ELF_INFO_H
#define ELF_INFO_H

#include<elf.h>
#include<stdio.h>
#include<string.h>
#include<stdlib.h>
#include"func_helpr.h"
extern const char *program; 

//check the system type if it's 64 bit
//if not use 32 bit

#if defined(__LP64__)
#define ElfW(type) Elf64_ ## type
#else
#define ElfW(type) Elf32_ ## type
#endif


func_array do_something(const char *program);
#endif