#ifndef BREAK_POINTS_H
#define BREAK_POINTS_H
#include<stdint.h>
#include<unistd.h>
#include<stdio.h>
#include<stdlib.h>

typedef struct breakpoints{
    uint64_t address;
    uint64_t data;
    struct breakpoints* next;
}break_point;

break_point* create_breakpoint_list(uint64_t address,uint64_t data);
void add_breakpoint(break_point** head, uint64_t address,uint64_t data);
void print_break_points(break_point* head);
void delete_breakpoint_list(break_point** head,int position);


#endif