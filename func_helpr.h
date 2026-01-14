#ifndef FUNC_HELPR_H
#define FUNC_HELPR_H

#include"parse_elf_info.h"

//create a struct to hold function info later
typedef struct function_info {
    char *name;
    uint64_t address;
    uint64_t size;
} func_info;


//dynamic array to hold function info structs
typedef struct array_func{
    func_info *functions;//the struct items
    size_t count; //number of struct objects
    size_t capacity; //how much mem we allocated
}func_array;


func_array create_func_array();
void add_array(func_array *arr,func_info *functions);
func_array search_for_func(func_array *arr,char *item);


#endif