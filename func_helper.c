#include"func_helpr.h"


func_array init_dynamic_func_array(){
    func_array *arr;
    arr->functions = NULL;
    arr->count =0;
    arr->capacity =0;
    return *arr;
}
void add_array(func_array *arr,func_info *functions){
    if(arr->count == arr->capacity){
        size_t new_cap = arr->capacity *=2;
        func_info *temp;
        temp=realloc(arr->functions,arr->capacity* sizeof(func_info));
        if(!temp){
            fprintf(stderr,"realloc failed\n");
            exit(EXIT_FAILURE);
        }
        arr->functions=temp;
        arr->capacity=new_cap;
    }
    arr->functions[arr->count++]=*functions;
}

void free_array(func_array *arr){
    free(arr->functions);
    arr->functions=NULL;
    arr->capacity=0;
    arr->capacity=0;
}

func_array search_for_func(func_array *arr,char *item){
    for(size_t i = 0;i<arr->count;i++){
        if(strcmp(arr->functions[i].name,item)==0){
            printf("Function %s found at address 0x%llx with size %llu\n",arr->functions[i].name,arr->functions[i].address,arr->functions[i].size);
            return *arr;
        }
    }
    fprintf(stderr,"function %s not found\n",item);
}