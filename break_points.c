#include"break_points.h"

break_point* create_breakpoint_list(uint64_t address,uint64_t data){
  break_point* new_break_point= malloc(sizeof(break_point));
  if(!new_break_point){
    fprintf(stderr,"unable to allocate space");
    exit(EXIT_FAILURE);
  }
  new_break_point->address=address;
  new_break_point->data =data;
  new_break_point->next = NULL;
  return new_break_point;
}

//insert to the break_point_list
void add_breakpoint(break_point** head, uint64_t address,uint64_t data){
  break_point* new_entry= create_breakpoint_list(address,data);
  if(*head == NULL){
    *head = new_entry;
    return;
  }
  break_point* temp = *head;
  while(temp->next !=NULL){
    temp = temp -> next;
  }
  temp->next = new_entry;
}

break_point* find_breakpoint(break_point* head ,uint64_t address){
  break_point *temp =head;
  while(temp !=NULL){
    if(temp->address ==address){
      return temp;
    }
    temp =temp->next;
  }
  return NULL;
}

void print_break_points(break_point* head){
  break_point* temp = head;
  int number = 0;//index the entries 
  while(temp != NULL){
    fprintf(stdout,"[%d]: address--> %llx  value--> %llx\n",number,temp->address,temp->data);
    temp = temp->next;
    number++;
  }
  printf("No breakpoint entry\n");
  return;
}
void delete_breakpoint_list(break_point** head,int position){
  if(*head ==NULL){
    fprintf(stderr,"empty lis");
    return;
  }
  break_point* temp= *head;
  if(position == 0){
    *head = temp->next;
    fprintf(stdout,"have removed break point at point %d",position);
    free(temp);
    return;
  }

  for(int i=0 ;temp!=NULL && i<position-1;i++){
    temp=temp->next;
  }
  if(temp == NULL ||temp->next ==NULL){
    fprintf(stderr,"out of range");
    return;
  }
  break_point *next= temp->next->next;
  free(temp->next);
  temp->next=next;
  fprintf(stdout,"have removed break point %d",position);

}