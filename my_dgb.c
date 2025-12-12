#include"break_points.h"
#include"my_dbg.h"

/*TODO
MODIFIY REGISTER/ADDRESS VALUE*/

//global break point List
break_point* break_point_list= NULL;

//do later i'm lazy
void modify_reg(pid_t child_proc,uint64_t reg,uint64_t value){
  struct user_regs_struct reg;
  if(ptrace(PTRACE_GETREGS,child_proc,NULL,&reg) <0){
    fprintf(stderr,"error in ptrace_getregs %s",strerror(errno));
    return;
  }
  switch(reg){
    case RAX:
      reg.rax = value;
      break;
    case RBX:
      reg.rbx = value;
      break;
    case RCX:
      reg.rcx = value;
      break;
    case RDX:
      reg.rdx = value;
      break;
    case RSI:
      reg.rsi = value;
      break;
    case RDI:
      reg.rdi = value;
      break;
    case RSP:
      reg.rsp = value;
      break;
    case RBP:
      reg.rbp = value;
      break;
    case RIP:
      reg.rip = value;
      break;
    default:
      fprintf(stderr,"unknown register %llx",reg);
      return;
  }
  if(ptrace(PTRACE_SETREGS,child_proc,NULL,&reg) <0){
    fprintf(stderr,"error in ptrace_setregs %s",strerror(errno));
    return;
  }
}

void print_wait_status(int status){
  if(WIFSTOPPED(status)){
    fprintf(stderr,"child stopped by signal %d\n",WSTOPSIG(status));
  }
  else if(WIFEXITED(status)){
    fprintf(stderr,"child exited with status %d\n",WEXITSTATUS(status));
  }
  else if(WIFSIGNALED(status)){
    fprintf(stderr,"child terminated due to uncaught signal %d\n",WTERMSIG(status));
  }
  else if(WCOREDUMP(status)){
    fprintf(stderr,"child produced core dump\n");
  }
  else{
    fprintf(stderr,"unexpected wait status %d\n",status);
  }
}

void load_program(const char *program){
  personality(ADDR_NO_RANDOMIZE); //disable aslr
  fprintf(stdout,"LOADING PROGRAM %s",program);
  if(ptrace(PTRACE_TRACEME,0,NULL,NULL)<0){
    fprintf(stderr,"error in ptrace_traceme\n");
    exit(EXIT_FAILURE);
  }
  execl(program,program,NULL);
}

void dissassemble_instruction(pid_t child_proc,char *func_name){
  int wait_status;
  pid_t dissasembly=fork();
  if(dissasembly ==0){
    char my_pid[20];
    sprintf(my_pid,"%d",child_proc);
    fprintf(stdout,"pid is %s",my_pid);
    char my_commands[100];
    snprintf(my_commands,sizeof(my_commands),"objdump --disassemble=%s /proc/%s/exe -M intel ",func_name,my_pid);
    //inacurate find a way to print out the current instruction only
    system(my_commands);
    exit(EXIT_SUCCESS);
  }
  else{
    waitpid(dissasembly,&wait_status,0);
  }
}

void set_break_point(pid_t child_proc,uint64_t address){
  uint64_t new_data;
  uint64_t INT3 = 0xcc;//signal to set break point
  uint64_t data = ptrace(PTRACE_PEEKDATA, child_proc,(void*)address,NULL);
  new_data = data;
  new_data = (data & ~0xff) | INT3;
  ptrace(PTRACE_POKEDATA,child_proc,(void*)address,new_data);
  fprintf(stdout,"setting break point at 0x%llx: 0x%llxx\n",address,data);
  add_breakpoint(&break_point_list,address,data);
}

void delete_break_point(pid_t child_proc,int postion){
  break_point *bp = break_point_list;
  for(int i =0; bp!=NULL && i<postion;i++){
  bp=bp->next;
  }
  if(bp==NULL){
    fprintf(stderr,"break point not found");
  }
  //remove int 3 signal
  if(ptreace(PTRACE_POKEDATA,child_proc,(void*)bp->address,bp->data) <0){
    fprintf(stderr,"error in restoring instruction %s",strerror(errno));
    return;
  }
  fprintf(stdout,"have removed break_point at %d at address 0x%llx",position,bp->address);
  delete_breakpoint_list(&break_point_list,position);
}

void next_instruction(pid_t child_proc){
  int wait_status;
  if(ptrace(PTRACE_SINGLESTEP,child_proc,NULL,NULL) < 0){
    fprintf(stderr,"error in single step %s",strerror(errno));
    exit(EXIT_FAILURE);
  }
  waitpid(child_proc,&wait_status,0);
}

//add continue
void continue(pid_t child_proc);

void dump_bytes(uint64_t data){
  unsigned char *bytes= (unsigned char*)&data;//always cast to unsigned char
  for(size_t i=0; i <sizeof(uint64_t);i++){
    if(i%16 ==0){
      fprintf(stdout,"\n%08lx: ",(unsigned long)i);
    }
    fprintf(stdout,"%02x",bytes[i]);
  }
  fprintf(stdout,"\n");
}

void get_current_rip(pid_t child_proc){
  struct user_regs_struct regs;
  if(ptrace(PTRACE_GETREGS,child_proc,NULL,&regs)<0){
    fprintf(stderr,"error in ptrace_getregs %s",strerror(errno));
    return;
  }
  uint64_t current_rip= regs.rip;
  fprintf(stdout,"rip is at -->0x%llx",current_rip);//debugging purposes

  errno=0;
  uint64_t data = ptrace(PTRACE_PEEKDATA,child_proc,(void*)current_rip,NULL);
  if (errno != 0) {
    fprintf(stderr,"error in ptrace_peekdata %s",strerror(errno));
    return;
  }
  fprintf(stdout,"Read 8 bytes at 0x%llx: %016lx\n",current_rip,data);
}

void list_registers(pid_t child_proc){
  struct user_regs_struct regs;
  if(ptrace(PTRACE_GETREGS,child_proc,NULL,&regs)<0){
    fprintf(stderr,"error in ptrace_getregs %s",strerror(errno));
  }
  fprintf(stdout,"REGISTERS");
  fprintf(stdout,"RAX : 0x%llxx\n  
                  RBX : 0X%llx\n, 
                  RCX : 0x%llx\n,
                  RSP : 0x%llx\n
                  RIP : 0x%llx\n
                  RSI : 0x%llx\n",
                  regs.rax,regs.rbx,regs.rcx,regs.rsp,regs.rip,regs.rsi);
}

int main(int argc, char *argv[])
{
  const char *program = argv[2];
  int wait_status;
  char commands[212];

  //check for file existence
  if(access(program,F_OK) == 0 && access(program,R_OK)==0){
    fprintf(stdout,"the program exists %s\n",program);
  }
  else{
    fprintf(stdout,"file does not exists %s\n",program);
  }

  if(argc < 2){
    fprintf(stderr,"not enough arguments\n",argv[1]);
    exit(EXIT_FAILURE);
  }
  pid_t child;
  child=fork();
  if(child == 0){
    load_program(program);
  }
  else{
    waitpid(child,&wait_status,0);
    print_wait_status(wait_status);
  }
  while(1){

    fprintf(stdout,"my_dbg> ");
    fgets(commands,sizeof(commands),stdin);
    commands[strcspn(commands,"\n")] = 0;//remove newline character

    if(strncmp(commands,"break",strlen("break")) == 0){
      char address_str[20];
      fprintf(stdout,"enter address to set break point: ");
      fgets(address_str,sizeof(address_str),stdin);
      uint64_t address = strtoull(address_str,NULL,16);//convert string to uint64_t
      set_break_point(child,address);
    }
    else if(strncmp(commands,"continue",strlen("continue")) == 0){
      if(ptrace(PTRACE_CONT,child,NULL,NULL)<0){
        fprintf(stderr,"error in ptrace_cont %s",strerror(errno));
        exit(EXIT_FAILURE);
      }
      //turn this to a function later
      waitpid(child,&wait_status,0);
      print_wait_status(wait_status);
    }
    else if(strncmp(commands,"step",strlen("step")) == 0){
      next_instruction(child);
    }
    else if(strncmp(commands,"registers",strlen("registers")) == 0){
      list_registers(child);
    }
    else if(strncmp(commands,"disassemble",strlen("disassemble")) == 0){
      char func[64];
      fprintf(stdout,"enter the func you want to disassemble: ");
      fgets(func,sizeof(func),stdin);
      func[strcspn(func,"\n")] =0;
      dissassemble_instruction(child,func);
    }
    else if(strncmp(commands,"list b",strlen("list b"))==0){
      print_break_point(&break_point_list);
    }
    else if(strncmp(commands,"exit",strlen("exit"))==0){
      fprintf(stdout,"exiting debugger\n");
      exit(EXIT_SUCCESS);
    }
    else if(strncmp(commands,"delete b",strlen("delete b"))==0){
      char position_str[10];
      print_break_points(&break_point_list);
      fprintf(stdout,"enter break point position to delete: ");
      fgets(position_str,sizeof(position_str),stdin);
      position_str[strcspn(position_str,"\n")];
      int position = atoi(position_str);
      delete_break_point(child,position);
    }
    else{
      fprintf(stdout,"unknown command %s",commands);
    }
    
  }
  return 0;
}
