#include"break_points.h"
#include"my_dbg.h"

//global break point List
break_point* break_point_list= NULL;

//do later i'm lazy
void modify_reg(pid_t child_proc,uint64_t reg,uint64_t value);

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
  fprintf(stdout,"LOADING PROGRAM %s",program);
  if(ptrace(PTRACE_TRACEME,0,NULL,NULL)<0){
    fprintf(stderr,"error in ptrace_traceme\n");
    exit(EXIT_FAILURE);
  }
  execl(program,program,NULL);
}

void dissassemble_instruction(pid_t child_proc){
  int wait_status;
  pid_t dissasembly=fork();
  waitpid(dissasembly,&wait_status,0);
  if(dissasembly ==0){
    char *my_pid;
    sprintf(my_pid,%d,child_proc);
    fprintf(stdout,"pid is %s",my_pid);
    const char my_commands[100];
    snprintf(my_commands,sizeof(my_commands),"objdump -d /proc/%s/exe -M Intel | grep -A 20 '<main>:'",my_pid);
    execl(my_commands,my_commands,NULL);
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

void next_instruction(pid_t child_proc){
  int wait_status;
  if(ptrace(PTRACE_SINGLESTEP,child_proc,NULL,NULL) < 0){
    fprintf(stderr,"error in single step %s",strerror(errno));
    exit(EXIT_FAILURE);
  }
  waitpid(child_proc,&wait_status,0);
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
  char *commands[212];

  //check for file existence
  if(access(program,F_OK) == 0 && access(program,R_OK)==0){
    fprintf(stdout,"the program exists %s",program);
  }
  else{
    fprintf(stdout,"file does not exists %s",program);
  }

  if(argc < 3){
    fprintf(stderr,"not enough arguments",argv[2]);
    exit(EXIT_FAILURE);
  }
  pid_t child;
  child=fork();
  if(child == 0){
    load_program(program);
  }
  while(1){
    waitpid(child,&wait_status,0);
    print_wait_status(wait_status);
  
    }
    
  }


}
