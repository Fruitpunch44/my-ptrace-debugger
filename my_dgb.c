#include"break_points.h"
#include"my_dbg.h"
//do later i'm lazy
void modify_reg(pid_t child_proc,uint64_t reg,uint64_t value);

void load_program(pid_t child_proc,const char *program){
  fprintf(stdout,"LOADING PROGRAM %s",program);
  if(ptrace(PTRACE_TRACEME,0,NULL,NULL)<0){
    fprintf(stderr,"error in ptrace_traceme\n");
    exit(EXIT_FAILURE);
  }
  execl(program,program,NULL);
}

void set_break_point(pid_t child_proc,uint64_t address){
  uint64_t new_data;
  uint64_t INT3 = 0xcc;//signal to set break point
  uint64_t data = ptrace(PTRACE_PEEKDATA, child_proc,(void*)address,NULL);
  new_data = data;
  new_data = (data & ~0xff) | INT3;
  ptrace(PTRACE_POKEDATA,child_proc,(void*)address,new_data);
  fprintf(stdout,"setting break point at 0x%llx: 0x%llxx\n",address,data);
  add_breakpoint(address,data);
}

void next_instruction(pid_t child_proc){
  int wait_status;
  if(ptrace(PTRACE_SINGLESTEP,child_proc,NULL,NULL) < 0){
    fprintf(stderr,"error in single step %s",strerror(errno));
    exit(EXIT_FAILURE);
  }
  waitpid(child_proc,&wait_status,0);
}

void list_registers(pid_t child){
  struct user_regs_struct.regs;
  if(ptrace(PTRACE_GETREGS,child,NULL,&reg)<0){
    fprintf(stderr,"error in ptrace_getregs %s",strerror(errno));
  }
  fprintf(stdout,"REGISTERS");
  fprintf(stdout,"RAX : 0x%llxx\n  RBX : 0X%llx\n, RCX : 0x%llx\n",regs.rax,regs.rbx,regs.rcx);
}

int main(int argc, char *argv[])
{
  const char *program = argv[2];
  int wait_status;

  //check for file existence
  if(access(program,F_OK) == 0 || aceess(program,R_OK)==0){
    fprintf(stdout,"the program exists %s",program);
  }
  fprintf(stdout,"file does not exists %s",program);

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
    //check if the child process exited nornmally
    if(WIFEXITED(wait_status)){
      fprintf(stdout,"child exited\n")
      break;
    }
  }


}
