#include"break_points.h"
#include"my_dbg.h"
#include"command_history.h"
#include"parse_elf_info.h"

/*TODO
MODIFIY REGISTER/ADDRESS VALUE
add function to help parse hex values to string
add a way to handle pie executables
add a way to parse the function name from the elf header for disassembly 
with capstone
add tui(ncurses) have never used it should be fun*/
break_point* break_point_list =NULL;

//do later i'm lazy
void modify_reg(pid_t child_proc,const char *reg,uint64_t value){
  struct user_regs_struct reg;
  if(ptrace(PTRACE_GETREGS,child_proc,NULL,&reg) <0){
    fprintf(stderr,"error in ptrace_getregs %s",strerror(errno));
    return;
  }
  if(strncmp(reg,"rip",strlen("rip")) ==0){
    reg.rip = value;
  }
  else if(strncmp(reg,"rax",strlen("rax")) ==0){
    reg.rax = value;
  }
  else if(strncmp(reg,"rbx",strlen("rbx")) ==0){
    reg.rbx = value;
  }
  else if(strncmp(reg,"rcx",strlen("rcx")) ==0){
    reg.rcx = value;
  }
  else if(strncmp(reg,"rdx",strlen("rdx")) ==0){
    reg.rdx = value;
  }
  else{
    fprintf(stderr,"unknown register %s",reg);
    return;
  }
  if(ptrace(PTRACE_SETREGS,child_proc,NULL,&reg) <0){
    fprintf(stderr,"error in ptrace_setregs %s",strerror(errno));
    return;
  }
}

void modify_address(pid_t child_proc,uint64_t address,uint64_t value){
  if(ptrace(PTRACE_POKEDATA,child_proc,(void*)address,value) <0){
    fprintf(stderr,"error in ptrace_pokedata %s",strerror(errno));
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
  if(personality(ADDR_NO_RANDOMIZE)<0){
    fprintf(stderr,"error in disabling aslr %s",strerror(errno));
    exit(EXIT_FAILURE);
  } //disable aslr
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

/*
void dissassemble_instruction2(pid_t child_proc,char *func){
  int wait_status;
  char text_data[400];
  pid_t disassemble= fork();
  if(disassemble == 0){
    //try to get the bytes at the function address
    for(size_t i=0 ;i <sizeof(text_data);i++){
      text_data[i]= (char)ptrace(PTRACE_PEEKDATA,child_proc,(void*)(func + i),NULL);
    }
    csh handle;
    cs_insn *insn;
    size_t count;
    if(cs_open(CS_ARCH_X86,CS_MODE_64,&handle) != CS_ERR_OK){
      fprintf(stderr,"error in capstone open");
      exit(EXIT_FAILURE);
    }
    count = cs_disasm(handle,(uint8_t*)text_data,sizeof(text_data),(uint64_t)func,0,&insn);
    if(count >0){
      for(size_t j=0;j <count;j++){
        printf("0x%"PRIx64":\t%s\t%s\n",insn[j].address,insn[j].mnemonic,insn[j].op_str);
      }
      cs_free(insn,count);
    }
    else{
      fprintf(stderr,"failed to disassemble given code!\n");
    }
  }
}
  does not work yet but the logic maybe correct lol
  have to figure out a way to get the func address from the elf file
  use the objdump for now
 */

void set_break_point(pid_t child_proc,uint64_t address){
  uint64_t new_data;
  uint64_t INT3 = 0xcc;//signal to set break point
  uint64_t data = ptrace(PTRACE_PEEKDATA, child_proc,(void*)address,NULL);
  new_data = data;
  new_data = (data & ~0xff) | INT3;
  if(ptrace(PTRACE_POKEDATA,child_proc,(void*)address,new_data) <0){
    fprintf(stderr,"error in setting break point %s",strerror(errno));
    return;
  }
  fprintf(stdout,"setting break point at 0x%llx: 0x%llx\n",address,data);
  add_breakpoint(&break_point_list,address,data);
}

void reinsert_break_point(pid_t child_proc,break_point* bp){
  uint64_t data_with_INT3 = (bp->data & ~0xff) | 0xcc;//signal to set break point
  if(ptrace(PTRACE_POKEDATA,child_proc,(void*)bp->address,data_with_INT3) <0){
    fprintf(stderr,"error in restoring instruction %s",strerror(errno));
    return;
  }
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
  if(ptrace(PTRACE_POKEDATA,child_proc,(void*)bp->address,bp->data) <0){
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

//add contine func 
//omo this was a lot
void continue_dgb(pid_t child_proc){
  int wait_status;
  uint64_t address_rewind;
  struct user_regs_struct reg;
  if(ptrace(PTRACE_CONT,child_proc,NULL,NULL)<0){
    fprintf(stderr,"error in ptrace_cont %s",strerror(errno));
    exit(EXIT_FAILURE);
  }
  waitpid(child_proc,&wait_status,0);
  //check when a breakpoint is hit and when it returns a sigtrap
  if(WIFSTOPPED(wait_status)&& WSTOPSIG(wait_status)==SIGTRAP){
    if(ptrace(PTRACE_GETREGS,child_proc,NULL,&reg)<0){
      fprintf(stderr,"error in ptrace_get regs %s",strerror(errno));
      exit(EXIT_FAILURE);
    }
    fprintf(stdout,"Breakpoint at 0x%llx\n:",reg.rip);
    address_rewind = reg.rip -1;//because of int3 instructin subtracting 1 

    break_point* bp = find_breakpoint(break_point_list,address_rewind);
    if(bp !=NULL){
      //restore original instruction
      if(ptrace(PTRACE_POKEDATA,child_proc,(void*)bp->address,bp->data)<0){
        fprintf(stderr,"error in restoring instruction %s",strerror(errno));
        exit(EXIT_FAILURE);
      }
      //rewind rip 
      reg.rip = address_rewind;
      if(ptrace(PTRACE_SETREGS,child_proc,NULL,&reg)<0){
        fprintf(stderr,"error in setting regs %s",strerror(errno));
        exit(EXIT_FAILURE);
      }
      //single step to execute original instruction
      if(ptrace(PTRACE_SINGLESTEP,child_proc,NULL,NULL)<0){
        fprintf(stderr,"error in single step after breakpoint %s",strerror(errno));
        exit(EXIT_FAILURE);
      }
      //wait for the single step to complete
      
      waitpid(child_proc,&wait_status,0);
      //reinsert the breakpoint
      reinsert_break_point(child_proc,bp);//add the break point back to the list

    }
  }
  print_wait_status(wait_status);
}

void dump_bytes(uint64_t data){
  unsigned char *bytes= (unsigned char*)&data;//always cast to unsigned char
  csh handle;
	cs_insn *insn;
	size_t count;

	if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK)
		return;
	count = cs_disasm(handle, bytes, sizeof(bytes)-1, 0x1000, 0, &insn);
	if (count > 0) {
		size_t j;
		for (j = 0; j < count; j++) {
			printf("0x%"PRIx64":\t%s\t\t%s\n", insn[j].address, insn[j].mnemonic,
					insn[j].op_str);
		}

		cs_free(insn, count);
	} else
		printf("ERROR: Failed to disassemble given code!\n");

	cs_close(&handle);
}
//add function to convert hex to string like how x/s works for a start 

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
  fprintf(stdout,"Read 8 bytes at 0x%llx: 0%016lx\n",current_rip,data);
  dump_bytes(data);
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
  char *input_commands;

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
    input_commands = readline("my_dbg> ");
    if(!input_commands){
      break; 
    }
    //handle empty input to repeat last command and prevent seg fault
    if(*input_commands == '\0'){
      free(input_commands);
      if(history_length>0){
        HIST_ENTRY *last = history_get(history_length);
        if(last->line){
          fprintf(stdout,"repeating %s\n",last->line);
          input_commands = strdup(last->line);
          }
        }
      else{
        continue;
      }
    }
    else{
        add_history(input_commands);
        }
  
    char  *cmd = strtok(input_commands," ");
    char *args= strtok(NULL,"");
    int found_command =0;
    COMMANDS *cmds=various_commands;

    for(cmds; cmds->name !=NULL;cmds++){
      if(strcmp(cmd,cmds->name)==0){
        cmds->func(args,child);
        found_command =1 ; 
        break;
      }
    }
    if(strcmp(cmd,"run")==0 || strcmp(cmd,"ru")==0){
      if(child>0){
        kill(child,SIGKILL);
        waitpid(child,&wait_status,0);
      }
      child=fork();
      if(child==0){
        load_program(program);
      }
      else{
        waitpid(child,&wait_status,0);
        print_wait_status(wait_status);
      }
      free(input_commands);
      continue;

    }
    if(!found_command){
      fprintf(stderr,"command on found\n");
      free(input_commands);
    }
  
  }
  free(input_commands);
  return 0;
}

