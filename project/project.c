#include <elf.h>
#include <stdio.h>
#include <getopt.h>
#include <signal.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <ctype.h>
#include <errno.h>

#include <sys/procfs.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <machine/reg.h>

#include <sys/syscall.h>
#include <sys/unistd.h>

#include "common.h"
#include "errors.h"

/* Information obtained from the NOTES section of the core file */
struct {
  prstatus_t prstatus;
  int prstatus_valid;   				/* Is the prstatus field valid? */
  prpsinfo_t prpsinfo; 
  int prpsinfo_valid;   			    /* Is the prpsinfo field valid? */
  struct fpreg fpregs; 
  int fpregs_valid;                     /* Are the floating point registers valid? */
} core_notes;

Elf32_Ehdr core_ehdr;	/* ELF header of core file  */
Elf32_Ehdr exec_ehdr;   /* ELF header of executable */
char *core_filename;    /* Name of core file        */
char *exec_filename;    /* Filename of executable   */
Elf32_Phdr *core_phdrs;	/* Program headers in core file */
char *progname;         /* Name of THIS executable  */
int  exec_pid;          /* PID of restarted process */

FILE *corefp;           /* The core file            */


/* Global flags/options for this restart program */
struct {
  int        stop;		/* If 0 then the child is in state "T" (stopped) when done, must send it a SIGCONT to run */
  int        verbose;   /* Print status messages? */
  int        select;    /* Choose the memory regions to be overwritten? */
  char      *filedes;   /* Text file containing checkpointed file descriptors */
  Elf32_Addr breakpt;   /* Instruction address to stop the child process at before restoring address space, registers.
						   Default is -1, which means stop at entry point specified in ELF header.*/
  int        wait;      /* Should restart wait for the restarted process to finish execution? */
} cr_options;

/* Command-line options (getopt) */
struct option options[] = {
  {"nostop",           no_argument, NULL, 'n'},
  {"verbose",          no_argument, NULL, 'V'},
  {"select",           no_argument, NULL, 's'},
  {"help",             no_argument, NULL, 'h'},
  {"breakpoint",       required_argument, NULL, 'b'},
  {"filedes",  	       optional_argument, NULL, 'f'},
  {"version",          no_argument, NULL, 'v'},
  {"wait",             no_argument, NULL, 'w'},
  {NULL,               no_argument, NULL, 0}
};

/* Taken from fs/binfmt_elf.c in the kernel sources */
#define roundup(x, y)  ((((x)+((y)-1))/(y))*(y))

static void parse_args(int argc, char *argv[]);
static void default_options();

static void usage();
static void version();

void get_elf_header(const char *filename, Elf32_Ehdr *ehdr, FILE **fp);
void read_phdrs(Elf32_Ehdr *ehdr, FILE *fp, Elf32_Phdr **phdrsp);

static void restart();
static void restore_addr_space();
static void restore_registers();
static void restore_fds();

static void map_memory(unsigned long start_addr, unsigned long size, int flags);
static void run_till_breakpt();
int    test_addr(unsigned long addr);
//static void restore_fds();
static void run_till_breakpt();

static void read_core_notes();


int main(int argc, char *argv[])
{
  progname = argv[0];
  default_options();
  parse_args(argc,argv);

  fprintf(stdout,"Restarting %s using core file %s\n",exec_filename,core_filename);
  get_elf_header(core_filename,&core_ehdr,&corefp);
  get_elf_header(exec_filename,&exec_ehdr,NULL);

  if (core_ehdr.e_type != ET_CORE) 
	die("%s is not an ELF CORE file",core_filename);

  if (exec_ehdr.e_type != ET_EXEC)
	die("%s is not an ELF executable",exec_filename);

  read_phdrs(&core_ehdr,corefp,&core_phdrs);

  core_notes.prpsinfo_valid = 0;
  core_notes.prstatus_valid = 0;
  core_notes.fpregs_valid   = 0;

  restart();

  fclose(corefp);
  free(core_phdrs);
  return 0;
}

void restart() 
{
  int status;
  read_core_notes();
  char cmd[50];	
  if (core_notes.prpsinfo_valid) 
	fprintf(stdout,"Original command-line (first 80 chars):\n%s\n\n",core_notes.prpsinfo.pr_psargs);

  exec_pid = fork();
  if (exec_pid < 0) {
	die("fork() failed. Aborting Restart.");
  }
  else if (!exec_pid) {
        //fprintf(stdout,"child process id %d\n ",exec_pid);
	//In the child process, i.e., the process which will restart from the core snapshot 
	restore_fds();
	if (ptrace(PT_TRACE_ME,0,NULL,0) < 0)
	  die_perror("ptrace(PT_TRACE_ME,...)");
	if (execl(exec_filename,exec_filename,NULL) < 0)
	  die_perror("execl(%s,...)",exec_filename);
  }

  // The child process will NEVER reach this point (will either exec or die) 
  fprintf(stdout,"Process will be restarted with pid        = %d\n",exec_pid);

  wait(&status);

  //fprintf(stdout,"%d\n",status);
  if (WIFEXITED(status))
	die("Restarted process abrubtly (exited with value %d). Aborting Restart.",WEXITSTATUS(status));
  else if (WIFSIGNALED(status))
	die("Restarted process abrubtly exited because of uncaught signal (%d). Aborting Restart.",WTERMSIG(status));
 run_till_breakpt();
  
  if (cr_options.verbose) {
	fprintf(stdout,"Stopped execution at address              = 0x%.5x\n",exec_ehdr.e_entry);
  }
printf("run untill break point\n");
  // Restore the state of the process
  restore_addr_space();

  restore_registers();

  // All done, ready to rumble 
  fprintf(stdout,"%s ready to continue from where it left off\n",exec_filename);
  if (cr_options.stop) {
	if (kill(exec_pid,SIGSTOP) < 0)
	  warn_perror("kill(%d,SIGSTOP)",exec_pid);
	else {
	  fprintf(stdout,"Sent SIGSTOP to %d. Send it a SIGCONT to resume\n",exec_pid);
	}
  }
	  
  if (ptrace(PT_DETACH,exec_pid,NULL,0) < 0)
	warn_perror("ptrace(PT_DETACH,%d,NULL,NULL)",exec_pid);

  // Wait for executable to finish if -w was specified 
  if (cr_options.wait) {
	int status;
	fprintf(stdout,"Waiting for restarted process to finish\n");
	while (wait(&status) != exec_pid);
	if (WIFEXITED(status))
	  fprintf(stdout,"Restarted process finished, exiting with value %d\n",WEXITSTATUS(status));
	else if (WIFSIGNALED(status))
	  fprintf(stdout,"Restarted process exited because of uncaught signal (%d)\n",WTERMSIG(status));
	else if (WIFSTOPPED(status))
	  fprintf(stdout,"Restarted process is currently stopped (by signal %d)\n",WSTOPSIG(status));
  }
}

void restore_registers()
{
  struct reg regs;
  regs = *((struct reg *)(&core_notes.prstatus.pr_reg));
  if (ptrace(PT_SETREGS,exec_pid,(caddr_t)&regs,0) < 0) {
	die_perror("ptrace(PT_SETREGS,...)");
  }
  if (core_notes.fpregs_valid) {
	if (ptrace(PT_SETFPREGS,exec_pid,(caddr_t)&core_notes.fpregs,0) < 0)
	  die_perror("ptrace(PT_SETFPREGS,...)");
  }
}

void restore_addr_space()
{

  int i;
  int go_ahead;
  Elf32_Addr end_addr;
  int success;

  for (i = 0; i < core_ehdr.e_phnum; i++) {
	go_ahead = 1;
	success = 1;
	end_addr = core_phdrs[i].p_vaddr + core_phdrs[i].p_memsz;
	

	if (core_phdrs[i].p_type != PT_LOAD)
	  continue;

	if (!(core_phdrs[i].p_flags & PF_W) || core_phdrs[i].p_filesz == 0) {
	  if (cr_options.verbose) {
		fprintf(stdout,"[0x%.8x - 0x%.8x] is either not writeable or filesize is 0. Ignoring.\n",core_phdrs[i].p_vaddr,end_addr);
	  }
	  continue;
	}

	if (cr_options.select) {
	  fprintf(stdout,"Restore [0x%.8x - 0x%.8x] (%c%c%c)? (0=No, 1=Yes) ",
			  core_phdrs[i].p_vaddr,end_addr,
			  (core_phdrs[i].p_flags & PF_R)?'r':'-',
			  (core_phdrs[i].p_flags & PF_W)?'w':'-',
			  (core_phdrs[i].p_flags & PF_X)?'x':'-');
	  scanf("%d",&go_ahead);
	}
	// If we have the go ahead, then read contents from core and copy to address space 
	if (go_ahead) {
	  // A "word" = 4 bytes = sizeof(long) 
	  unsigned long *mem,*origmem,*ptr;

	  if (core_phdrs[i].p_memsz != core_phdrs[i].p_filesz) {
		warn("Filesize and memory size for memory region 0x%.8lx - 0x%.8lx differ. Ignoring this region.",core_phdrs[i].p_vaddr,end_addr);
		continue;
	  }

	  mem = origmem = (unsigned long*)malloc(core_phdrs[i].p_memsz);
          	  if (fseek(corefp,core_phdrs[i].p_offset,SEEK_SET) < 0) 
		die("Could not seek to area with memory [0x%.8lx - 0x%.8lx] in core file",core_phdrs[i].p_vaddr,end_addr);
	  if (fread(origmem,core_phdrs[i].p_filesz,1,corefp) != 1)
		die("Could not read region [0x%.8lx - 0x%.8lx] from core file",core_phdrs[i].p_vaddr,end_addr);
	  
	  // Test if these addresses are valid, if not, allocate them 
	  if (!test_addr(core_phdrs[i].p_vaddr) || !test_addr(end_addr - 4)) {
		if (cr_options.verbose) {
		  fprintf(stdout,"Addresses [0x%.8x - 0x%.8x] were not part of address space, making them\n",core_phdrs[i].p_vaddr,end_addr);
		}

          //fprintf(stdout,"\n vaddr = %u, memsz = %u, flags = %u \n",core_phdrs[i].p_vaddr,core_phdrs[i].p_memsz,core_phdrs[i].p_flags);
		map_memory(core_phdrs[i].p_vaddr, core_phdrs[i].p_memsz, core_phdrs[i].p_flags);
		
	  }

	  // Write word by word 
	  for (ptr = (unsigned long*)core_phdrs[i].p_vaddr; ptr < (unsigned long*)end_addr; ptr++,mem++) {
		unsigned long written;
		if (ptrace(PT_WRITE_D,exec_pid,(caddr_t)ptr,(int)(*mem)) < 0) {
		  warn_perror("ptrace(PT_WRITE_D,...)");
		  success = 0;
		  break;
		}
		written = ptrace(PT_READ_D,exec_pid,(caddr_t)ptr,0);
		if (written != (unsigned long)(*mem))
		  warn("Wanted to write 0x%.8lx to address 0x%.8lx but couldn't. That location contains 0x%.8lx",*mem,ptr,written);
	  }

	  if (success && cr_options.verbose) {
		fprintf(stdout,"Loaded region [0x%.8x - 0x%.8x] (%c%c%c) from core file\n",
				core_phdrs[i].p_vaddr, end_addr,
				(core_phdrs[i].p_flags & PF_R)?'r':'-',
				(core_phdrs[i].p_flags & PF_W)?'w':'-',
				(core_phdrs[i].p_flags & PF_X)?'x':'-');
	  }
	  else if (!success)
		warn("Error loading region [0x%.8x - 0x%.8x] from core file",core_phdrs[i].p_vaddr,end_addr);

	  free(origmem);
	} // if (go_ahead) 
  
} // for (i = ... ) 
}


/* Tests if we can write into the child's address space at the specified address.
 * Return value:
 * >0	If we can
 * =0   If we can't because the address is not valid (needs to be allocated)
 * <0   If there was some other ptrace error
 */
int  test_addr(unsigned long addr_arg)
{
  void *addr = (void*)addr_arg;
  long word = 0;
  long ptrace_ret;
  
  ptrace_ret = ptrace(PT_WRITE_D,exec_pid,addr,(word));
  if (ptrace_ret < 0) {
	if (errno == EIO || errno == EFAULT)
	  return 0;
	else
	  return -1;
  }
  else
	return 1;
}

/* Makes addresses from the address specified till size more
 * in the child's address space valid using the mmap2 system
 * call
 */
void map_memory(unsigned long addr, unsigned long size, int flags)
{
  int status;
  char cmd[200];
  struct reg regs,temp_regs;
  unsigned int int_instr = 0x000080cd; /* INT 0x80 */
  unsigned int push_eax= 0x00000050;
  unsigned int orig_instr;
  sprintf(cmd,"procstat -v %d "/*| grep 0x | awk   ' { print $2,$3,$4 } ' | cut -d '%%' -f1 > temp.txt*/,exec_pid); 
	system(cmd);
  if (ptrace(PT_GETREGS,exec_pid,(caddr_t)&regs,0) < 0)
    die_perror("ptrace(PTRACE_GETREGS,%d,(caddr_t)&regs,0)",exec_pid);



   /*mmap2 system call seems to take arguments as follows:
   * eax = __NR_mmap2 
   * ebx = (unsigned long) page aligned address
   * ecx = (unsigned long) page aligned file size
   * edx = protection
   * esi = flags
   * Other arguments (fd and pgoff) are not required for anonymous mapping 
   */
  int i;


  orig_instr = ptrace(PT_READ_D, exec_pid, (caddr_t)regs.r_eip,0);
  temp_regs = regs;
  unsigned int arr[8]={0,0,-1,MAP_ANON|MAP_PRIVATE|MAP_FIXED,flags,size,addr,45};
  for(i=0;i<8;i++)
    {
    temp_regs.r_eip=regs.r_eip;
    temp_regs.r_eax=arr[i];
    if(ptrace(PT_WRITE_D, exec_pid,(caddr_t)temp_regs.r_eip,push_eax)<0)
    die_perror("ptrace(PT_WRITE,%d,0x%.8x) while pushing",exec_pid,arr[i]);

    if(ptrace(PT_SETREGS,exec_pid,(caddr_t)&temp_regs,0)<0)
    die_perror("ptrace(PT_SETREGS,%d,0x%.8x)%d while pushing",exec_pid,arr[i],i);
    
    if(ptrace(PT_STEP, exec_pid, (caddr_t)1, 0)<0)
    printf("\nafter continue\n");

    wait(NULL);
      
      
    if(ptrace(PT_GETREGS, exec_pid,(caddr_t)&temp_regs,0)<0);
    }
    
  
 temp_regs.r_eip=regs.r_eip; 
 temp_regs.r_eax=SYS_mmap;
  if (ptrace(PT_WRITE_D,exec_pid,(caddr_t)(temp_regs.r_eip),int_instr) < 0)
    die_perror("ptrace(PT_WRITE,%d,0x%.8x,INT 0x80) failed while allocating memory",exec_pid,temp_regs.r_eip);
  
  if (ptrace(PT_SETREGS,exec_pid,(caddr_t)&temp_regs,0) < 0) {
	die_perror("ptrace(PT_SETREGS,%d,...) failed while allocating memory",exec_pid);  	
}
 if (ptrace(PT_STEP,exec_pid,(caddr_t)1,0) < 0)
        die_perror("ptrace(PT_STEP,...) failed while executing mmap");

//temp_regs.r_esp = temp_regs.r_esp - 28;
  

  wait(&status);
	
  if (WIFEXITED(status))
	die("Restarted process abrubtly (exited with value %d). Aborting Restart.",WEXITSTATUS(status));
  else if (WIFSIGNALED(status))
	die("Restarted process abrubtly exited because of uncaught signal (%d). Aborting Restart.",WTERMSIG(status));

  if (ptrace(PT_GETREGS,exec_pid,(caddr_t)&temp_regs,0) < 0) {
	die_perror("ptrace(PT_GETREGS,...) failed after executing mmap2 system call");
  }
//fprintf(stdout,"hello iam here in map_memory() \n");

  if (temp_regs.r_eax != addr)
	warn("Wanted space at address 0x%.8x, mmap2 system call returned 0x%.8x. This could be a problem.",addr,temp_regs.r_eax); 
  else if (cr_options.verbose)

	fprintf(stdout,"Successfully allocated [0x%.8lx - 0x%.8lx]\n",addr,addr+size);
  if(ptrace(PT_WRITE_D, exec_pid, (caddr_t)regs.r_eip,orig_instr)<0)
     	die_perror("ptrace(PT_WRITE_D,...) failed after executing mmap2 system call");
  	
	
 //Restore original registers 
if (ptrace(PT_SETREGS,exec_pid,(caddr_t)&regs,0) < 0) {
	die_perror("ptrace(PT_SETREGS,...) when restoring registering after allocating memory (mmap2)");

  }
}


void run_till_breakpt()
{
  /* Execute the process to be restarted till it reaches the entry point (_start function)
   * The idea is that the dynamic library loading etc. will all be done by this time (__libc_start_main function)
   */
  int status;
  struct reg regs;
  unsigned long orig_instr, bkpt_instr;
   
  if (cr_options.breakpt == -1)
	cr_options.breakpt = exec_ehdr.e_entry;

  bkpt_instr = 0x000000cc;  /* The INT3 instruction in IA32 architecture, 
  							 * actual opcode is 0xcc.
							 */
printf("breakpt=%x\n",cr_options.breakpt);

//fprintf(stdout,"%d\n",status);
//  if (WIFEXITED(status))
//	die("Child process exited with exit code %d. Restart aborted.",WEXITSTATUS(status));
//fprintf(stdout,"hello\n");
  
/* Store original instruction at breakpoint and replace with INT3 */
  orig_instr = ptrace(PT_READ_I,exec_pid,(void*)cr_options.breakpt,0);
  if (orig_instr < 0)
	die_perror("ptrace(PT_READ_I,%d,0x%.8x,0)",exec_pid,cr_options.breakpt);

  if (ptrace(PT_WRITE_I,exec_pid,(void*)cr_options.breakpt,bkpt_instr) < 0)
	die_perror("ptrace(PT_WRITE_I,%d,0x%.8x,INT3)",exec_pid,cr_options.breakpt);

  /* Continue execution of child till it executes the INT3 */
  if (ptrace(PT_CONTINUE,exec_pid,(caddr_t)1,0) < 0)
	die_perror("ptrace(PT_CONTINUE,%d,0,0)",exec_pid);

  wait(&status);
  if (WIFEXITED(status))
	die("Child process exited with exit code %d. Restart aborted.",WEXITSTATUS(status));
  else if (WIFSIGNALED(status))
	die("Restarted process abrubtly exited because of uncaught signal (%d). Aborting Restart.",WTERMSIG(status));

  /* Restore original instruction and set eip (PC) to original instruction = breakpoint */
  if (ptrace(PT_GETREGS,exec_pid,(caddr_t)&regs,0) < 0)
	die_perror("ptrace(PT_GETREGS,%d,&regs,0)",exec_pid);
printf("eip=%x\n",regs.r_eip);
  regs.r_eip = cr_options.breakpt;
  if (ptrace(PT_WRITE_I,exec_pid,(void*)cr_options.breakpt,orig_instr) < 0)
	die_perror("ptrace(PT_WRITE_I,%d,0x%.8x,0x%.8x)",exec_pid,cr_options.breakpt,orig_instr);
printf("eip=%x\n",regs.r_eip);
  if (ptrace(PT_SETREGS,exec_pid,(caddr_t)&regs,0) < 0)
	die_perror("ptrace(PT_SETREGS,%d,&regs,0)",exec_pid);

}


void restore_fds()
{
  FILE *fp;
  char buf[NAME_MAX];
  if (!cr_options.filedes)
	return;

  fprintf(stdout,"Restoring file descriptors from '%s'\n",cr_options.filedes);
  fp = fopen(cr_options.filedes,"r");
  if (!fp) 
	die("Could not open %s. Aborting restart",cr_options.filedes);

  if (cr_options.verbose) {
	fprintf(stdout,"%s opened with fd = %d\n",cr_options.filedes,fileno(fp));
  }

  while (!feof(fp)) {
	savefds_fd_t fd;
	int temp_fd,i,c;

	/* -- BEGIN : VERY DIRTY AND POOR QUALITY PARSING CODE -- */
	for (i = 0; (c = fgetc(fp)) != ':' && c != EOF; i++)
	  buf[i] = c;
	buf[--i] = 0;
	fd.fd = atoi(buf);

	while ((c = fgetc(fp)) != EOF && isspace(c));
	for (buf[0] = c, i = 1; (c = fgetc(fp)) != ':' && c != EOF; i++)
	  buf[i] = c;
	buf[--i] = 0;
	i--;
	while (isspace(buf[i]))
	  i--;
	strcpy(fd.filename,buf);

	while ((c = fgetc(fp)) != EOF && isspace(c));
	for (buf[0]=c, i = 1; (c = fgetc(fp)) != ':' && c != EOF; i++)
	  buf[i] = c;
	buf[i] = 0;
	fd.offset = strtol(buf,NULL,0);

	while ((c = fgetc(fp)) != EOF && isspace(c));
	for (buf[0]=c, i = 1; (c = fgetc(fp)) != '\n' && c != EOF; i++)
	  buf[i] = c;
	buf[i] = 0;
	fd.flags = strtol(buf,NULL,0);

	if (c == EOF)
	  break;
	/* -- END VERY DIRTY AND POOR QUALITY PARSING CODE -- */

	if ((temp_fd = open(fd.filename,fd.flags)) < 0) {
	  die_perror("Restoring fd %d : open(%s,%x)",fd.fd,fd.filename,fd.flags);
	  continue;
	} else {
	  if (temp_fd != fd.fd) {
		if (cr_options.verbose)
		  fprintf(stdout,"%s has been assigned fd %d, changing to original fd = %d\n",fd.filename,temp_fd,fd.fd);

		/* If the file from which we're reading fd information has the required fd, then change it */
		if (fd.fd == fileno(fp)) {
		  int new_fp_fd, old_fp_fd;
		  old_fp_fd = fileno(fp);
		  if (cr_options.verbose) {
			fprintf(stdout,"%s had fd %d, changing it because %d is required by %s\n",
					cr_options.filedes,old_fp_fd,fd.fd,fd.filename);
		  }
		  if ((new_fp_fd = dup(old_fp_fd)) < 0) 
			die_perror("dup(%d) in %s:%d",old_fp_fd,__FILE__,__LINE__);
		  if (fclose(fp) < 0)
			die_perror("fclose(%d) in %s:%d",old_fp_fd,__FILE__,__LINE__);
		  fp = fdopen(new_fp_fd,"r");
		  if (!fp) 
			die_perror("fdopen() while using new fd for %s",cr_options.filedes);
		}
		/* End of code handling the situation where the cr_options.filedes file takes the required fd */

		if (dup2(temp_fd,fd.fd) != fd.fd)
		  die_perror("Restoring fd %d : dup2(%d,%d). Aborting Restart.",fd.fd,temp_fd,fd.fd);
	  }
	  if (close(temp_fd) < 0)
		warn_perror("close(temporary fd)");
	  if (lseek(fd.fd,fd.offset,SEEK_SET) < 0)
		die_perror("lseek(%d,%d,SEEK_SET)",fd.fd,fd.offset);
	  if (cr_options.verbose)
		fprintf(stdout,"fd %d (%s) restored (offset %ld, flags 0x%.8x (%d))\n",
				fd.fd,fd.filename,fd.offset,fd.flags,fd.flags);
	}
  }
  fclose(fp);
}

/* Read the NOTES from the core file */
void read_core_notes()
{
  Elf32_Nhdr nhdr;
  int num_notes, i;
  unsigned long offset, length;
  int found;

  /* Find the NOTES program header */
  found = 0;
  for (i = 0; i < core_ehdr.e_phnum; i++) {
	switch (core_phdrs[i].p_type) {
	case PT_NOTE: 
	  offset = core_phdrs[i].p_offset;
	  length = core_phdrs[i].p_filesz;
	  found++;
	  break;
	case PT_LOAD: 
	  break;
	default:
	  warn("Program header %d is of an unexpected type (0x%x). Ignoring",i,core_phdrs[i].p_type);
	}
  }
  
  if (found != 1)
	die("We needed excatly 1 NOTES program header, we found %d. Abort.\n",found);

  /* Read in the notes */
  if (fseek(corefp,offset,SEEK_SET) < 0)
	die("Could not seek to NOTES section of core file");

  for (num_notes = 0; ftell(corefp) < offset + length; num_notes++) {
	char *name;
	int namesz, descsz;

	if (fread(&nhdr,sizeof(nhdr),1,corefp) != 1) 
	  die("Could not read header for note #%d",num_notes);
	namesz = roundup(nhdr.n_namesz, 4);
	descsz = roundup(nhdr.n_descsz, 4);
	name = (char*)malloc(namesz);
	
	if (fread(name,namesz,1,corefp) != 1) 
	  die("Could not read name of note #%d",num_notes);
	name[nhdr.n_namesz] = '\0';

	switch(nhdr.n_type) {
	case NT_PRPSINFO:
	  if (fread(&core_notes.prpsinfo,descsz,1,corefp) != 1)
		die("Could not read the NT_PRPSINFO note (Note #%d)",num_notes);
	  core_notes.prpsinfo_valid++;
	  break;
	case NT_PRSTATUS:
	  if (fread(&core_notes.prstatus,descsz,1,corefp) != 1)
		die("Could not read the NT_PRSTATUS note (Note #%d)",num_notes);
	  core_notes.prstatus_valid++;
	  break;
	case NT_FPREGSET:
	  if (fread(&core_notes.fpregs,descsz,1,corefp) != 1)
		die("Could not read the NT_PRFPREG note (Note #%d)",num_notes);
	  core_notes.fpregs_valid++;
	  break;
	default:
	  if (fseek(corefp,descsz,SEEK_CUR) < 0) 
		die("Note #%d (name = %s), type (%d) was being ignored. Could not seek past it.",num_notes,name,nhdr.n_type);
	  else if (cr_options.verbose)
		warn("Note #%d (name = %s), type (%d) is being ignored",num_notes,name,nhdr.n_type);
	}
	free(name);
  }
}


void default_options() 
{
  cr_options.stop    = 1;
  cr_options.verbose = 0;
  cr_options.select  = 0;
  cr_options.filedes = NULL;
  cr_options.breakpt = -1;
  cr_options.wait    = 0;
}


void parse_args(int argc, char *argv[])
{
  char *optstring = "bmf::hnsvVw";
  int c;

  core_filename = exec_filename = NULL;

  while ((c = getopt_long(argc,argv,optstring,options,NULL)) != -1) {
	switch(c) {
	case 'b':
	  cr_options.breakpt = strtol(optarg,NULL,0);
	  break;
	case 'm':
	  fprintf(stderr,"Option %c is not yet implemented. Ignoring.", c);
	  break;
	case 'f':
	  if (!optarg)
		cr_options.filedes = SAVEFDS_DEFAULT_SAVE_FILENAME;
	  else
		cr_options.filedes = optarg;
	  break;
	case 'h':
	  usage();
	  break; /* won't reach here */
	case 'n':
	  cr_options.stop = 0;
	  break;
	case 's':
	  cr_options.select++;
	  break;
	case 'v':
	  version();
	  break; /* won't reach here */
	case 'V':
	  cr_options.verbose++;
	  break;
	case 'w':
	  cr_options.wait++;
	  break;
	case '?':
	  break;
	default:
	  fprintf (stderr, "?? getopt returned character code 0%o ??\n", c);
	}
  }
  
  if (!cr_options.wait && cr_options.stop) {
	fprintf(stdout,"**************************************************************************\n");
	fprintf(stdout,"We're having some problems if don't use --wait when you don't use --nostop\n");
	fprintf(stdout,"So, forcing a --wait\n");
	fprintf(stdout,"**************************************************************************\n");
	fprintf(stdout,"\n");
	cr_options.wait++;
  }

  if (optind < argc)
	exec_filename = argv[optind++];

  if (optind < argc)
	core_filename = argv[optind++];

  if (!core_filename || !exec_filename)
	usage();
}


void usage()
{
  fprintf(stdout,"Restart a process checkpointed using it's core file.\n");
  fprintf(stdout,"Usage: %s [options] <executable filename> <core filename>\n",progname);
  fprintf(stdout,"\n");
  fprintf(stdout,"Options:\n");
  fprintf(stdout,"  -b, --breakpoint=ADDRESS   When execing the program to be restarted then run till given\n");
  fprintf(stdout,"                             instruction ADDRESS before restoring address space and registers\n");
  fprintf(stdout,"                             (Default is the entry point of the executable, which is generally\n");
  fprintf(stdout,"                             the address of the _start function, thus all dynamic libraries are\n");
  fprintf(stdout,"                             loaded by this time. Specifying this is useful for statically linked\n");
  fprintf(stdout,"                             executables (Compiled with the --static flag in gcc)).\n");
  fprintf(stdout,"  -f, --filedes[=FILENAME]   Restore file descriptors from FILENAME created by\n");
  fprintf(stdout,"                             libsavefds.so (Default FILENAME is \"%s\")\n",SAVEFDS_DEFAULT_SAVE_FILENAME);
  fprintf(stdout,"  -n, --nostop               Do not pause the restarted process\n");
  fprintf(stdout,"                             (By default the process must be sent a SIGCONT to continue)\n");
  fprintf(stdout,"  -s, --select               Make detailed selections while the address space is restored\n");
  fprintf(stdout,"  -V, --verbose              Be a bit verbose about what is being done while restarting\n");
  fprintf(stdout,"  -w, --wait                 Wait for restarted process to finish execution\n");
  fprintf(stdout,"  -h, --help                 Display this help and exit\n");
  fprintf(stdout,"  -v, --version              Display version information and exit\n");
  exit(0);
}

void version()
{
  fprintf(stdout,"Restart from core. Version %s.\n",___VERSION___);
  fprintf(stdout,"project1b\n");
  exit(0);
}


/* Given a filename, reads the ELF32 header and if fp != NULL, returns
 * the FILE* structure of the filename
 */

void get_elf_header(const char *filename, Elf32_Ehdr *ehdr, FILE **fp) 
{
  FILE *file = fopen(filename,"r");
  if (!file) 
	die("Couldn't open file '%s'",filename);
  
  if (fread(ehdr,sizeof(*ehdr),1,file) != 1)
	die("Could not read ELF header from file '%s'",filename);

  if (fp == NULL)
	fclose(file);
  else
	(*fp) = file;
}


/* Reads program headers into an array of program headers.
 * Requires a pointer to the ELF32 header and the FILE structure
 * to the file on disk whose ELF32 header is being looked at
 */
void read_phdrs(Elf32_Ehdr *ehdr, FILE *fp, Elf32_Phdr **phdrp)
{
  Elf32_Phdr *phdrs;
  phdrs = (Elf32_Phdr*)malloc(ehdr->e_phentsize * ehdr->e_phnum);

  if (fseek(fp,ehdr->e_phoff,SEEK_SET)<0)
	die("Could not seek to program header section");

  if (fread(phdrs,ehdr->e_phentsize,ehdr->e_phnum,fp) != ehdr->e_phnum)
	die("Could not read all program headers");

  *phdrp = phdrs;
}

