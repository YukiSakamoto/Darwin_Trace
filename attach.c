#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <unistd.h>
#include <sys/types.h>
#include <sys/ptrace.h>
#include <errno.h>

#include <mach/mach.h>
#include <spawn.h>
#include <udis86.h>

#include "memory_op.h"
#include "functable.h"

extern int errno;

#define RESET_ERROR (errno=0)
#define ERROR_OCCURED (errno!=0)


#ifdef debug_mode
#	define debug_printf(...)	printf("[[DebugPrint]]   ");printf(__VA_ARGS__)
#else
#	define debug_printf(...)
#endif

char *function_unknown = "UnknownFunction";

void *chk_malloc(size_t size)
{
	void *p = malloc(size);
	if (p == NULL) {
		debug_printf("NULL returned by malloc!\n");
	} 
	return p;
}

void target_proc(char **args)
{
	int ret;

	short ps_flags = 0;
	pid_t pid;
	posix_spawn_file_actions_t actions;
	posix_spawnattr_t attrs;

	if (args == NULL) {	return;	}

	RESET_ERROR;
	posix_spawn_file_actions_init(&actions);
	posix_spawnattr_init(&attrs);

#ifndef _POSIX_SPAWN_DISABLE_ASLR
#	define _POSIX_SPAWN_DISABLE_ASLR 0x0100
#endif
	ps_flags |= POSIX_SPAWN_SETEXEC;
	ps_flags |= _POSIX_SPAWN_DISABLE_ASLR;
	ret = posix_spawnattr_setflags(&attrs, ps_flags);
	if (ret != 0) {
		fprintf(stderr, "cannot set posix_spawn flags\n");
		return;
	}

	/* attached */
	ret = ptrace(PT_TRACE_ME, 0, 0, 0);
	posix_spawn(&pid, args[0], &actions, &attrs, args, NULL);
	fprintf(stderr, "Failed\n");
	exit(1);
}

struct breakpoint_entry {
	vm_address_t addr;
	unsigned char orig_inst_code;
	int  valid;
	struct breakpoint_entry *next;
};

int set_breakpoint(mach_port_t task, vm_address_t target_addr, struct breakpoint_entry *brk_ptr_list)
{
	register struct breakpoint_entry *p;
	int alloc_required = 1;
	unsigned char breakpoint_code = 0xcc;	/* int3 */

	/* search the entry */
	for(p = brk_ptr_list; p->next != NULL; p = p->next) {
		if (p->addr == target_addr) {
			alloc_required = 0;
			break;
		}
	}
	if (alloc_required == 1 && p->addr == target_addr) {
		alloc_required = 0;
	}

	/* new entry -- allocate and initialize */
	if (alloc_required == 1) {
		p->next = chk_malloc(sizeof(struct breakpoint_entry));
		/* skip */
		p = p->next;
		memset(p, 0x00, sizeof(struct breakpoint_entry));
		p->addr = target_addr;
		/* save original instruction code */
		read_write_process_memory(task, target_addr, &(p->orig_inst_code), NULL, sizeof(unsigned char));
	}

	/* set int3(0xcc) instruction code */
	if (read_write_process_memory(task, target_addr, NULL, &breakpoint_code, sizeof(unsigned char)) ) {
		p->valid = 1;
		/* for debugging 
		fprintf(stderr, "set break at 0x%llx\n", target_addr);
		*/
		return 0;
	} else {
		return -1;
	}
}

int disable_breakpoint(mach_port_t task, vm_address_t target_addr, void *brk_ptr_list)
{
	register struct breakpoint_entry *p;
	int ret = -1;
	for(p = brk_ptr_list; p != NULL; p = p->next) {
		if (p->addr == target_addr && p->valid == 1) {
			unsigned char orig_code = p->orig_inst_code;
			if (read_write_process_memory(task, target_addr, NULL, &orig_code, sizeof(unsigned char)) ) {
				p->valid = 0;
				ret = 0;
				break;
			}
		}
	}
	return ret;
}

int is_breakpoint(vm_address_t addr, struct breakpoint_entry *brk_ptr_list)
{
	int i;
	register struct breakpoint_entry *p;
	for(p = brk_ptr_list; p != NULL; p = p->next) {
		if (p->addr == addr && p->valid == 1) {
			return 1;
		}
	}
	return 0;
}

int is_exclude_func(struct symbol_info *psym) {
	int i;
	int ret = 0;

	static char exclude_funcnames[][64] = {
		"__mh_execute_header",
		"start",
		"",
	};
	
	for(i = 0; exclude_funcnames[i][0] != 0x00; i++) {
		if(strcmp(psym->name, exclude_funcnames[i]) == 0) {
			ret = 1;
			break;
		}
	}
	return ret;
}

static
char *lookup_function(vm_address_t addr, struct symbol_info *psymbol_table, size_t nsym, int *type)
{
	int i;
	char *pfuncname = function_unknown;
	int found = 0;
	for(i = 0; i < nsym; i++) {
		if (psymbol_table[i].nlist64.n_value == addr && 0 < strlen(psymbol_table[i].name)) {
			pfuncname = psymbol_table[i].name;
			*type = 1;
			found = 1;
		} else {
			int j;
			for(j = 0; j < psymbol_table[i].ret_address_num; j++) {
				if (addr == psymbol_table[i].ret_inst_address[j]) {
					pfuncname = psymbol_table[i].name;
					*type = 2;
					found = 1;
				}
			}
		}
		if (found != 0) {
			break;
		}
	}
	return pfuncname;
}


static
int breakpoint_handler(uint64_t addr, struct symbol_info *psymbol_table, size_t nsym, int stack_depth)
{
	int i;
	int output = 1;
	int type;
	const char *fname = lookup_function(addr, psymbol_table, nsym, &type);
	
	/* output to stderr */
	if (output) {
		fprintf(stderr, "[Tracer] ");
	}
	if (type == 2 && 0 < stack_depth) {
		stack_depth--;
	}
	if (output) {
		for(i = 0; i < stack_depth; i++) {
			fprintf(stderr, "    ");
		}
	}
	if (type == 1) {
		stack_depth++;
	}
	if (output) {
		fprintf(stderr, "%s [ %s (at 0x%llx)]\n", type == 1 ? "===>" : type == 2 ? "<===" : "    " , fname, addr);
	}
	return stack_depth;
}

void display_symbol_table(struct symbol_info *psymbol_info, size_t nsym)
{
	register int i = 0;
	for(i = 0; i < nsym; i++) {
		fprintf(stderr, "%s [ at 0x%llx]\n", psymbol_info[i].name, psymbol_info[i].nlist64.n_value);
	}
}

/* qsort callback func */
int symbolinfo_comp(const void *a, const void *b)
{
	return ((struct symbol_info*)a)->nlist64.n_value - ((struct symbol_info*)b)->nlist64.n_value;
}


void debugger_proc(pid_t child_proc, char **args)
{
	/* about child process */
	int child_stat;
	kern_return_t kret;
	mach_port_t task;
	int wait_cnt = 0;

	/* related analysys of target process binary. */
	int i;
	int nsym;
	int text_section;
	uint64_t text_section_offset;
	uint64_t text_section_size;
	uint64_t text_section_vmaddr;
	struct symbol_info *psymbol_table;
	int init = 0;
	struct breakpoint_entry top;

	int stack_depth = 0;

	/* error check */
	if (child_proc == 0 || child_proc == -1)	return;

	/* initialize */
	memset(&top, 0x00, sizeof(top));

	/* open the port (do as an administrator) */
	kret = task_for_pid(mach_task_self(), child_proc, &task);
	if (kret != KERN_SUCCESS) {
		fprintf(stderr, "task_for_pid() failed\n");
		fprintf(stderr, "%s\n", mach_error_string(kret));
		exit(0);
	}

	fprintf(stderr, "[Tracer] child_proc: %d\n", child_proc);
	/* main loop */
	while(waitpid(child_proc, &child_stat, WUNTRACED)) {
		char buffer[128];
		char w_buf[128];
		w_buf[0] = 0x90;	/* nop */

		if (WIFEXITED(child_stat)) {
			/* Child Process Terminated */
			fprintf(stderr, "[Tracer]  Process :%d Terminated\n", child_proc);
			return;
		}
		memset(buffer, 0x00, 128);
		if(wait_cnt == 0) {
			/* -- The debugee program has not been expanded.-- */
			/* -- 	lookup named symbol	-- */
			struct file_info bininfo;
			ud_t ud_obj;
			uint64_t previous_eip;
			uint64_t func_start_addr;
			uint64_t func_end_addr;

			nsym = get_func_table(args[0], &psymbol_table, &text_section, &text_section_offset, &text_section_size, &text_section_vmaddr);
			debug_printf("nsym: %d\n", nsym);
			debug_printf("text section = %d\n", text_section);
			debug_printf("text section offset: 0x%llx\n", text_section_offset);
			debug_printf("text section size: 0x%llx\n", text_section_size);
			debug_printf("text section vmaddr: 0x%llx\n", text_section_vmaddr);

			qsort(psymbol_table, nsym, sizeof(struct symbol_info), symbolinfo_comp);

			/* XXX for debugging  */
			/*display_symbol_table(psymbol_table, nsym);*/

			/* code analysys */
			map_binary(args[0], &bininfo);
			ud_init(&ud_obj);
			ud_set_input_buffer(&ud_obj, bininfo.top + text_section_offset, text_section_size);
			ud_set_mode(&ud_obj, 64);

			previous_eip = text_section_vmaddr;
			/* set breakpoint at the entry and exit points of functions */
			for(i = 0; i < nsym; i++) {
				if (is_exclude_func(psymbol_table + i) == 1) {
					continue;
				}
				/* 1, specifying the region of the function */
				func_start_addr = psymbol_table[i].nlist64.n_value;
				if (i != nsym - 1) {
					/* next section's entry point - 1 */
					func_end_addr = psymbol_table[i + 1].nlist64.n_value;
				} else {
					func_end_addr = text_section_vmaddr + text_section_size + 1;
				}
				debug_printf("%s: %llx --> %llx\n", psymbol_table[i].name, func_start_addr, func_end_addr);
				psymbol_table[i].ret_address_num = 0;

				previous_eip = ud_obj.pc + text_section_vmaddr;

				while(ud_disassemble(&ud_obj) && previous_eip < func_start_addr) {
					previous_eip = ud_obj.pc + text_section_vmaddr;
				}
				while(ud_disassemble(&ud_obj) && previous_eip < func_end_addr) {
					if (func_start_addr <= previous_eip && ud_obj.mnemonic == UD_Iret) {
						set_breakpoint(task, previous_eip, &top);
						psymbol_table[i].ret_inst_address[ psymbol_table[i].ret_address_num ] = previous_eip;
						psymbol_table[i].ret_address_num++;
					}
					previous_eip = ud_obj.pc + text_section_vmaddr;
				}
				if (0 < psymbol_table[i].ret_address_num) {
					set_breakpoint(task, psymbol_table[i].nlist64.n_value, &top);
				}
			}
			debug_printf("break point insert\n");
			unmap_binary(&bininfo);
		} else {
			/* break point */
			/* 1, Get current address from RIP value.
			 * 2, Find current function name by EIP, and Logging.
			 * 3, Substitute original instruction code for current break point code(0x90).
			 * 4, Decrement EIP value.
			 * 5, Execute only one op-code.
			 * 6, Substitute 0x90 for oroginal code (located in entrance of function).
			 */
			uint64_t rip;
			read_process_register_64(task, RIP, &rip);
			if (is_breakpoint(rip - 1, &top) == 1) {
				stack_depth = breakpoint_handler(rip - 1, psymbol_table, nsym, stack_depth);
				write_process_register_64(task, RIP, RELATIVE_VAL, -1);
				disable_breakpoint(task, rip - 1, &top);
				ptrace(PT_STEP, child_proc, (caddr_t)1, 0);
				set_breakpoint(task, rip - 1, &top);
			}
		}
		wait_cnt++;
		ptrace(PT_CONTINUE, child_proc, (caddr_t)1, 0);
	}
}

char **parse_args(int argc, char **argv)
{
	int i;
	char **args = chk_malloc(sizeof(char*) * argc);
	memset(args, 0x00, sizeof(char*) * argc);
	for(i = 0; i < argc; i++) {
		args[i] = argv[i + 1];
	}
	return args;
}


int main(int argc, char **argv)
{
	char **args = parse_args(argc, argv);
	pid_t c_pid;

	c_pid = fork();
	if (c_pid == -1) {
		return -1;
	} else if(c_pid == 0) {
		target_proc(args);
	} else {
		debugger_proc(c_pid, args);
	}
	return 0;
}

