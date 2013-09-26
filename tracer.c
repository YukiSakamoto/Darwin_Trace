/* Standard Libraries */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* UNIX System calls related */
#include <unistd.h>
#include <sys/types.h>
#include <sys/ptrace.h>
#include <dirent.h>
#include <errno.h>

/* Mach Port related */
#include <mach/mach.h>
#include <spawn.h>
#include <udis86.h>

/* This program's headers */
#include "tracer.h"
#include "memory_op.h"
#include "functable.h"

extern int errno;
#define RESET_ERROR (errno=0)
#define ERROR_OCCURED (errno!=0)

char *function_unknown = "UnknownFunction";

void *chk_malloc(size_t size)
{
	void *p = malloc(size);
	if (p == NULL) {
		debug_printf("NULL returned by malloc!\n");
	} 
	return p;
}

void chk_free(void *p)
{
	if (p != NULL) {
		free(p);
	}
}

void target_proc(struct execute_context *ctx)
{
	int ret;

        char **args = ctx->passing_args;
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
		/*"start",*/
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


void debugger_proc(pid_t child_proc, struct execute_context *ctx)
{
	/* about child process */
	int child_stat;
	kern_return_t kret;
	mach_port_t task;
	int wait_cnt = 0;
        char **args = ctx->passing_args;

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
			/*display_symbol_table(psymbol_table, nsym); */

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


const 
struct option options[] = {
	{	"-v",           OPT_VERBOSE, 0	},
	{	"--verbose",    OPT_VERBOSE, 0	},
	{	"UNKNOWN",	OPT_UNKNOWN, 0	},
};


static 
unsigned int lookup_optnum(char *str)
{
    int i;
    for(i = 0; i < options[i].opt_num != OPT_UNKNOWN; i++) {
        if (strcmp(options[i].opt_str, str) == 0) {
            return i;
        }
    }
    return -1;
}


/* check if file (passed as basename) exists in dirpath
 * If it is found, this function will return the fullpath, 
 * but otherwise NULL
 */
char *lookup_file(char *dirpath, char *basename)
{
    DIR *dir;
    struct dirent *dp;
    char *fullpath = NULL;  /* malloc if target is found */
    int requirelen = strlen(dirpath) + strlen(basename) + 1;
    if ((dir = opendir(dirpath)) != NULL) {
        while((dp = readdir(dir)) != NULL) {
            if (strcmp(dp->d_name, basename) == 0) {
                /* found */
                fullpath = calloc(sizeof(char), requirelen);
                sprintf(fullpath, "%s/%s", dirpath, dp->d_name);
                break;
            }
        }
        closedir(dir);
    }
    return fullpath;
}

char *search_binary_path(char *cmd)
{
    char *path_env_str;
    char *err_msg = NULL;
    char *searched_path;

    char current_search_dir[1024];
    int i;
    char *p;
    
    /* check if it is relative path from current directory */
    if (*(cmd + 0) == '.' && *(cmd + 1) == '/') {
        searched_path = calloc(sizeof(char), strlen(cmd) + 1);
        strcpy(searched_path, cmd);
        err_msg = "relative pat";
        goto found;
    }
    if (strchr(cmd, '/') != NULL) {
        /* slash containing => denote relative path */
        searched_path = calloc(sizeof(char), strlen(cmd) + 1);
        strcpy(searched_path, cmd);
        err_msg = "containing /";
        goto found;
    }

    /* search by environt variable PATH */
    path_env_str = getenv("PATH");
    if (path_env_str == NULL) 
        err_msg = "getenv() returned NULL to get PATH";

    i = 0; 
    p = path_env_str;
    memset(current_search_dir, 0x00, sizeof(current_search_dir));
    do {
        if ( *p == ':' || *p == '\0' ) {
            current_search_dir[i] = '\0';
            searched_path = lookup_file(current_search_dir, cmd);
            if (searched_path != NULL) {
                err_msg = "Found";
                goto found;
            } else {
                i = 0;
            }
        } else {
            current_search_dir[i] = *p;
            i++;
        }
        p++;
    } while( *p != '\0' );
    if (searched_path == NULL) {
        err_msg = "not found in environment path";
    }
found:
    printf("%s\n", searched_path);
    return searched_path;
error:
    return NULL;
}

void parse_opt(int argc, char **argv, struct execute_context *exec_ctx)
{
    int i;
    int j;
    int optdict_index;
    char *p;
    /* initializing and store the arguments */
    exec_ctx->argc = (unsigned int)argc;
    exec_ctx->argv = argv;
    exec_ctx->opt_flags = 0x00;
    exec_ctx->fullpath = NULL;

    /* parse options for this program */
    for(i = 1; i <= exec_ctx->argc; i++) {
        if ( (*exec_ctx->argv[i]) == '-') {
            optdict_index = lookup_optnum(exec_ctx->argv[i]);
            if (optdict_index != -1) {
                debug_printf(stderr, "argument for this program: %s\n", exec_ctx->argv[i]);
                exec_ctx->opt_flags |= options[optdict_index].opt_num;
            }
        } else {
            break;
        }
    }
    /* copy options for forked (target) program */
    exec_ctx->passing_args_count = exec_ctx->argc - i;
    exec_ctx->passing_args = chk_malloc( sizeof(char*) * (exec_ctx->passing_args_count + 1) );
    memset(exec_ctx->passing_args, 0x00, sizeof(char*) * (exec_ctx->passing_args_count + 1) );
    for(j = 0 ; i <= exec_ctx->passing_args_count; i++, j++) {
        exec_ctx->passing_args[j] = exec_ctx->argv[i];
        debug_printf(stderr, "passing: %s\n", exec_ctx->argv[i]);
    }
    p = search_binary_path(exec_ctx->passing_args[0]);
    if (p != NULL) {
        exec_ctx->passing_args[0] = p;
    }
    return;
}

/* ENTRY POINT */
int main(int argc, char **argv)
{
	struct execute_context exec_ctx;
	pid_t c_pid;
        debug_printf(stderr,"start!\n");
        parse_opt(argc, argv, &exec_ctx);
	fprintf(stderr, "[Tracer] Target program is %s\n", exec_ctx.passing_args[0]);

	c_pid = fork();
        exec_ctx.target_pid = c_pid;
	if (c_pid == -1) {
		return -1;
	} else if(c_pid == 0) {
		target_proc(&exec_ctx);
	} else {
		debugger_proc(c_pid, &exec_ctx);
	}
	chk_free(exec_ctx.passing_args);
	return 0;
}

