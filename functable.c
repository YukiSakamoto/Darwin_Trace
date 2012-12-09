#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <unistd.h>
#include <fcntl.h>

#ifndef _MACHO_LOADER_H
#	include <mach-o/loader.h>
#	include <mach-o/fat.h>
#	include <mach-o/nlist.h>
#endif

#include "functable.h"

#ifdef debug_mode
#	define debug_printf(...) printf(__VA_ARGS__)
#	define debug_putchar(a) putchar(a)
#else
#	define debug_printf(...) 
#	define debug_putchar(a)
#endif

#define EXPORT




void __print_nlist64(struct nlist_64 *p)
{
	int output = 1;

	if (output != 0) {
		printf("\tn_type:\t0x%02x\n", p->n_type);
		printf("\tn_sect:\t0x%02x\n", p->n_sect);
		printf("\tn_desc:\t0x%02x\n", p->n_desc);
		printf("\tn_value:\t0x%02llx\n", p->n_value);
	}
}


uint32_t load_command_list[] = {
	LC_REQ_DYLD,
	LC_SEGMENT,	
	LC_SYMTAB,
	LC_SYMSEG,
	LC_THREAD,
	LC_UNIXTHREAD,
	LC_LOADFVMLIB,
	LC_IDFVMLIB,
	LC_IDENT,
	LC_FVMFILE,
	LC_PREPAGE,   
	LC_DYSYMTAB,
	LC_LOAD_DYLIB,
	LC_ID_DYLIB	,
	LC_LOAD_DYLINKER ,
	LC_ID_DYLINKER,
	LC_PREBOUND_DYLIB ,
	LC_ROUTINES	,
	LC_SUB_FRAMEWORK ,
	LC_SUB_UMBRELLA ,
	LC_SUB_CLIENT	,
	LC_SUB_LIBRARY ,
	LC_TWOLEVEL_HINTS ,
	LC_PREBIND_CKSUM,
	LC_LOAD_WEAK_DYLIB ,
	LC_SEGMENT_64,
	LC_ROUTINES_64,
	LC_UUID,
	LC_RPATH,
	LC_CODE_SIGNATURE,
	LC_SEGMENT_SPLIT_INFO ,
	LC_REEXPORT_DYLIB,
	LC_LAZY_LOAD_DYLIB,
	LC_ENCRYPTION_INFO,
	LC_DYLD_INFO,
	LC_DYLD_INFO_ONLY,
	LC_LOAD_UPWARD_DYLIB,
	LC_VERSION_MIN_MACOSX,
	LC_VERSION_MIN_IPHONEOS,
	LC_FUNCTION_STARTS,
	LC_DYLD_ENVIRONMENT,
};

const int load_command_list_size = sizeof(load_command_list) / sizeof(uint32_t);

int map_binary(char *binpath, struct file_info *bin_struct)
{
	int fd;
	struct stat fs;
	char *top = NULL;
	int ret;
	fd = open(binpath, O_RDONLY);
	if (fd == -1) 
		goto CLOSING;
	if (fstat(fd, &fs) < 0) {	goto CLOSING;	}
	top = mmap(NULL, fs.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
	if (top == MAP_FAILED) 	{	
		top = NULL;
		goto CLOSING;	
	}
	ret = 1;
CLOSING:
	strcpy(bin_struct->path, binpath);
	bin_struct->top = top;
	bin_struct->fd = fd;
	return ret;
}

void unmap_binary(struct file_info *p)
{
	if (p != NULL && p->top != NULL) {
		close(p->fd);
		p->top == NULL;
		debug_printf("unmap_binary done\n");
	}
}

/* for library */
static
char *get_first_loadcommand(char *mapped_binary)
{
	char *ret = NULL;
	if (mapped_binary != NULL) {
		uint32_t magic = *(uint32_t*)mapped_binary;
		if (magic == MH_MAGIC || magic == MH_CIGAM) {
			ret = mapped_binary + sizeof(struct mach_header);
		} else if (magic == MH_MAGIC_64 || magic == MH_CIGAM_64) {
			ret = mapped_binary + sizeof(struct mach_header_64);
		}
	}
	return ret;
}

/* for library */
static
char *get_next_loadcommand(char *mapped_binary, char *pcurrent)
{
	int i;
	int check = 0;
	char *ret = NULL;
	struct load_command *current_struct = (struct load_command*)pcurrent;
	for(i = 0; i < load_command_list_size; i++) {
		if (current_struct->cmd == load_command_list[i]) {
			check = 1;
			break;
		}
	}
	if (check == 1) {
		ret = pcurrent + current_struct->cmdsize;
	}
	return ret;
}

static
void read_mach_header2(struct mach_header *p, char *mapped_binary)
{
	if (mapped_binary != NULL && p != NULL) {
		char *cur = mapped_binary;
		p->magic = *(uint32_t*)cur;
		cur += sizeof(uint32_t);

		p->cputype = *(cpu_type_t*)cur;
		cur += sizeof(cpu_type_t);

		p->cpusubtype = *(cpu_subtype_t*)cur;
		cur += sizeof(cpu_subtype_t);

		p->filetype = *(uint32_t*)cur;
		cur += sizeof(uint32_t);

		p->ncmds = *(uint32_t*)cur;
		cur += sizeof(uint32_t);

		p->sizeofcmds = *(uint32_t*)cur;
		cur += sizeof(uint32_t);

		p->flags = *(uint32_t*)cur;
	}
}

/* for library */
extern
int get_namedsymbol_table(char *mapped_binary, struct symbol_info **ppsymbol_array)
{
	/* XXX mach header parsing is need */
	int i;
	register void *rp;
	struct mach_header mh;
	uint32_t loadcommand_type;

	/* variables for parsing symbol table */
	struct symtab_command *p_symtab;
	char *p_symbol_strtable = NULL;
	int nsyms;
	struct nlist_64 *p_nlist;

	struct symbol_info *psymbol_list_top;
	register struct symbol_info *rp_symbol_info;
	char *p_symbol_string_table = NULL;
	
	if (mapped_binary == NULL)	return -1;
	read_mach_header2(&mh, mapped_binary);
	rp = get_first_loadcommand(mapped_binary);
	for(i = 0; i < mh.ncmds; i++, rp = get_next_loadcommand(mapped_binary, rp)) {
		loadcommand_type = ((struct load_command*)rp)->cmd;
		if (loadcommand_type == LC_SYMTAB) {
			debug_printf("%s found LC_SYMTAB\n", __func__);
			/* symtab command */
			p_symtab = (struct symtab_command*)rp;
			p_symbol_string_table = mapped_binary + p_symtab->stroff;
			p_nlist = (struct nlist_64*)(mapped_binary + p_symtab->symoff);
			nsyms = p_symtab->nsyms;
			goto FOUND_SYMBOL_TABLE;
		}
	}
FOUND_SYMBOL_TABLE:
	/* copy */
	psymbol_list_top = malloc(sizeof(struct symbol_info) * nsyms);
	for(i = 0, rp_symbol_info = psymbol_list_top; i < nsyms; i++, rp_symbol_info++, p_nlist++) {
		strcpy(rp_symbol_info->name, p_symbol_string_table + p_nlist->n_un.n_strx);
		debug_printf("[ %s ]: n_type: %02x, n_value: %llx, n_sect: %d\n", rp_symbol_info->name, p_nlist->n_type, p_nlist->n_value, p_nlist->n_sect);
		rp_symbol_info->nlist64 = *p_nlist;
	}
	*ppsymbol_array = psymbol_list_top;
RET:
	return nsyms;
}

int is_x86_64(struct mach_header *mh)
{
	int ret = 0;
	if (mh->magic == MH_MAGIC_64) {
		ret++;
	}
	return ret;
}

int is_x86(struct mach_header *mh)
{
	int ret = 0;
	if (mh->magic == MH_MAGIC) {
		ret++;
	}
	return ret;
}

void read_section_64(char *p)
{
	char buffer[512];
	struct section_64 *p_sec = (struct section_64*)p;
	debug_printf("\t====SECTION====\n");
	debug_printf("\t\t");
	debug_printf("sectname: %s\n", p_sec->sectname);
	debug_printf("\t\t");
	debug_printf("segname:  %s\n", p_sec->segname);
	debug_printf("\t\t");
	debug_printf("addr: 0x%llx\n", p_sec->addr);
	debug_printf("\t\t");
	debug_printf("size: %llu\n", p_sec->size);
	debug_printf("\t\t");
	debug_printf("offset: %u\n", p_sec->offset);
	debug_printf("\t\t");
	debug_printf("align:  %u\n", p_sec->align);
	debug_printf("\t\t");
	debug_printf("reloff: %u\n", p_sec->reloff);
	debug_printf("\t\t");
	debug_printf("nreloc: %u\n", p_sec->nreloc);

}

char *find_text_section64_struct(char *mapped_binary, int *section_nth)
{
	char *ret = NULL;
	int i;
	int section_index = 1;
	register void *rp;
	uint32_t loadcommand_type;
	struct mach_header mh;
	if (mapped_binary == NULL)
		goto RET;
	read_mach_header2(&mh, mapped_binary);
	rp = get_first_loadcommand(mapped_binary);
	for(i = 0; i < mh.ncmds; i++, rp = get_next_loadcommand(mapped_binary, rp)) {
		loadcommand_type = ((struct load_command*)rp)->cmd;
		if (loadcommand_type == LC_SEGMENT_64) {
			int j;
			struct segment_command_64 *p_segcmd = (struct segment_command_64*)rp;
			register void *rp2 = rp + sizeof(struct segment_command_64);

			for(j = 0; j < p_segcmd->nsects; j++) {
				struct section_64 *p_sec64 = (struct section_64*)rp2;
				if (strcmp(p_sec64->sectname, "__text") == 0) {
					ret = (void*)p_sec64;
					*section_nth = section_index;
					break;
				}
				section_index++;
				rp2 += sizeof(struct section_64);
			}

			if (ret != NULL) {
				goto RET;
			}
		}
	}

RET:
	return ret;
}


void read_lc_segment64(char *p)
{
	int i;
	char buffer[1024];
	struct segment_command_64	*p_segcmd = (struct segment_command_64*)p;
	if (p_segcmd->cmd != LC_SEGMENT_64)	return;
	
	debug_putchar('\t');
	debug_printf("segname: %s\n", p_segcmd->segname);
	debug_putchar('\t');
	debug_printf("vmaddr:  0x%llx\n", p_segcmd->vmaddr);
	debug_putchar('\t');
	debug_printf("vmsize:  0x%llx\n", p_segcmd->vmsize);
	debug_putchar('\t');
	debug_printf("fileoff: 0x%llx\n", p_segcmd->fileoff);
	debug_putchar('\t');
	debug_printf("filesize:0x%llx\n", p_segcmd->filesize);
	debug_putchar('\t');
	debug_printf("nsects:  %d\n", p_segcmd->nsects);

	p += sizeof(struct segment_command_64);
	for(i = 0; i < p_segcmd->nsects; i++) {
		read_section_64(p);
		p += sizeof(struct section_64);
	}
}

extern
int get_func_table(char *filename, struct symbol_info **ppsymbol_table, int *ptext_section_index, uint64_t *ptext_section_offset, uint64_t *ptext_section_size, uint64_t *ptext_section_vmaddr)
{
	struct symbol_info *psymbol_table, *pfunc_table;
	char *is_func_judge;
	struct file_info bininfo;
	int nsym = 0;
	int text_section;
	int i, j;
	int func_count;
	int ret = -1;

	struct section_64 *p_text_sec64;
	if (filename == NULL)
		goto ENSURE;

	map_binary(filename, &bininfo);
	nsym = get_namedsymbol_table(bininfo.top, &psymbol_table);
	p_text_sec64 = (struct section_64*) find_text_section64_struct(bininfo.top, &text_section);
	if (0 < nsym && text_section == -1 && p_text_sec64 != NULL) {
		goto ENSURE;
	}

	/* exclude non-function symbols */
	is_func_judge = (char*) malloc(sizeof(char) * nsym);
	if (is_func_judge == NULL) {
		fprintf(stderr, "malloc error\n");
		goto ENSURE;
	}

	memset(is_func_judge, 0x00, sizeof(char) * nsym);
	func_count = 0;
	for(i = 0; i < nsym; i++) {
		if ( ((psymbol_table[i].nlist64.n_type) & N_TYPE) == N_SECT && 
						psymbol_table[i].nlist64.n_sect == text_section && 0 < strlen(psymbol_table[i].name) ) {
			debug_printf("%s\n", psymbol_table[i].name);
			func_count++;
			*(is_func_judge + i) = 0x01;
		}
	}
	pfunc_table = (struct symbol_info*) malloc(sizeof(struct symbol_info) * func_count);
	for(i = 0, j = 0; i < nsym; i++) {
		if ( 0 < *(is_func_judge + i) ) {
			pfunc_table[j] = psymbol_table[i];	j++;
		}
	}
	debug_printf(" j %s= func_count \n", j == func_count ? "=" : "!" );
	debug_printf("func_count : %d  j : %d \n", func_count , j);

	/* prepare returning */
	free(psymbol_table);
	ret = func_count;
	*ppsymbol_table = pfunc_table;
	*ptext_section_index = text_section;
	*ptext_section_offset= p_text_sec64->offset;
	*ptext_section_size  = p_text_sec64->size;
	*ptext_section_vmaddr= p_text_sec64->addr;
ENSURE:
	unmap_binary(&bininfo);
	return ret;
}


#ifdef UNITTEST
int main(int argc, char **argv)
{
	int i;
	int nsym;
	struct symbol_info *psymbol_table;
	int text_section;
	if (argc == 1) {
		printf("too few arguments\n");
		return 0;
	}
	nsym = get_func_table(argv[1], &psymbol_table, &text_section);
	printf("nsym: %d\n", nsym);
	printf("text_section: %d\n", text_section);
	for(i = 0; i < nsym; i++) {
		if (psymbol_table[i].nlist64.n_sect == text_section && 0 < strlen(psymbol_table[i].name) && 
						psymbol_table[i].nlist64.n_type & N_TYPE == N_SECT && psymbol_table[i].nlist64.n_sect == text_section)
		{
			printf("==================================================\n");
			printf("%s  \n", psymbol_table[i].name);
			__print_nlist64( &(psymbol_table[i].nlist64) );
		}
	}
	return 0;
}
#endif
