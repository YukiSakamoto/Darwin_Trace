
#ifndef _MACHO_LOADER_H
#	include <mach-o/loader.h>
#	include <mach-o/fat.h>
#	include <mach-o/nlist.h>
#endif

struct file_info {
	char 	path[256];
	char	*top;
	int 	fd;
};

struct symbol_info {
	char name[256];
	struct nlist_64 nlist64;
	uint64_t ret_inst_address[128];
	int ret_address_num;
};

int map_binary(char *binpath, struct file_info *bin_struct);
/*
int get_func_table(char *filename, struct symbol_info **ppsymbol_table, int *ptext_section_index, uint64_t *text_section_offset);
*/
int get_func_table(char *filename, struct symbol_info **ppsymbol_table, int *ptext_section_index, uint64_t *text_section_offset, uint64_t *text_section_size, uint64_t *text_section_vmaddr);

