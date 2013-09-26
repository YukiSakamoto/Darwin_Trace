
#ifndef _TRACER_MAIN_HEADER
# define _TRACER_MAIN_HEADER
struct execute_context {
	unsigned int argc;
        char **argv;
        unsigned int opt_flags;

        char **passing_args;
        int passing_args_count;
};

struct option {
	char opt_str[32];
	unsigned int  opt_num;
        int  has_value; /* 0 or 1 */

};

#define OPT_UNKNOWN		0x0000
#define OPT_VERBOSE		0x0001

#endif
