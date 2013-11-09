
#ifndef _TRACER_MAIN_HEADER
# define _TRACER_MAIN_HEADER

struct execute_context {
    unsigned int argc;
    char **argv;
    unsigned int opt_flags;
    char **passing_args;
    int passing_args_count;
    pid_t target_pid;
    char **fullpath;
};

struct option {
    char opt_str[32];
    unsigned int  opt_num;
    int  has_value; /* 0 or 1 */
};

#define OPT_UNKNOWN 0x0000
#define OPT_VERBOSE 0x0001


#ifdef debug_mode
#   define debug_printf(...)	printf("[[DebugPrint]]   ");printf(__VA_ARGS__)
#else
#   define debug_printf(...)
#endif

#endif
