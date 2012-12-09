
enum register_32 {
	EAX = 1000,
	EBX,
	ECX,
	EDX,
	ESI,
	EDI,
	ESP,
	EBP,
	EIP,
};

enum register_64 {
	RAX = 2000,
	RBX,
	RCX,
	RDX,
	RSI,
	RDI,
	RSP,
	RBP,
	RIP,
};


#define ABSOLUTE_VAL	0x00
#define RELATIVE_VAL	0x01


int read_process_register_32(mach_port_t task, int register_type, int32_t *value);
int write_process_register_32(mach_port_t task, int register_type, int way, int value);

int read_process_register_64(mach_port_t task, int register_type, int64_t *value);
int write_process_register_64(mach_port_t task, int register_type, int way, int value);

int read_write_process_memory(mach_port_t task, vm_address_t target_addr, char *r_buffer, char *w_buffer, int length);
