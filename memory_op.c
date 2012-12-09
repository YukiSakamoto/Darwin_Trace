
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <unistd.h>
#include <sys/types.h>
#include <sys/ptrace.h>
#include <errno.h>

#include <mach/mach.h>

#include "memory_op.h"
/* [out] value 	*/
int read_process_register_32(mach_port_t task, int register_type, int32_t *value)
{
	int ret = 0;
	kern_return_t kret;
	thread_act_port_array_t thread_list;
	mach_msg_type_number_t thread_count;
	x86_thread_state32_t state;
	mach_msg_type_number_t state_count = x86_THREAD_STATE32_COUNT;

	kret = task_threads(task, &thread_list, &thread_count);
	printf("thread_count = %d\n", thread_count);
	kret = thread_get_state( thread_list[0], x86_THREAD_STATE32, (thread_state_t)&state, &state_count);
	if (kret != KERN_SUCCESS) {
		printf("thread_get_state() failed\n");
		printf("%s\n", mach_error_string(kret));
		return -1;
	}
	/*printf("eip: %x \n", state.__eip);*/
	switch (register_type) {
		case EAX:
			*value = state.__eax;
			break;
		case EBX:
			*value = state.__ebx;
			break;
		case ECX:
			*value = state.__ecx;
			break;
		case EDX:
			*value = state.__edx;
			break;
		case ESI:
			*value = state.__esi;
			break;
		case EDI:
			*value = state.__edi;
			break;
		case ESP:
			*value = state.__esp;
			break;
		case EBP:
			*value = state.__ebp;
			break;
		case EIP:
			*value = state.__eip;
			break;
	}
	return 0;
}

int write_process_register_32(mach_port_t task, int register_type, int way, int value)
{
	int ret = 0;
	kern_return_t kret;
	thread_act_port_array_t thread_list;
	mach_msg_type_number_t thread_count;
	x86_thread_state32_t state;
	mach_msg_type_number_t state_count = x86_THREAD_STATE32_COUNT;
	uint32_t *p_reg;

	kret = task_threads(task, &thread_list, &thread_count);
	/*printf("thread_count = %d\n", thread_count);*/
	kret = thread_get_state( thread_list[0], x86_THREAD_STATE32, (thread_state_t)&state, &state_count);
	if (kret != KERN_SUCCESS) {
		printf("thread_get_state() failed\n");
		printf("%s\n", mach_error_string(kret));
		return -1;
	}
	/*printf("eip: %llx \n", state.__rip);*/

	switch (register_type) {
		case RAX:
			p_reg = &(state.__eax);
			break;
		case RBX:
			p_reg = &(state.__ebx);
			break;
		case RCX:
			p_reg = &(state.__ecx);
			break;
		case RDX:
			p_reg = &(state.__edx);
			break;
		case RSI:
			p_reg = &(state.__esi);
			break;
		case RDI:
			p_reg = &(state.__edi);
			break;
		case RSP:
			p_reg = &(state.__esp);
			break;
		case RBP:
			p_reg = &(state.__ebp);
			break;
		case RIP:
			p_reg = &(state.__eip);
			break;
		default:
			p_reg = NULL;
			printf("invalid register.\n");
			return -1;
	}

	if (way == ABSOLUTE_VAL) {
		*p_reg = value;
	} else if (way == RELATIVE_VAL) {
		*p_reg += value;
	} else {
		fprintf(stderr, "invalue parameter(%s)\n", __func__);
		return -1;
	}

	/*state.__rip--; */
	kret = thread_set_state(thread_list[0], x86_THREAD_STATE64, (thread_state_t)&state, state_count);
	if (kret != KERN_SUCCESS) {
		printf("thread_set_state() failed\n");
		printf("%s\n", mach_error_string(kret));
		return -1;
	}
	return 0;
}

int write_process_register_64(mach_port_t task, int register_type, int way, int value)
{
	int ret = 0;
	kern_return_t kret;
	thread_act_port_array_t thread_list;
	mach_msg_type_number_t thread_count;
	x86_thread_state64_t state;
	mach_msg_type_number_t state_count = x86_THREAD_STATE64_COUNT;
	uint64_t *p_reg;

	kret = task_threads(task, &thread_list, &thread_count);
	/*printf("thread_count = %d\n", thread_count);*/
	kret = thread_get_state( thread_list[0], x86_THREAD_STATE64, (thread_state_t)&state, &state_count);
	if (kret != KERN_SUCCESS) {
		printf("thread_get_state() failed\n");
		printf("%s\n", mach_error_string(kret));
		return -1;
	}
	/*printf("eip: %llx \n", state.__rip);*/

	switch (register_type) {
		case RAX:
			p_reg = &(state.__rax);
			break;
		case RBX:
			p_reg = &(state.__rbx);
			break;
		case RCX:
			p_reg = &(state.__rcx);
			break;
		case RDX:
			p_reg = &(state.__rdx);
			break;
		case RSI:
			p_reg = &(state.__rsi);
			break;
		case RDI:
			p_reg = &(state.__rdi);
			break;
		case RSP:
			p_reg = &(state.__rsp);
			break;
		case RBP:
			p_reg = &(state.__rbp);
			break;
		case RIP:
			p_reg = &(state.__rip);
			break;
		default:
			p_reg = NULL;
			printf("invalid register.\n");
			return -1;
	}

	if (way == ABSOLUTE_VAL) {
		*p_reg = value;
	} else if (way == RELATIVE_VAL) {
		*p_reg += value;
	} else {
		printf("invalue parameter(%s)\n", __func__);
		return -1;
	}

	/*state.__rip--; */
	kret = thread_set_state(thread_list[0], x86_THREAD_STATE64, (thread_state_t)&state, state_count);
	if (kret != KERN_SUCCESS) {
		printf("thread_set_state() failed\n");
		printf("%s\n", mach_error_string(kret));
		return -1;
	}
	return 0;
}

int read_process_register_64(mach_port_t task, int register_type, int64_t *value)
{
	int ret = 0;
	kern_return_t kret;
	thread_act_port_array_t thread_list;
	mach_msg_type_number_t thread_count;
	x86_thread_state64_t state;
	mach_msg_type_number_t state_count = x86_THREAD_STATE64_COUNT;

	kret = task_threads(task, &thread_list, &thread_count);
	/*printf("thread_count = %d\n", thread_count);*/
	kret = thread_get_state( thread_list[0], x86_THREAD_STATE64, (thread_state_t)&state, &state_count);
	if (kret != KERN_SUCCESS) {
		printf("thread_get_state() failed\n");
		printf("%s\n", mach_error_string(kret));
		return -1;
	}
	switch(register_type) {
		case RAX:
			*value = state.__rax;
			break;
		case RBX:
			*value = state.__rbx;
			break;
		case RCX:
			*value = state.__rcx;
			break;
		case RDX:
			*value = state.__rdx;
			break;
		case RSI:
			*value = state.__rsi;
			break;
		case RDI:
			*value = state.__rdi;
			break;
		case RSP:
			*value = state.__rsp;
			break;
		case RBP:
			*value = state.__rbp;
			break;
		case RIP:
			*value = state.__rip;
			break;
		default:
			return -1;
	}
	return 0;
}

int read_write_process_memory(mach_port_t task, vm_address_t target_addr, char *r_buffer, char *w_buffer, int length)
{
	int ret = 0;
	kern_return_t kret;

	vm_address_t start_addr = 0;
	vm_address_t offset;

	/* do not forget to deallocate */
	pointer_t copied;
	int copy_count;

	/* variables for getting descriptions about memory protections */
	int _basic[VM_REGION_BASIC_INFO_COUNT];
	vm_region_basic_info_t desc_basic_info = (vm_region_basic_info_t)_basic;
	mach_port_t desc_objname;
	int desc_infocnt;
	vm_address_t desc_start;
	vm_address_t desc_range = vm_page_size;
	

	/* READING MEMORY */
	/* searching page */
	start_addr = 0;
	for(offset = target_addr; vm_page_size < offset; ) {
		offset -= vm_page_size;
		start_addr += vm_page_size;
	}
	kret = vm_read(task, start_addr, vm_page_size, &copied, &copy_count);
	if (kret != KERN_SUCCESS) {
		printf("%s\n", mach_error_string(kret));
		goto RET;
	}
	if (r_buffer != NULL) {
		/*printf("0x%x\n", (unsigned int)*(char*)(copied + offset)); */
		memcpy(r_buffer, (char*)(copied + offset), length);
		ret = 1;
	}

	if (w_buffer == NULL) {
		goto RET;
	}
	memcpy( (char*)(copied + offset), w_buffer, length);
	/*
	desc_start = start_addr;
	kret = vm_region_recurse(
					task, &desc_start, &desc_range, VM_REGION_BASIC_INFO,
					(vm_region_info_t)desc_basic_info, &desc_infocnt, 
					&desc_objname);
	if (kret != KERN_SUCCESS) {
		printf("vm_region failed!\n");
		printf("%s\n", mach_error_string(kret));
	}*/

	/* PERMIT WRITING */ 
	ret = 0;	/* reset return val. */
	kret = vm_protect(task, start_addr, vm_page_size, FALSE, VM_PROT_WRITE | VM_PROT_READ | VM_PROT_EXECUTE);
	if (kret != KERN_SUCCESS) {
		printf("vm_region failed\n");
		printf("%s\n", mach_error_string(kret));
	}

	/* WRITING MEMORY */
	kret = vm_write(task, start_addr, copied, vm_page_size);
	if (kret != KERN_SUCCESS) {
		printf("vm_write failed\n");
		printf("%s\n", mach_error_string(kret));
		goto RET;
	}
	ret = 1;

RET:
	kret = vm_deallocate(task, copied,  copy_count);
	if (kret != KERN_SUCCESS) {
		printf("vm_deallocate failed\n");
		printf("%s\n", mach_error_string(kret));
	}
	return ret;
}
