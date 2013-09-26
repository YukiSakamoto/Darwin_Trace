# Darwin-Trace

### What's this?
This is a tracer that hooks and tracks function-calling and returning on Mac OS X Darwin.

This is an example.



	#include <stdio.h>

	int fibonacci(int i) {
		if (i == 0 || i == 1) {
			return 1;
		} else {
			return fibonacci(i - 1) + fibonacci(i - 2);
		}
	}

	int main(void)
	{
    	printf("%d\n", fibonacci(3));
    	return 0;
    }
    
Compiling this code, and execute this tracer passed above program's name as an argument, you would get following outputs.

	$> sudo ./tracer testcode/fibonacci
	Password:
	[Tracer] child_proc: 73550
	[Tracer] ===> [ _main (at 0x100000ec0)]
	[Tracer]     ===> [ _fibonacci (at 0x100000e60)]
	[Tracer]         ===> [ _fibonacci (at 0x100000e60)]
	[Tracer]             ===> [ _fibonacci (at 0x100000e60)]
	[Tracer]             <=== [ _fibonacci (at 0x100000ebb)]
	[Tracer]             ===> [ _fibonacci (at 0x100000e60)]
	[Tracer]             <=== [ _fibonacci (at 0x100000ebb)]
	[Tracer]         <=== [ _fibonacci (at 0x100000ebb)]
	[Tracer]         ===> [ _fibonacci (at 0x100000e60)]
	[Tracer]         <=== [ _fibonacci (at 0x100000ebb)]
	[Tracer]     <=== [ _fibonacci (at 0x100000ebb)]
	3
	[Tracer] <=== [ _main (at 0x100000efd)]
	[Tracer]  Process :73550 Terminated
	

### Mechanism

	1. Fork the process
	2. Disable ASLR(short of Address Space Layout Randomization) and load the target binary for child process.
	3. Before running the child process, parent program disassemble the target binary, and set brekpoints on each functions' entrypoint and exit points.
	4. Run.


### Build
* requirements
	* udis86 (For disassenble)
	* Mac OS X(You cannot compile and execute on Linux)

* build

		> ./waf configure
		> ./waf build
		> ./waf install		( <- this is option )

If the build is completed, a binary file named 'tracer' would be generated.
	
### execution
* Mac OS X requires root permission or a signature to open ports to other process. So, please execute like following:

		sudo ./tracer XXX(target_program)

	
