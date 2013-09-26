# Darwin-Trace

### What's this?
This is a tracer that hooks and record function-calling on Mac OS X Darwin.

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
    
Compiling this code, and execute this tracer for the binary, you would get following outputs.

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
First of all, this program fork the process, disable ASLR (Address Space Layout Randomization) and load the target binary for child process.
Next, before running the child process, this program disassembles the target binary and set breakpoints on each functions' entrance and exit address.
Then, this program will enable to start the child process.


### Build
* requirements
	* udis86 (For disassenble x86_64 binary)
	* Mac OS X(You cannot compile and execute on Linux)

* build

After install these requirements, 

		> ./waf configure
		> ./waf build

If the build is completed, a binary file named 'tracer' would be generated.
	
### execution
* Mac OS X requires root permission or a signature to open ports to other process. So, please execute like following:

		sudo ./tracer XXX(target_process)

	
