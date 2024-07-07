# CSOps-rs - A program that invokes the csops system call on MAC OS

This is a Rust version of [https://github.com/axelexic/CSOps](https://github.com/axelexic/CSOps). 

As stated on  https://github.com/axelexic/CSOps,
the csops system call, is an Apple Private system call that is used by many system deamons (mainly /usr/libexec/taskgated) to verify code signature. The 'codesign' command line utility, creates a hash of executable -- one hash per memory page -- and stores them in a code directory. 'codesign' then computes the hash of the code directory and signs this hash. While signing code, one can specify if the signature should be embedded inside the executable itself, or if it should be kept in a seperate external file or in a seperate database (/var/db/DetachedSignature, which is  sqlite3 database with two tables-- code and global). When execv/__mac_execve system call runs, it checks to see if the executable is code signed. If it is not, then it uses the TASK_ACCESS_PORT (mach port 14) in the kernel, to communicate with 'taskgated' in userspace to see if the process has a detached signature. 'taskgated', consults the executable as well as the DetachedSignature database to verify if the code was signed. (Note that this whole process results in multiple context switches, and is highly inefficient. If you want to avoid this inefficiency, you are well advised to sign your code.)

While signing code, one can specify what action the kernel should take if the signature is invalid. For invalid code, the options are to mark as 'kill' (which will send a SIGKILL to the process) or mark it as 'hard', which doesn't seem to be doing anything. These flags are checked at the time kernel executes execve (__mac_execve) system call. 

At runtime, one can use the csops system call to query and mark an already running code as invalid and kill it. This utility is a command line tool to do these things. Note that giving a PID value of 0 (zero), results in invoking these operations on the CSOps utility itself. To manipulate the state of any other process, you must have root privileges.

# Building

```
prompt$ cargo build --bin csops-bin

```

# Usage 


Usage: ./CSOps -op [operation] PID
Options are:
	status                  : Get the code signature status of the given PID.
	mark-invalid            : Invalidate the given PID's Code Signature.
	mark-hard               : Sets the CS_HARD (0x00000100) code signing flag on the given PID.
	mark-kill               : Sets the CS_KILL (0x00000200) code signing flag on the given PID.
	executable-path         : Get the executable path name of the PID. Used by taskgated.
	cd-hash                  : Get the code directory hash (CDHASH) of the given PID.
	entitlements             : Get the entitlements blob of the given PID in XML format.
	macho_offset            : Get file offset of active mach-o section of the given PID.
	blob                    : Get the entire code signing blob of the given PID.
	signing-id               : Get the code signature identity (bundle ID) of the given PID.
	mark-restrict           : Sets the CS_RESTRICT (0x00000800) code signing flagon the given PID.
	clear-installer         : Clear the CS_INSTALLER (0x00000008) code signing flag on the given PID.
	clear-platform          : Clear the CS_PLATFORM_BINARY (0x04000000) code signing flag on the given PID.
	teamid                  : Get the Team ID of the given PID.
	clear-lv                : Clear the CS_REQUIRE_LV (0x00002000) code signing flag on the given PID.
	der-entitlement         : Get the entitlements blob in DER format of the given PID.
	validation-category     : Get the validation category of the given PID.
