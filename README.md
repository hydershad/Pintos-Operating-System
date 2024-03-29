# Pintos OS
Pintos is a simple operating system framework for the 80x86 architecture. It supports kernel threads, loading and running user programs, and a file system, but it implements all of these in a very simple way. 

Here are the following files that have been written by Hyder Shad and Kiptoo Touni:

In Userprog

   process.c 

   process.h 
   Loads ELF binaries and starts processes. 

   pagedir.c 

   pagedir.h 
   A simple manager for 80x86 hardware page tables. Although you probably won't want to modify this code for this project, you may want to call some of its functions. See section 4.1.2.3 Page Tables, for more information. 

   syscall.c 

   syscall.h 
   Whenever a user process wants to access some kernel functionality, it invokes a system call. This is a skeleton system call handler. Currently, it just prints a message and terminates the user process. In part 2 of this project you will add code to do everything else needed by system calls. 

   exception.c 

   exception.h 
   When a user process performs a privileged or prohibited operation, it traps into the kernel as an "exception" or "fault."(3) These files handle exceptions. Currently all exceptions simply print a message and terminate the process. Some, but not all, solutions to project 2 require modifying page_fault() in this file. 

In Virtual Memory

   All files
   
In Filesystems

   fsutil.c 
   Simple utilities for the file system that are accessible from the kernel command line. 

   filesys.h 

   filesys.c 
   Top-level interface to the file system. See section 3.1.2 Using the File System, for an introduction. 

   directory.h 

   directory.c 
   Translates file names to inodes. The directory data structure is stored as a file. 

   inode.h 

   inode.c 
   Manages the data structure representing the layout of a file's data on disk. 

   file.h 

   file.c 
   Translates file reads and writes to disk sector reads and writes. 

   lib/kernel/bitmap.h 

   lib/kernel/bitmap.c 
   A bitmap data structure along with routines for reading and writing the bitmap to disk files. 



# How to install pintos

0. Make sure that the dependencies have been installed:
   - `sudo apt-get update`
   - `sudo apt-get install qemu`
   - `sudo apt-get install realpath`
1. Run this command: `source install.sh`
2. If that doesn't work, read the error messages.

# How to check if pintos was installed correctly 

0. Run `which pintos`. It should output something like this: `/home/username/utils/pintos`
1. Cd into the `userprog` directory 
2. Run `make` 
3. Run `make check` 
   - This should take around 5-10 minutes to finish. If you get a bunch of tests being run and at the end you get 76/76 test cases failed, then your installation worked
   - If it doesn't finish (e.g. you get stuck in an infinte loop then the installation didn't work)
   - If you are using a newer version of Linux and have an infinite loop, please follow the instructions [here](https://github.com/justintemp/Pintos_Starter/blob/master/temp/PintosFixInfiniteLoop.md)
   - The final output should look like this
   
   ![alt text](https://github.com/justintemp/Pintos_Starter/raw/master/temp/PintosInstallSucess.png "Wow I can't believe you failed all of the tests")
   
# How to fix the installation if it suddenly stopped working

0. Even if you install pintos correctly, it could end up not being installed correctly later down the line if you change your directory structure (this is because your paths to the pintos files changed)
1. You'll know if there is an issue if you can't run `make check` and if `which pintos` doesn't output anything.
2. To fix that, you can try re-running the script
3. If that doesn't work, take a look at the following files
4. In your `~/.bashrc` file, there should be a line that looks something like this with the correct path to your `.PINTOS_PATH` file: `source /home/username/Pintos_Starter/.PINTOS_PATH`. You can see files that start with `.` by running `ls -al`
5. Check the contents of the `.PINTOS_PATH` file. It should look something like this: 

`export PATH=$PATH:/home/username/Pintos_Starter/utils`

6. In your `~/.bashrc` file, there should also be something that looks like this: 

`alias pintos-gdb='GDBMACROS=/home/username/Pintos_Starter/misc/gdb-macros pintos-gdb'`

7. Run `echo $PATH`. It should have a bunch of stuff, but there should be something like this in it: 

`/home/username/Pintos_Starter/utils/`

# How to run all of the pintos tests

0. Go into the directory for the current project (for the first pintos project, this will be the userprog directory): `cd userprog`
1. Build the directory with `make`
2. Run `make check`:
   - You'll see a lot of stuff being output, but if you're patient for about 10-30 minutes, you'll get a summary of your results at the end.
   
# How to get your grade

0. The tests are weighted. You can see the actual grade by running `make grade`
1. Some of the tests involve synchronization and race conditions. The grading script runs 3 times and takes the lowest of the 3 grades so make sure to run `make grade` several times and make sure you get the same grade each time

# How to run a single pintos test

With the help of Dr. Google, I was able to write a convenient script for you all.

0. Open up the `run_pintos_tests.sh` file in the `userprog` directory and change it to use the tests that you want to run
1. Simply add to (or remove from) the list of test files you see in the `TEST_FILES` variable
2. The list of all the tests can be seen by running `ls build/tests/userprog` (all of the green executables in here are test files)

Things to note
   - You can redirect anything you don't care about to /dev/null
   - The script redirects the result of the test to /dev/null and prints the output of the test by default. You can easily change this by changing the file redirection

# How to debug a pintos test with GDB

This is rather cumbersome, so just bear with me.

First run `make check` and then kill it with Ctrl-c after you get some output that looks like this:

```
cd build && make check
make[1]: Entering directory '/home/justin/Github/Pintos_Labs/userprog/build'
pintos -v -k -T 60 --qemu  --filesys-size=2 -p tests/userprog/args-none -a args-none -- -q  -f run args-none < /dev/null 2> tests/userprog/args-none.errors > tests/userprog/args-none.output
perl -I../.. ../../tests/userprog/args-none.ck tests/userprog/args-none tests/userprog/args-none.result
fail tests/userprog/args-none
```

There are three things for each test that gets run:

(1)
`pintos -v -k -T 60 --qemu  --filesys-size=2 -p tests/userprog/args-none -a args-none -- -q  -f run args-none < /dev/null 2> tests/userprog/args-none.errors > tests/userprog/args-none.output`

(2)
`perl -I../.. ../../tests/userprog/args-none.ck tests/userprog/args-none tests/userprog/args-none.result`

(3)
`fail tests/userprog/args-none`

You really only care about the first one. Copy the entire command except for everything after the `< /dev/null` part since that is just used to redirect output and error messages (look familiar?)

Paste what you just copied onto the command line. 
   - Don't press enter yet
   - Edit the beginning of the command to say `pintos --gdb` instead of just `pintos`
   - Make sure the path is right (i.e. change the `tests/userprog/args-none` to have build/ in front of it: `build/tests/userprog/args-none`
   - Now you can hit enter

You'll notice that the output is paused. This is because the pintos process you just ran is waiting for you to attach your GDB debugger. 

Open up a new terminal tab with the shortcut Ctrl-Shift-t
   - Run the script to attach your GDB debugger to the running pintos process: `./attachGdb.sh`
   - The script launches gdb with the `--tui` flag by default (you can remove this if you'd like)
   - The first command you should always run is `debugpintos` (nothing will work without running this)
   - Then you're all set

For a debugging demonstration in video form, please check out this [video](https://utexas.app.box.com/s/2r357h16t4xc1xeg3kva69i754ie18yf).
