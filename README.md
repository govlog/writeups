# Labyrenth => mobile_2 :


We are given a MIPS binary, which is probably a ransomware ( hint + filename ).

```
-> file routerlocker
routerlocker: ELF 32-bit MSB executable, MIPS, MIPS64 version 1 (SYSV), dynamically linked, interpreter /lib/ld.so.1, for GNU/Linux 2.6.26, BuildID[sha1]=b9720b983cafb2a111bbac302b4ead891019e600, not stripped
```

# Decompile it !

As I didn't knew anything in MIPS asm, and quite franckly, didn't have the time to learn a new arch, I used retdec.com to "decompile" the binary and started looking under the hood :


Once cleaned a bit, we start to get a clear picture of the execution flow :


```
    stat_loc = 0 # bp-104

	# forking himself to make debugging "harder"
    if fork() != 0:
        wait(&stat_loc)
        return 0

    # start of the forked process

    .... "obf MIPS asm" part 1 (construct the filename string)
    .... (not catched by the "decompiler")
    ....

    ptrace(0) # gdb will not like it

    .... "obf MIPS asm" second part
    .... (not catched by the "decompiler")
    ....

    file_path = ???????

    file = fopen(&file_path, "r") # 0x400a1c

    if file == NULL:
        fwrite("License file not found.\n", 1, 24, stream)
        fwrite("Lock it up, and lock it out.\n", 1, 29, stream)
        return 1
```

Just before the program fork, there is a huge bloc of asm opcodes that create the filename string :

![create filename string](/obf1.png)

We could have reversed the mips asm, but as I'm a lazy guy and had kept a debian MIPS qemu image, I decided to do it dynamically :



# Trace it!


To obtain the filename easily, we can simply strace the process, but as the process is forking itself, we need to use the -ff switch ( to follow the child execution ).

IMPORTANT : If we decide later to use gdb, we will have to use "set follow-fork-mode child" to be able to break or debug into the forked process.



```
root@debian-mips:~# strace -ff -q -e open ./routerlocker
open("/etc/ld.so.cache", O_RDONLY)      = 4
open("/lib/mips-linux-gnu/libc.so.6", O_RDONLY) = 4
[pid  2448] open("/tmp/router.lck", O_RDONLY) = -1 ENOENT (No such file or directory)
License file not found.
Lock it up, and lock it out.
--- SIGCHLD (Child exited) @ 0 (0) ---
```

Ok, now that we have the filename, let's continue reading the decompiled code :

```
    if fread(&file_buf, 1, 29, v5) >= 29:
        # 0x400d44
        fclose(v5)
```

It read 29 bytes in the license file, which clearly indicates us the size of the license.
Let's create a '/tmp/router.lck' file with 29 bytes in it and see what happen in strace :

```
[pid  2463] open("/tmp/router.lck", O_RDONLY) = 4
[pid  2463] fstat64(4, {st_mode=S_IFREG|0644, st_size=30, ...}) = 0
[pid  2463] old_mmap(NULL, 65536, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0x77a7a000
[pid  2463] read(4, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAA", 4096) = 29
[pid  2463] close(4)                    = 0
[pid  2463] munmap(0x77a7a000, 65536)   = 0
[pid  2463] write(2, "Serial is invalid.\n", 19Serial is invalid.) = 19
[pid  2463] write(2, "Ambrocious, unlock this door!\n", 30Ambrocious, unlock this door!) = 30
```


Good. Let's continue :


```
	.... big blob of "obf MIPS asm" to construct a value in v0?
	....
	....

        v6 = strlen(&file_buf) # 0x400d1850
        v7 = (4 * v8 & 252 | v8 % 4) + &g13
        v9 = 0 # 0x400d484753
        # branch -> 0x400d44

        while True:
            # 0x400d44
            if v9 < v6:
                v10 = v9 + &v3 # 0x400c58
                if v10[44] != v10[76] ^ *v7:
                    # 0x400c84
                    fwrite("Serial is invalid.\n", 1, 19, g17)
                    fwrite("Ambrocious, unlock this door!\n", 1, 30, g17)
```


We see a kind of "weird-crc-magickey-xor-sum" algo, in addition to this, looking at the code through IDA, we clearly see that, before the loop, the program is creating a value by adding stuff on the stack to the v0 register. The decompiler didn't catch anything :

![magic key creation ?](/obf2.png)

# Debug it !
