savedcmd_ipfi.o := ld -m elf_x86_64 -z noexecstack --no-warn-rwx-segments   -r -o ipfi.o @ipfi.mod  ; /usr/lib/modules/6.18.9-arch1-2/build/tools/objtool/objtool --hacks=jump_label --hacks=noinstr --hacks=skylake --ibt --orc --retpoline --rethunk --sls --static-call --uaccess --prefix=16  --link  --module ipfi.o

ipfi.o: $(wildcard /usr/lib/modules/6.18.9-arch1-2/build/tools/objtool/objtool)
