obj-m = rootkit.o
rootkit-objs := src/hooks.o src/backdoor.o src/proc.o src/rootkit.o
KDIR = /lib/modules/`uname -r`/build

ccflags-y := -save-temps -std=gnu99 -Wno-declaration-after-statement -Wno-vla

all: kbuild client

kbuild:
	make -C $(KDIR) M=`pwd`

client:
	gcc src/client.c -o client

clean:
	#rm -r *.mod.c *.o *.ko *.symvers *.order .*cmd .tmp_versions
	make -C $(KDIR) M=`pwd` clean
	rm client
