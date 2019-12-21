obj-m += rootkit.o
rootkit-objs := hooks.o backdoor.o
KDIR = /lib/modules/`uname -r`/build

all: kbuild

kbuild:
	make -C $(KDIR) M=`pwd` modules

clean:
	#rm -r *.mod.c *.o *.ko *.symvers *.order .*cmd .tmp_versions
	make -C $(KDIR) M=`pwd` clean
