obj-m = rootkit.o
KDIR = /lib/modules/`uname -r`/build

all: kbuild

kbuild:
	make -C $(KDIR) M=`pwd`

clean:
	rm -r *.mod.c *.o *.ko *.symvers *.order sys.h .*cmd .tmp_versions
