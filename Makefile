obj-m+=crypty.o

all:
	make -C /lib/modules/$(shell uname -r)/build/ M=$(PWD) modules
	$(CC) testebbchar.c -o test
	sudo insmod crypty.ko key="0123456789ABCDEF" iv="0123456789ABCDEF"
	sudo ./test
clean:
	make -C /lib/modules/$(shell uname -r)/build/ M=$(PWD) clean
	rm test
