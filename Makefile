#Bruno Guilherme Spirlandeli Marini         RA: 17037607
#Caio Lima e Souza Della Torre Sanches 		RA: 17225285
#Jefferson Meneses da Silva                 RA: 17230400
#Marcos Aurélio Tavares de Sousa Filho 		RA: 17042284


obj-m+=crypty.o

all:
	make -C /lib/modules/$(shell uname -r)/build/ M=$(PWD) modules
	$(CC) testCrypto.c -o test
	sudo insmod crypty.ko key="0123456789ABCDEF" iv="0123456789ABCDEF"
	sudo ./test
clean:
	make -C /lib/modules/$(shell uname -r)/build/ M=$(PWD) clean
	rm test
