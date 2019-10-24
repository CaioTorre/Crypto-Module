/*
Bruno Guilherme Spirlandeli Marini         	RA: 17037607
Caio Lima e Souza Della Torre Sanches 		RA: 17225285
Jefferson Meneses da Silva                  RA: 17230400
Marcos Aurélio Tavares de Sousa Filho 		RA: 17042284
*/

#include<stdio.h>
#include<stdlib.h>
#include<errno.h>
#include<fcntl.h>
#include<string.h>
#include<unistd.h>

#define BUFFER_LENGTH 258              // The buffer length including option
unsigned char receive[BUFFER_LENGTH];  // The receive buffer from the LKM

void c2h(char *, char *, int );
char c2h_conv(char);
char h2c_conv(char);

int main(){
	
    int ret, fd, opcao, op;
    char stringToSend[BUFFER_LENGTH - 2];
	char send[BUFFER_LENGTH];
	char rcv;

	fd = open("/dev/MyCryptoRomance", O_RDWR);         // Open the device with read/write access
	
	do{
		
		do{
			printf("-------------------------------------------------\n");
			printf(" Digite a opcao desejada: \n\n");
			printf(" 0. Sair;\n");
			printf(" 1. Cifrar string;\n");
			printf(" 2. Decifrar string;\n");
			printf(" 3. Resumo criptografico;\n\n");
			printf(" Opcao: ");
			scanf("%i", &opcao);
			printf("-------------------------------------------------\n");
		}while(opcao < 0 || opcao > 3);      
	   
		if(opcao != 0){
			
            if (fd < 0){
				perror("FOMOS FALHOS AO ABRIR O DISPOSITIVO...\n");
				printf("Erro cod. %d, %d\n", fd, (int)errno);
				return errno;
		    }
		
	        char fu[] = {'c', 'd', 'h'};
			
		    printf("\nDigite a string a ser ");
		
		    switch(opcao){
			    case 1:
					    printf("cifr");
				    break;
			    case 2:
					    printf("decifr");
				    break;
			    case 3:
					    printf("hashe");
				    break;
		    }
			
		    printf("ada: ");
		    getchar();
		    scanf("%[^\n]%*c", send);  // Read in a string (with spaces)
		
		    for(int i = 0; i < strlen(send); i++)
		    {
			    if(send[i] >= 'a' && send[i]<='z')
			    send[i]-=32;
		    }

        	int p;
        	for (p = 0; p < strlen(send); p++) stringToSend[p + 2] = send[p];
		    stringToSend[p + 2] = 0;
		    stringToSend[0] = fu[opcao - 1];
		    stringToSend[1] = ' ';	
	
		    ret = write(fd, stringToSend, strlen(stringToSend)); // Send the string to the LKM
		    if (ret < 0){
			    perror("Failed to write the message to the device.");
			    return errno;
		    }
	
		    ret = read(fd, receive, BUFFER_LENGTH);        // Read the response from the LKM
		
		    if (ret < 0){
			    perror("Failed to read the message from the device.");
			    return errno;
		    }
            
            int tamanho_new = 0;
            while (receive[tamanho_new] != 0) tamanho_new++;
            
		    unsigned char c;

		    printf("Hex:   [");
		    for(int i=0;i<tamanho_new;i++) 
			    printf("%c", receive[i]);
		    printf("]\n");
	
		    tamanho_new /= 2;
		    printf("ASCII: [");
		    for(int i=0;i<tamanho_new;i++) 			
			    printf(" %c", (char)(h2c_conv(receive[2*i])*16 + h2c_conv(receive[2*i+1])));
		    printf("]\n");
	
	        for(int i=0;i<BUFFER_LENGTH;i++) receive[i] = 0;
	        
		    printf("Press ENTER to return to menu...\n");
		    getchar();
	
		    stringToSend[0] = 0;
		}
		
	}while(opcao != 0);
	
	close(fd);
	
	printf("End of the program\n");
	return 0;
}

void c2h(char *charstrn, char *hexstrn, int charlen) {
	int tam = charlen;
    while (charlen-- >= 0) {
        hexstrn[2*charlen+1] = c2h_conv(charstrn[charlen] % (char)16); //1s
        hexstrn[2*charlen] = c2h_conv(charstrn[charlen] / (char)16);   //16s
    }
	hexstrn[2*tam+2] = 0;
}

char c2h_conv(char c) {
    if (c < (char)10) return c + '0';
    return c + 'A' - (char)10;
}

char h2c_conv(char c) {
	if (c <= '9') return c - '0';
    return c - 'A' + (char)10;
}
