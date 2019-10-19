/**
 * @file   testebbchar.c
 * @author Derek Molloy
 * @date   7 April 2015
 * @version 0.1
 * @brief  A Linux user space program that communicates with the ebbchar.c LKM. It passes a
 * string to the LKM and reads the response from the LKM. For this example to work the device
 * must be called /dev/ebbchar.
 * @see http://www.derekmolloy.ie/ for a full description and follow-up descriptions.
*/
#include<stdio.h>
#include<stdlib.h>
#include<errno.h>
#include<fcntl.h>
#include<string.h>
#include<unistd.h>

#define BUFFER_LENGTH 258 ///< The buffer length including option
unsigned char receive[BUFFER_LENGTH];     ///< The receive buffer from the LKM

int main(){
   int ret, fd;
   char stringToSend[BUFFER_LENGTH];

   printf("Starting device test code example...\n");
   fd = open("/dev/MyCryptoRomance", O_RDWR);             // Open the device with read/write access
   if (fd < 0){
      perror("Failed to open the device...");
      printf("Erro cod. %d, %d\n", fd, (int)errno);
      return errno;
   }
   printf("Type in a short string to send to the kernel module:\n");
   scanf("%[^\n]%*c", stringToSend);                // Read in a string (with spaces)
   printf("Writing message to the device [%s].\n", stringToSend);
   printf("Tam string: %d", strlen(stringToSend));

   ret = write(fd, stringToSend, strlen(stringToSend)); // Send the string to the LKM
   if (ret < 0){
      perror("Failed to write the message to the device.");
      return errno;
   }

   printf("Press ENTER to read back from the device...\n");
   getchar();

   printf("Reading from the device...\n");
   ret = read(fd, receive, BUFFER_LENGTH);        // Read the response from the LKM
   if (ret < 0){
      perror("Failed to read the message from the device.");
      return errno;
   }

	unsigned char c, msgBuffer[41];
	int i;

	printf("The received message is [%i]: ", strlen(receive));
	   for(i=0;i<strlen(receive);i++) {
		c = receive[i];
		if(c < 10)
		sprintf(msgBuffer + strlen(msgBuffer), "0%x", c);
		else
		sprintf(msgBuffer + strlen(msgBuffer), "%x", c);
	}
	msgBuffer[40] = '\0';

	for(i=0;i<strlen(msgBuffer);i++)
	{
		if(msgBuffer[i] > 96 && msgBuffer[i] < 123)
			msgBuffer[i] = msgBuffer[i] - 32;
	}

	printf("%s", msgBuffer);

   printf("\nEnd of the program\n");

   return 0;
}
