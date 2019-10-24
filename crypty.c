/*
Bruno Guilherme Spirlandeli Marini         	RA: 17037607
Caio Lima e Souza Della Torre Sanches 		RA: 17225285
Jefferson Meneses da Silva                  RA: 17230400
Marcos Aurélio Tavares de Sousa Filho 		RA: 17042284
*/

#include <linux/init.h>           // Macros used to mark up functions e.g. __init __exit
#include <linux/module.h>         // Core header for loading LKMs into the kernel
#include <linux/device.h>         // Header to support the kernel Driver Model
#include <linux/kernel.h>         // Contains types, macros, functions for the kernel
#include <linux/fs.h>             // Header for the Linux file system support
#include <linux/uaccess.h>        // Required for the copy to user function
#include <linux/mutex.h>	  // Required for the mutex functionality
#include <linux/moduleparam.h>

#include <crypto/hash.h>
#include <linux/stat.h>
#include <linux/crypto.h>
#include <linux/random.h>
#include <linux/mm.h>
#include <linux/scatterlist.h>
#include <crypto/skcipher.h>
#include <linux/err.h>

#define DEVICE_NAME "MyCryptoRomance"    // The device will appear at /dev/ebbchar using this value
#define CLASS_NAME  "MyCrypto"           // The device class -- this is a character device driver
#define PARAM_LEN 33
#define FILL_SG(sg,ptr,len)     do { (sg)->page_link = virt_to_page(ptr); (sg)->offset = offset_in_page(ptr); (sg)->length = len; } while (0)
#define DATA_SIZE 64

#define THEO_MAX_SIZE 256

#define AES_KEY_SIZE_BYTES 16
#define AES_IV_SIZE_BYTES 16

#define SHA1_SIZE_BYTES 20

MODULE_LICENSE("GPL");                   	      // The license type -- this affects available functionality
MODULE_AUTHOR("JBMC");                                // The author -- visible when you use modinfo
MODULE_DESCRIPTION("Famigerado projetinho de SO B");  // The description -- see modinfo
MODULE_SUPPORTED_DEVICE("MyCryptoRomance");
MODULE_VERSION("0.1");                                // A version number to inform users

static char crp_key_hex[PARAM_LEN];
static char crp_iv_hex[PARAM_LEN];
static char crp_key[AES_KEY_SIZE_BYTES];
static char crp_iv[AES_IV_SIZE_BYTES];

char *key;
char *iv;
char mensagemChar[THEO_MAX_SIZE] = {0};
static char msgRet[THEO_MAX_SIZE] = {0};
static int answerSize;

module_param(key, charp, 0000);
MODULE_PARM_DESC(key, "Key String for AES-CBC");
module_param(iv, charp, 0000);
MODULE_PARM_DESC(iv, "Initialization Vector for AES-CBC");

static int    majorNumber;                  // Stores the device number -- determined automatically
static char   message[THEO_MAX_SIZE] = {0};     // Memory for the string that is passed from userspace
static short  size_of_message;              // Used to remember the size of the string stored
static int    numberOpens = 0;              // Counts the number of times the device is opened
static struct class*  ebbcharClass  = NULL; // The device-driver class struct pointer
static struct device* ebbcharDevice = NULL; // The device-driver device struct pointer
static DEFINE_MUTEX(ebbchar_mutex);         // A macro that is used to declare a new mutex that is visible in this file

/* --------- Links úteis ---------
 * https://www.kernel.org/doc/html/v4.16/crypto/api-skcipher.html
 * https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Cipher_Block_Chaining_(CBC)
 * https://pt.wikipedia.org/wiki/SHA-1
 * ---------  ---------  ---------
 */

static char h2c_conv(char c) {
	if (c <= '9') return c - '0';
    return c - 'A' + (char)10;
}

static char c2h_conv(char c) {
    if (c < (char)10) return c + '0';
    return c + 'A' - (char)10;
}

static void h2c(char *hexstrn, char *charstrn, int hexlen) { //Hexlen deve ser par
    hexlen--;
    while (hexlen > 0) {
        charstrn[(int)(hexlen/2)] = h2c_conv(hexstrn[hexlen]) + 16 * h2c_conv(hexstrn[hexlen - 1]);
	    hexlen -= 2;
	}
}

// The prototype functions for the character driver -- must come before the struct definition

static int     dev_open(struct inode *, struct file *);
static int     dev_release(struct inode *, struct file *);
static ssize_t dev_read(struct file *, char *, size_t, loff_t *);
static ssize_t dev_write(struct file *, const char *, size_t, loff_t *);

static struct file_operations fops =
{
   .open = dev_open,
   .read = dev_read,
   .write = dev_write,
   .release = dev_release,
};

static void hexdump(unsigned char *buf, unsigned int len) {
		unsigned char* aux = buf;
        while (len--) { printk(KERN_CONT "%02x - %u ", *aux, *aux); aux++; }
        printk("\n");
}

struct tcrypt_result {
    struct completion completion;
    int err;
};

struct skcipher_def {
    struct scatterlist sg[6];
    struct crypto_skcipher *tfm;
    struct skcipher_request *req;
    struct tcrypt_result result;
};

static int trigger_skcipher_encrypt(char *plaintext, int tam_plaintext)
{
    struct crypto_skcipher *skcipher = NULL; // Estrutura contendo o handler de skcipher    
    struct skcipher_request *req = NULL;     // Estrutura contendo o request para o kernel 

    /* Ponteiros para alocar os textos de entrada/saída */
    char *scratchpad = NULL;
    struct scatterlist sg_scratchpad;
    char *criptograf = NULL;
    struct scatterlist sg_criptograf;
    char *resultdata = NULL;

    /* Ponteiros para alocar os parâmetros de AES */
    char *Eivdata = NULL;
    char *Ekey = NULL;
    
    int ret = -EFAULT; // Valor de retorno
    int x;             // Variavel contadora

    /* Valores de debug */
    int expected_iv_size;
    int scratchpad_size;
    int n_cipher_blocks;
    
    /* Requisitar uma alocação de cifra */
    skcipher = crypto_alloc_skcipher("cbc(aes)", 0, 0); //cbc-aes-aesni
    if (IS_ERR(skcipher)) {
        pr_info("Could not allocate skcipher handle (%ld)\n", PTR_ERR(skcipher));
        return PTR_ERR(skcipher);
        goto out;
    }

    /* Requisitar uma alocação de requisito para o kernel */
    req = skcipher_request_alloc(skcipher, GFP_KERNEL);
    if (!req) {
        pr_info("Could not allocate skcipher request\n");
        ret = -ENOMEM;
        goto out;
    }
    
    /* Verificar o tamanho esperado do Vetor de Inicialização */
    expected_iv_size = crypto_skcipher_ivsize(skcipher);
    
    /* Requisitar uma área de memória para alocar a chave */
    Ekey = kmalloc(AES_KEY_SIZE_BYTES, GFP_KERNEL);
    if (!Ekey) {
        pr_info("Could not allocate key\n");
        goto out;
    }

    /* Preencher o espaço alocado */
    for(x=0; x<AES_KEY_SIZE_BYTES; x++) Ekey[x] = crp_key[x];
    
    /* Configurar chave simétrica */
    if (crypto_skcipher_setkey(skcipher, Ekey, AES_KEY_SIZE_BYTES)) {
        pr_info("Key could not be set\n");
        ret = -EAGAIN;
        goto out;
    }
    
    /* Requisitar uma área de memória para alocar o IV */
    Eivdata = kmalloc(AES_IV_SIZE_BYTES, GFP_KERNEL);
    if (!Eivdata) {
        pr_info("Could not allocate ivdata\n");
        goto out;
    }

    /* Preencher o espaço alocado */
    for(x=0; x<AES_IV_SIZE_BYTES; x++) Eivdata[x] = crp_iv[x];
    
    /* Verificar se será necessário fazer padding */
    if (tam_plaintext % AES_IV_SIZE_BYTES) {
        n_cipher_blocks = 1 + (tam_plaintext / AES_IV_SIZE_BYTES);
        scratchpad_size = AES_IV_SIZE_BYTES * n_cipher_blocks;
    } else {
        n_cipher_blocks = tam_plaintext / AES_IV_SIZE_BYTES;
        scratchpad_size = tam_plaintext;
    }
    
    /* Requisitar uma área de memória para alocar o plaintext */
    scratchpad = kmalloc(scratchpad_size, GFP_KERNEL);
    if (!scratchpad) {
        pr_info("Could not allocate scratchpad\n");
        goto out;
    }
    /* Preencher o espaço alocado */
    for(x=0; x<tam_plaintext;   x++) scratchpad[x] = plaintext[x];

    /* Realizar padding se necessário */
    for(;    x<scratchpad_size; x++) scratchpad[x] = 0;
    
    /* Requisitar uma área de memória para alocar o resultado da criptografia */
    criptograf = kmalloc(scratchpad_size, GFP_KERNEL);
    if (!criptograf) {
        pr_info("Could not allocate criptograf\n");
        goto out;
    }
    
    /* Inicializar scatterlists */
    sg_init_one(&sg_scratchpad, scratchpad, scratchpad_size);
    sg_init_one(&sg_criptograf, criptograf, scratchpad_size);
    
    /* Configurar valores da criptografia */
    skcipher_request_set_crypt(req, &sg_scratchpad, &sg_criptograf, scratchpad_size, Eivdata);
    
    /* Efetuar criptografia */
    ret = crypto_skcipher_encrypt(req);
    
    /* Verificar valor de retorno */
    if (ret) {
        pr_info("Encryption failed...\n");
        goto out;
    }
    
    /* Exibir resultado para debug */
    resultdata = sg_virt(&sg_criptograf);

    /* Armazenar resposta para devolver ao programa */
    for(x=0;x<scratchpad_size;x++){
	    msgRet[2*x]     = c2h_conv((unsigned char)resultdata[x] / 16);
	    msgRet[2*x + 1] = c2h_conv((unsigned char)resultdata[x] % 16);
	}
    msgRet[2*x] = 0;
    
    /* Armazenar tamanho da resposta do programa */
    answerSize = 2*scratchpad_size + 1;
    
    /* Liberar estruturas utilizadas */
    out:
    if (skcipher)
        crypto_free_skcipher(skcipher);
    if (req)
        skcipher_request_free(req);
    if (Ekey)
    	kfree(Ekey);
    if (Eivdata)
        kfree(Eivdata);
    if (scratchpad)
        kfree(scratchpad);
    if (criptograf)
        kfree(criptograf);
    return ret;
}


static int trigger_skcipher_decrypt(char *ciphertext, int tam_ciphertext)
{
    /* Estrutura contendo o handler de skcipher */
    struct crypto_skcipher *skcipher = NULL;

    /* Estrutura contendo o request para o kernel */
    struct skcipher_request *req = NULL;

    /* Ponteiros para alocar os textos de entrada/saída */
    char *scratchpad = NULL;
    struct scatterlist sg_scratchpad;
    char *decriptogr = NULL;
    struct scatterlist sg_decriptogr;
    char *resultdata = NULL;

    /* Ponteiros para alocar os parâmetros de AES */
    char *Eivdata = NULL;
    char *Ekey = NULL;

    /* Valor de retorno */
    int ret = -EFAULT;

    /* Variavel contadora */
    int x;

    /* Valores de debug */
    int expected_iv_size;
    int scratchpad_size;
    int n_cipher_blocks;
    
    /* Requisitar uma alocação de cifra */
    skcipher = crypto_alloc_skcipher("cbc(aes)", 0, 0); //cbc-aes-aesni
    if (IS_ERR(skcipher)) {
        pr_info("Could not allocate skcipher handle (%ld)\n", PTR_ERR(skcipher));
        return PTR_ERR(skcipher);
        goto out;
    }

    /* Requisitar uma alocação de requisito para o kernel */
    req = skcipher_request_alloc(skcipher, GFP_KERNEL);
    if (!req) {
        pr_info("Could not allocate skcipher request\n");
        ret = -ENOMEM;
        goto out;
    }
    
    /* Verificar o tamanho esperado do Vetor de Inicialização */
    expected_iv_size = crypto_skcipher_ivsize(skcipher);
    
    /* Requisitar uma área de memória para alocar a chave */
    Ekey = kmalloc(AES_KEY_SIZE_BYTES, GFP_KERNEL);
    if (!Ekey) {
        pr_info("Could not allocate key\n");
        goto out;
    }

    /* Preencher o espaço alocado */
    for(x=0; x<AES_KEY_SIZE_BYTES; x++) Ekey[x] = crp_key[x];
    
    /* Configurar chave simétrica */
    if (crypto_skcipher_setkey(skcipher, Ekey, AES_KEY_SIZE_BYTES)) {
        pr_info("Key could not be set\n");
        ret = -EAGAIN;
        goto out;
    }
    
    /* Requisitar uma área de memória para alocar o IV */
    Eivdata = kmalloc(AES_IV_SIZE_BYTES, GFP_KERNEL);
    if (!Eivdata) {
        pr_info("Could not allocate ivdata\n");
        goto out;
    }

    /* Preencher o espaço alocado */
    for(x=0; x<AES_IV_SIZE_BYTES; x++) Eivdata[x] = crp_iv[x];
    
    /* Verificar se será necessário fazer padding */
    if (tam_ciphertext % AES_IV_SIZE_BYTES) {
        n_cipher_blocks = 1 + (tam_ciphertext / AES_IV_SIZE_BYTES);
        scratchpad_size = AES_IV_SIZE_BYTES * n_cipher_blocks;
    } else {
        n_cipher_blocks = tam_ciphertext / AES_IV_SIZE_BYTES;
        scratchpad_size = tam_ciphertext;
    }

    
    /* Requisitar uma área de memória para alocar o plaintext */
    scratchpad = kmalloc(scratchpad_size, GFP_KERNEL);
    if (!scratchpad) {
        pr_info("Could not allocate scratchpad\n");
        goto out;
    }

    /* Preencher o espaço alocado */
    for(x=0; x<tam_ciphertext;   x++) scratchpad[x] = ciphertext[x];

    /* Realizar padding se necessário */
    for(;    x<tam_ciphertext; x++) scratchpad[x] = 0;
    
    /* Requisitar uma área de memória para alocar o resultado da criptografia */
    decriptogr = kmalloc(scratchpad_size, GFP_KERNEL);
    if (!decriptogr) {
        pr_info("Could not allocate decriptogr\n");
        goto out;
    }
    
    /* Inicializar scatterlists */
    sg_init_one(&sg_scratchpad, scratchpad, scratchpad_size);
    sg_init_one(&sg_decriptogr, decriptogr, scratchpad_size);
    
    /* Configurar valores da criptografia */
    skcipher_request_set_crypt(req, &sg_scratchpad, &sg_decriptogr, scratchpad_size, Eivdata);
    
    /* Efetuar criptografia */
    ret = crypto_skcipher_decrypt(req);
    
    /* Verificar valor de retorno */
    if (ret) {
        pr_info("Decryption failed...\n");
        goto out;
    }
    
    /* Exibir resultado para debug */
    resultdata = sg_virt(&sg_decriptogr);

    /* Armazenar resposta para devolver ao programa */
    for(x=0;x<scratchpad_size;x++){
	    msgRet[2*x]     = c2h_conv((unsigned char)resultdata[x] / 16);
	    msgRet[2*x + 1] = c2h_conv((unsigned char)resultdata[x] % 16);
	}
    msgRet[2*x] = 0;
    
    /* Armazenar tamanho da resposta do programa */
    answerSize = 2*scratchpad_size + 1;
    
    /* Liberar estruturas utilizadas */
    out:
    if (skcipher)
        crypto_free_skcipher(skcipher);
    if (req)
        skcipher_request_free(req);
    if (Ekey)
    	kfree(Ekey);
    if (Eivdata)
        kfree(Eivdata);
    if (scratchpad)
        kfree(scratchpad);
    if (decriptogr)
        kfree(decriptogr);
    return ret;
}

static int trigger_hash(char *plaintext, int tam_plaintext)
{
    struct shash_desc *desc;
    struct crypto_shash *alg;
    char *hashval = NULL;
    
    int ret = -EFAULT; // Valor de retorno
    int x;             // Variavel contadora
    
    alg = crypto_alloc_shash("sha1", 0, 0);
    desc = kmalloc(sizeof(struct shash_desc), GFP_KERNEL);
    if (!desc){return (long int)ERR_PTR(-ENOMEM); goto out_hash;}
    desc->tfm = alg;
    desc->flags = 0x0;

    hashval = kmalloc(SHA1_SIZE_BYTES, GFP_KERNEL);
    if (!hashval) goto out_hash;

    ret = crypto_shash_digest(desc, plaintext, tam_plaintext, hashval);

    // Armazenar resposta para devolver ao programa 
    for(x=0;x<SHA1_SIZE_BYTES;x++){
	    msgRet[2*x]     = c2h_conv((unsigned char)hashval[x] / 16);
	    msgRet[2*x + 1] = c2h_conv((unsigned char)hashval[x] % 16);
	}
    msgRet[2*x] = 0;
    
    // Armazenar tamanho da resposta do programa
    answerSize = SHA1_SIZE_BYTES*2 + 1;

out_hash:
    // Liberar estruturas utilizadas
    if(alg) crypto_free_shash(alg);
    if(desc) kfree(desc);
    if(hashval) kfree(hashval);
    return ret;
}

static int __init cripty_init(void){
    static int i;

    /*  Copiando conteudo para os vetores */
    for(i = 0; i < strlen(key) && i < PARAM_LEN - 1; i++)
	    crp_key_hex[i] = key[i];

    if(i < PARAM_LEN - 1) 
	    for(; i < PARAM_LEN - 1; i++)
		    crp_key_hex[i] = '0';

    for(i = 0; i < strlen(iv) && i < PARAM_LEN - 1; i++)
	    crp_iv_hex[i] = iv[i];

    if(i < PARAM_LEN - 1) 
	    for(; i < PARAM_LEN - 1; i++)
		    crp_iv_hex[i] = '0';

    crp_key_hex[PARAM_LEN - 1] = '\0';
    crp_iv_hex[PARAM_LEN - 1] = '\0';
    
    h2c(crp_key_hex, crp_key, PARAM_LEN-1);
    h2c(crp_iv_hex,  crp_iv,  PARAM_LEN-1);

   /* Fim Copia */
   
   mutex_init(&ebbchar_mutex); // Initialize the mutex lock dynamically at runtime
   
   // Try to dynamically allocate a major number for the device -- more difficult but worth it
   majorNumber = register_chrdev(0, DEVICE_NAME, &fops);
   if (majorNumber<0){
      printk(KERN_ALERT "EBBChar failed to register a major number\n");
      return majorNumber;
   }

   // Register the device class
   ebbcharClass = class_create(THIS_MODULE, CLASS_NAME);
   if (IS_ERR(ebbcharClass)){                // Check for error and clean up if there is
      unregister_chrdev(majorNumber, DEVICE_NAME);
      printk(KERN_ALERT "Failed to register device class\n");
      return PTR_ERR(ebbcharClass);          // Correct way to return an error on a pointer
   }
   //printk(KERN_INFO "EBBChar: device class registered correctly\n");

   // Register the device driver
   ebbcharDevice = device_create(ebbcharClass, NULL, MKDEV(majorNumber, 0), NULL, DEVICE_NAME);
   if (IS_ERR(ebbcharDevice)){               // Clean up if there is an error
      class_destroy(ebbcharClass);           // Repeated code but the alternative is goto statements
      unregister_chrdev(majorNumber, DEVICE_NAME);
      printk(KERN_ALERT "Failed to create the device\n");
      return PTR_ERR(ebbcharDevice);
   }
   
   return 0;
}

/** @brief The LKM cleanup function
 *  Similar to the initialization function, it is static. The __exit macro notifies that if this
 *  code is used for a built-in driver (not a LKM) that this function is not required.
 */
static void __exit cripty_exit(void){
   mutex_destroy(&ebbchar_mutex);                           // destroy the dynamically-allocated mutex
   device_destroy(ebbcharClass, MKDEV(majorNumber, 0));     // remove the device
   class_unregister(ebbcharClass);                          // unregister the device class
   class_destroy(ebbcharClass);                             // remove the device class
   unregister_chrdev(majorNumber, DEVICE_NAME);             // unregister the major number
}

static int dev_open(struct inode *inodep, struct file *filep){

   mutex_lock(&ebbchar_mutex);   // Try to acquire the mutex (i.e., put the lock on/down)
   numberOpens++;
   return 0;
}

static ssize_t dev_read(struct file *filep, char *buffer, size_t len, loff_t *offset){
   int error_count = 0;
   
   error_count = copy_to_user(buffer, msgRet, answerSize);
   
   if (error_count==0){            // if true then have success
      return (size_of_message=0);  // clear the position to the start and return 0
   }
   else {
      printk(KERN_INFO "EBBChar: Failed to send %d characters to the user\n", error_count);
      return -EFAULT;              // Failed -- return a bad address message (i.e. -14)
   }
}

static ssize_t dev_write(struct file *filep, const char *buffer, size_t len, loff_t *offset){
   sprintf(message, "%s", buffer);

   h2c(message+2, mensagemChar, len-2);
   
   switch(message[0]){
      case 'c': // cifrar
		trigger_skcipher_encrypt(mensagemChar, (len-2)/2); 
		break;
	  case 'd': // decifrar	
		trigger_skcipher_decrypt(mensagemChar, (len-2)/2);
    	break;
      case 'h': // resumo criptográfico
		trigger_hash(mensagemChar, (len-2)/2); 
    	break;
   }

   return len;
}

static int dev_release(struct inode *inodep, struct file *filep){

   mutex_unlock(&ebbchar_mutex);          // Releases the mutex (i.e., the lock goes up)
   printk(KERN_INFO "EBBChar: Device successfully closed\n");
   return 0;
}

module_init(cripty_init);
module_exit(cripty_exit);
