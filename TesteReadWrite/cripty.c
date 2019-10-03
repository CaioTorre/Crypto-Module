#include <linux/init.h>           // Macros used to mark up functions e.g. __init __exit
#include <linux/module.h>         // Core header for loading LKMs into the kernel
#include <linux/device.h>         // Header to support the kernel Driver Model
#include <linux/kernel.h>         // Contains types, macros, functions for the kernel
#include <linux/fs.h>             // Header for the Linux file system support
#include <linux/uaccess.h>          // Required for the copy to user function
#include <linux/mutex.h>	         /// Required for the mutex functionality
#include <linux/moduleparam.h>
#include <linux/stat.h>
#include <linux/crypto.h>
#include <linux/random.h>
#include <linux/mm.h>
#include <linux/scatterlist.h>
#include <crypto/skcipher.h>

#define  DEVICE_NAME "ebbchar"    ///< The device will appear at /dev/ebbchar using this value
#define  CLASS_NAME  "ebb"        ///< The device class -- this is a character device driver
#define PARAM_LEN 33
#define FILL_SG(sg,ptr,len)     do { (sg)->page_link = virt_to_page(ptr); (sg)->offset = offset_in_page(ptr); (sg)->length = len; } while (0)
#define DATA_SIZE 256

MODULE_LICENSE("GPL");            ///< The license type -- this affects available functionality
MODULE_AUTHOR("JBMC");    ///< The author -- visible when you use modinfo
MODULE_DESCRIPTION("Famigerado projetinho de SO B");  ///< The description -- see modinfo
MODULE_SUPPORTED_DEVICE("mycryptoromance");
MODULE_VERSION("0.1");            ///< A version number to inform users

static char   crp_key[PARAM_LEN];
static char   crp_iv[PARAM_LEN];
static int    crp_key_len;
static int    crp_iv_len;
static char   operacao;
char *key;
char *iv;
char mensagemChar[256] = {0};

module_param(key, charp, 0000);
MODULE_PARM_DESC(key, "Key String for AES-CBC");
module_param(iv, charp, 0000);
MODULE_PARM_DESC(iv, "Initialization Vector for AES-CBC");

static int    majorNumber;                  ///< Stores the device number -- determined automatically
static char   message[256] = {0};           ///< Memory for the string that is passed from userspace
static short  size_of_message;              ///< Used to remember the size of the string stored
static int    numberOpens = 0;              ///< Counts the number of times the device is opened
static struct class*  ebbcharClass  = NULL; ///< The device-driver class struct pointer
static struct device* ebbcharDevice = NULL; ///< The device-driver device struct pointer
static DEFINE_MUTEX(ebbchar_mutex);  /// A macro that is used to declare a new mutex that is visible in this file

/* CODIGO FEIO NN OLHEM PLS */
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
static void c2h(char *charstrn, char *hexstrn, int charlen) {
    charlen--;
    while (charlen-- >= 0) {
        hexstrn[2*charlen+1] = c2h_conv(charstrn[charlen] % (char)16); //1s
        hexstrn[2*charlen] = c2h_conv(charstrn[charlen] / (char)16);   //16s
    }
}
/* PODE OLHAR AGR */

// The prototype functions for the character driver -- must come before the struct definition
static int     dev_open(struct inode *, struct file *);
static int     dev_release(struct inode *, struct file *);
static ssize_t dev_read(struct file *, char *, size_t, loff_t *);
static ssize_t dev_write(struct file *, const char *, size_t, loff_t *);

static void
hexdump(unsigned char *buf, unsigned int len)
{
        while (len--)
                printk("%02x", *buf++);

        printk("\n");
}

struct tcrypt_result {
    struct completion completion;
    int err;
};

/* tie all data structures together */
struct skcipher_def {
    struct scatterlist sg;
    struct crypto_skcipher *tfm;
    struct skcipher_request *req;
    struct tcrypt_result result;
};

/* Callback function */
static void test_skcipher_cb(struct crypto_async_request *req, int error)
{
    struct tcrypt_result *result = req->data;

    if (error == -EINPROGRESS)
        return;
    result->err = error;
    complete(&result->completion);
    pr_info("Encryption finished successfully\n");
}

/* Perform cipher operation */
static unsigned int test_skcipher_encdec(struct skcipher_def *sk,
                     int enc)
{
    int rc = 0;

    if (enc)
        rc = crypto_skcipher_encrypt(sk->req);
    else
        rc = crypto_skcipher_decrypt(sk->req);

    switch (rc) {
    case 0:
        break;
    case -EINPROGRESS:
    case -EBUSY:
        rc = wait_for_completion_interruptible(
            &sk->result.completion);
        if (!rc && !sk->result.err) {
            reinit_completion(&sk->result.completion);
            break;
        }
    default:
        pr_info("skcipher encrypt returned with %d result %d\n",
            rc, sk->result.err);
        break;
    }
    init_completion(&sk->result.completion);

    return rc;
}

/* Initialize and trigger cipher operation */
static int test_skcipher()
{
    struct skcipher_def sk;
    struct crypto_skcipher *skcipher = NULL;
    struct skcipher_request *req = NULL;
    char *scratchpad = NULL;
    char *ivdata = NULL;
    unsigned char key[32];
    int ret = -EFAULT;

    char *input, *encr, *decr;
    input = kmalloc(GFP_KERNEL, DATA_SIZE);
    encr = kmalloc(GFP_KERNEL, DATA_SIZE);
    //decr = kmalloc(GFP_KERNEL, DATA_SIZE);

    skcipher = crypto_alloc_skcipher("cbc-aes-aesni", 0, 0);
    if (IS_ERR(skcipher)) {
        pr_info("could not allocate skcipher handle\n");
        return PTR_ERR(skcipher);
    }

    req = skcipher_request_alloc(skcipher, GFP_KERNEL);
    if (!req) {
        pr_info("could not allocate skcipher request\n");
        ret = -ENOMEM;
        goto out;
    }

    skcipher_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG,
                      test_skcipher_cb,
                      &sk.result);

    /* AES 256 with random key (YEEEET) */
    
    get_random_bytes(&key, 32); //mudar para receber a key
    if (crypto_skcipher_setkey(skcipher, key, 32)) {
        pr_info("key could not be set\n");
        ret = -EAGAIN;
        goto out;
    }

    /* IV will be random */
    ivdata = kmalloc(16, GFP_KERNEL);
    if (!ivdata) {
        pr_info("could not allocate ivdata\n");
        goto out;
    }
    get_random_bytes(ivdata, 16); //mudar para receber o iv

    /* Input data will be random */
    scratchpad = kmalloc(16, GFP_KERNEL);
    if (!scratchpad) {
        pr_info("could not allocate scratchpad\n");
        goto out;
    }
    get_random_bytes(scratchpad, 16);

    sk.tfm = skcipher;
    sk.req = req;

    /* We encrypt one block */
    sg_init_one(&sk.sg, scratchpad, 16);
    skcipher_request_set_crypt(req, &sk.sg, &sk.sg, 16, ivdata);
    init_completion(&sk.result.completion);

    struct scatterlist *uhuh;
    uhuh = sk.req->src;
    FILL_SG(uhuh, input, DATA_SIZE);
    uhuh = sk.req->dst;
    FILL_SG(uhuh,  encr, DATA_SIZE);
    
    /* encrypt data */
    ret = test_skcipher_encdec(&sk, 1);
    if (ret)
        goto out;

    pr_info("Encryption triggered successfully\n");
    
    printk(KERN_INFO "IN: "); hexdump(input, DATA_SIZE);
    printk(KERN_INFO "EN: "); hexdump(encr, DATA_SIZE);
    
out:
        //kfree(decrypted);
        
        crypto_free_skcipher(skcipher);
    if (req)
        skcipher_request_free(req);
    if (ivdata)
        kfree(ivdata);
    if (scratchpad)
        kfree(scratchpad);
    return ret;
}

/** @brief Devices are represented as file structure in the kernel. The file_operations structure from
 *  /linux/fs.h lists the callback functions that you wish to associated with your file operations
 *  using a C99 syntax structure. char devices usually implement open, read, write and release calls
 */
static struct file_operations fops =
{
   .open = dev_open,
   .read = dev_read,
   .write = dev_write,
   .release = dev_release,
};

/** @brief The LKM initialization function
 *  The static keyword restricts the visibility of the function to within this C file. The __init
 *  macro means that for a built-in driver (not a LKM) the function is only used at initialization
 *  time and that it can be discarded and its memory freed up after that point.
 *  @return returns 0 if successful
 */
static int __init cripty_init(void){
   printk(KERN_INFO "EBBChar: Initializing the EBBChar LKM\n");
   pr_info("Inicializado cripty.c\n");	
	
   /*  Copiando conteudo para os vetores */

	static int i;
	for(i = 0; i < strlen(key) && i < PARAM_LEN - 1; i++)
		crp_key[i] = key[i];
	
	if(i < PARAM_LEN - 1) 
		for(; i < PARAM_LEN - 1; i++)
			crp_key[i] = '0';

	for(i = 0; i < strlen(iv) && i < PARAM_LEN - 1; i++)
		crp_iv[i] = iv[i];
	
	if(i < PARAM_LEN - 1) 
		for(; i < PARAM_LEN - 1; i++)
			crp_iv[i] = '0';

	crp_key[PARAM_LEN - 1] = '\0';
	crp_iv[PARAM_LEN - 1] = '\0';	
	
	printk(KERN_INFO "ENTÂO MEU PACERO: %s %s\n", crp_key, crp_iv);
   /* Fim Copia */


   mutex_init(&ebbchar_mutex);       /// Initialize the mutex lock dynamically at runtime

   // Try to dynamically allocate a major number for the device -- more difficult but worth it
   majorNumber = register_chrdev(0, DEVICE_NAME, &fops);
   if (majorNumber<0){
      printk(KERN_ALERT "EBBChar failed to register a major number\n");
      return majorNumber;
   }
   printk(KERN_INFO "EBBChar: registered correctly with major number %d\n", majorNumber);

   // Register the device class
   ebbcharClass = class_create(THIS_MODULE, CLASS_NAME);
   if (IS_ERR(ebbcharClass)){                // Check for error and clean up if there is
      unregister_chrdev(majorNumber, DEVICE_NAME);
      printk(KERN_ALERT "Failed to register device class\n");
      return PTR_ERR(ebbcharClass);          // Correct way to return an error on a pointer
   }
   printk(KERN_INFO "EBBChar: device class registered correctly\n");

   // Register the device driver
   ebbcharDevice = device_create(ebbcharClass, NULL, MKDEV(majorNumber, 0), NULL, DEVICE_NAME);
   if (IS_ERR(ebbcharDevice)){               // Clean up if there is an error
      class_destroy(ebbcharClass);           // Repeated code but the alternative is goto statements
      unregister_chrdev(majorNumber, DEVICE_NAME);
      printk(KERN_ALERT "Failed to create the device\n");
      return PTR_ERR(ebbcharDevice);
   }
   printk(KERN_INFO "EBBChar: device class created correctly\n"); // Made it! device was initialized
   
   test_skcipher(crp_key,crp_iv); //param key e iv
   
   
   return 0;
}

/** @brief The LKM cleanup function
 *  Similar to the initialization function, it is static. The __exit macro notifies that if this
 *  code is used for a built-in driver (not a LKM) that this function is not required.
 */
static void __exit cripty_exit(void){
   mutex_destroy(&ebbchar_mutex);        /// destroy the dynamically-allocated mutex
   device_destroy(ebbcharClass, MKDEV(majorNumber, 0));     // remove the device
   class_unregister(ebbcharClass);                          // unregister the device class
   class_destroy(ebbcharClass);                             // remove the device class
   unregister_chrdev(majorNumber, DEVICE_NAME);             // unregister the major number
   //printk(KERN_INFO "EBBChar: Goodbye from the LKM!\n");
   pr_info("Finalizando cripty.c\n");
}

/** @brief The device open function that is called each time the device is opened
 *  This will only increment the numberOpens counter in this case.
 *  @param inodep A pointer to an inode object (defined in linux/fs.h)
 *  @param filep A pointer to a file object (defined in linux/fs.h)
 */
static int dev_open(struct inode *inodep, struct file *filep){

  mutex_lock(&ebbchar_mutex);   /// Try to acquire the mutex (i.e., put the lock on/down)
                                          /// returns 1 if successful and 0 if there is contention
     // printk(KERN_ALERT "EBBChar: Device in use by another process");
      //return -EBUSY;

   numberOpens++;
   printk(KERN_INFO "EBBChar: Device has been opened %d time(s)\n", numberOpens);
   return 0;
}

/** @brief This function is called whenever device is being read from user space i.e. data is
 *  being sent from the device to the user. In this case is uses the copy_to_user() function to
 *  send the buffer string to the user and captures any errors.
 *  @param filep A pointer to a file object (defined in linux/fs.h)
 *  @param buffer The pointer to the buffer to which this function writes the data
 *  @param len The length of the b
 *  @param offset The offset if required
 */
static ssize_t dev_read(struct file *filep, char *buffer, size_t len, loff_t *offset){
   int error_count = 0;
   // copy_to_user has the format ( * to, *from, size) and returns 0 on success
   error_count = copy_to_user(buffer, message, size_of_message);

   if (error_count==0){            // if true then have success
      printk(KERN_INFO "EBBChar: Sent %d characters to the user\n", size_of_message);
      return (size_of_message=0);  // clear the position to the start and return 0
   }
   else {
      printk(KERN_INFO "EBBChar: Failed to send %d characters to the user\n", error_count);
      return -EFAULT;              // Failed -- return a bad address message (i.e. -14)
   }
}

/** @brief This function is called whenever the device is being written to from user space i.e.
 *  data is sent to the device from the user. The data is copied to the message[] array in this
 *  LKM using the sprintf() function along with the length of the string.
 *  @param filep A pointer to a file object
 *  @param buffer The buffer to that contains the string to write to the device
 *  @param len The length of the array of data that is being passed in the const char buffer
 *  @param offset The offset if required
 */
static ssize_t dev_write(struct file *filep, const char *buffer, size_t len, loff_t *offset){
   sprintf(message, "%s(%zu letters)", buffer, len);   // appending received string with its length
   size_of_message = strlen(message);                 // store the length of the stored message
   printk(KERN_INFO "EBBChar: Received %zu characters from the user\n", len);

   switch(message[0]){
      case 'c': // cifrar
		printk(KERN_INFO "TO CRIPTOGRAFANDO");

		printk(KERN_INFO "Msg[ANTES]= %s", message+2);
		h2c(message+2, mensagemChar, len-2);
		printk(KERN_INFO "Msg[DEPOIS]= %s", mensagemChar);
	break;
	  case 'd': // decifrar
		printk(KERN_INFO "TO DESCRIPTOGRAFANDO\n");
    break;
      case 'h': // resumo criptográico
		printk(KERN_INFO "TO MANDANDO O RESUMO\n");
    break;
   }

   return len;
}

/** @brief The device release function that is called whenever the device is closed/released by
 *  the userspace program
 *  @param inodep A pointer to an inode object (defined in linux/fs.h)
 *  @param filep A pointer to a file object (defined in linux/fs.h)
 */
static int dev_release(struct inode *inodep, struct file *filep){

   mutex_unlock(&ebbchar_mutex);          /// Releases the mutex (i.e., the lock goes up)
   printk(KERN_INFO "EBBChar: Device successfully closed\n");
   return 0;
}

/** @brief A module must use the module_init() module_exit() macros from linux/init.h, which
 *  identify the initialization function at insertion time and the cleanup function (as
 *  listed above)
 */

module_init(cripty_init);
module_exit(cripty_exit);
