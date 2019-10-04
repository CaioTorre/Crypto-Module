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

#define DEVICE_NAME "ebbchar"    ///< The device will appear at /dev/ebbchar using this value
#define CLASS_NAME  "ebb"        ///< The device class -- this is a character device driver
#define PARAM_LEN 33
#define FILL_SG(sg,ptr,len)     do { (sg)->page_link = virt_to_page(ptr); (sg)->offset = offset_in_page(ptr); (sg)->length = len; } while (0)
#define DATA_SIZE 256

MODULE_LICENSE("GPL");            ///< The license type -- this affects available functionality
MODULE_AUTHOR("JBMC");    ///< The author -- visible when you use modinfo
MODULE_DESCRIPTION("Famigerado projetinho de SO B");  ///< The description -- see modinfo
MODULE_SUPPORTED_DEVICE("MyCryptoRomance");
MODULE_VERSION("0.1");            ///< A version number to inform users

static void hexdump(unsigned char *buf, unsigned int len) {
        while (len--) { printk("%02x", *buf++); }
        printk("\n");
}

struct tcrypt_result {
    struct completion completion;
    int err;
};

// https://stackoverflow.com/questions/3869028/how-to-use-cryptoapi-in-the-linux-kernel-2-6

/* tie all data structures together */
/*
*struct skcipher_request {
*	unsigned int cryptlen;
*
*	u8 *iv;
*
*	struct scatterlist *src;
*	struct scatterlist *dst;
*
*	struct crypto_async_request base;
*	
*	void *__ctx[] CRYPTO_MINALIGN_ATTR;
*};
*/

struct skcipher_def {
    //struct scatterlist sg_src;
    //struct scatterlist sg_dst;
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
        rc = wait_for_completion_interruptible( &sk->result.completion );
        if (!rc && !sk->result.err) {
            reinit_completion(&sk->result.completion);
            break;
        }
    default:
        pr_info("skcipher encrypt returned with %d result %d\n", rc, sk->result.err);
        break;
    }
    init_completion(&sk->result.completion);

    return rc;
}

/* Initialize and trigger cipher operation */
static int test_skcipher(void)
{
    struct skcipher_def sk;
    struct crypto_skcipher *skcipher = NULL;
    struct skcipher_request *req = NULL;
    char *scratchpad = NULL;
    char *resultdata = NULL;
    char *ivdata = NULL;
    unsigned char key[32];
    int ret = -EFAULT;

    skcipher = crypto_alloc_skcipher("cbc(aes)", 0, 0); //cbc-aes-aesni
    if (IS_ERR(skcipher)) {
        pr_info("could not allocate skcipher handle (%ld)\n", PTR_ERR(skcipher));
        return PTR_ERR(skcipher);
    }

    req = skcipher_request_alloc(skcipher, GFP_KERNEL);
    if (!req) {
        pr_info("could not allocate skcipher request\n");
        ret = -ENOMEM;
        goto out;
    }

    skcipher_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG, test_skcipher_cb, &sk.result);

    /* AES 256 with random key */
    get_random_bytes(&key, 32);
    if (crypto_skcipher_setkey(skcipher, key, 32)) {
        pr_info("key could not be set\n");
        ret = -EAGAIN;
        goto out;
    }

    printk(KERN_INFO "Key: "); hexdump(key, 32);

    /* IV will be random */
    ivdata = kmalloc(16, GFP_KERNEL);
    if (!ivdata) {
        pr_info("could not allocate ivdata\n");
        goto out;
    }
    get_random_bytes(ivdata, 16);

    printk(KERN_INFO "IV: "); hexdump(ivdata, 16);
    
    /* Input data will be random */
    scratchpad = kmalloc(16, GFP_KERNEL);
    if (!scratchpad) {
        pr_info("could not allocate scratchpad\n");
        goto out;
    }
    get_random_bytes(scratchpad, 16);
    printk(KERN_INFO "Data: "); hexdump(scratchpad, 16);

    sk.tfm = skcipher;
    sk.req = req;

    /* We encrypt one block */
    sg_init_one(&sk.sg, scratchpad, 16);
    skcipher_request_set_crypt(req, &sk.sg, &sk.sg, 16, ivdata);
    init_completion(&sk.result.completion);

    /* encrypt data */
    ret = test_skcipher_encdec(&sk, 1);
    if (ret)
        goto out;

    pr_info("Encryption triggered successfully\n");

    /* print results */
    resultdata = sg_virt(&sk.sg);
    printk(KERN_INFO "Result: "); hexdump(resultdata, 32);
    
out:
    if (skcipher)
        crypto_free_skcipher(skcipher);
    if (req)
        skcipher_request_free(req);
    if (ivdata)
        kfree(ivdata);
    if (scratchpad)
        kfree(scratchpad);
    return ret;
}

static int __init cripty_init(void){
   pr_info("Inicializado cripty.c\n");	

   test_skcipher(); //param key e iv
   
   return 0;
}

/** @brief The LKM cleanup function
 *  Similar to the initialization function, it is static. The __exit macro notifies that if this
 *  code is used for a built-in driver (not a LKM) that this function is not required.
 */
static void __exit cripty_exit(void){
   pr_info("Finalizando cripty.c\n");
}

module_init(cripty_init);
module_exit(cripty_exit);
