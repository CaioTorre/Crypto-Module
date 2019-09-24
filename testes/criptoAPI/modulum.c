#include <linux/module.h> //Needed by all modules
#include <linux/kernel.h> //Needed for KERN_INFO
#include <linux/init.h> //Needed for the macros

#include <linux/moduleparam.h>
#include <linux/crypto.h>
#include <linux/mm.h>
#include <linux/scatterlist.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Triplice alianca");
MODULE_DESCRIPTION("Testing the crypto module");
MODULE_SUPPORTED_DEVICE("mycryptoromance");

// Data structures for the module
struct tcrypt_result {
    struct completion completion;
    int err;
};

/* tie all data structures together */
struct blkcipher_def {
    struct scatterlist sg;
    struct crypto_blkcipher *tfm;
    struct blkcipher_request *req;
    struct tcrypt_result result;
};


/* Perform cipher operation */
static unsigned int test_blkcipher_encdec(struct blkcipher_def *sk,
                     int enc)
{
    int rc = 0;

    if (enc)
        rc = crypto_blkcipher_encrypt(sk->req);//crypto_blkcipher_encrypt(sk->req);
    else
        rc = crypto_blkcipher_decrypt(sk->req);//crypto_blkcipher_decrypt(sk->req);

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
        pr_info("blkcipher encrypt returned with %d result %d\n",
            rc, sk->result.err);
        break;
    }
    init_completion(&sk->result.completion);

    return rc;
}

static void _strcpy(char* dest, char* src) {
    int i = 0;
    while (src[i]) dest[i] = src[i++];
    dest[i] = '\0'; 
}


/* Initialize and trigger cipher operation */
static int test_blkcipher(void)
{
    struct blkcipher_def sk;
    struct crypto_blkcipher *blkcipher = NULL;
    struct blkcipher_request *req = NULL;
    char *scratchpad = NULL;
    char *ivdata = NULL;
    unsigned char key[32];
    int ret = -EFAULT;

    blkcipher = crypto_alloc_blkcipher("cbc-aes-aesni", 0, 0);
    if (IS_ERR(blkcipher)) {
        pr_info("could not allocate blkcipher handle\n");
        return PTR_ERR(blkcipher);
    }

    req = blkcipher_request_alloc(blkcipher, GFP_KERNEL);
    if (!req) {
        pr_info("could not allocate blkcipher request\n");
        ret = -ENOMEM;
        goto out;
    }

    blkcipher_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG,
                      test_blkcipher_cb,
                      &sk.result);

    /* AES 256 with random key */
    get_random_bytes(&key, 32);
    if (crypto_blkcipher_setkey(blkcipher, key, 32)) {
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
    get_random_bytes(ivdata, 16);

    /* Input data will be random */
    scratchpad = kmalloc(16, GFP_KERNEL);
    if (!scratchpad) {
        pr_info("could not allocate scratchpad\n");
        goto out;
    }
    _strcpy(scratchpad, "abcdeABCDE12345");
    //get_random_bytes(scratchpad, 16);

    sk.tfm = blkcipher;
    sk.req = req;

    /* We encrypt one block */
    sg_init_one(&sk.sg, scratchpad, 16);
    blkcipher_request_set_crypt(req, &sk.sg, &sk.sg, 16, ivdata);
    init_completion(&sk.result.completion);

    /* encrypt data */
    ret = test_blkcipher_encdec(&sk, 1);
    if (ret)
        goto out;

    pr_info("Encryption triggered successfully\n");

out:
    if (blkcipher)
        crypto_free_blkcipher(blkcipher);
    if (req)
        blkcipher_request_free(req);
    if (ivdata)
        kfree(ivdata);
    if (scratchpad)
        kfree(scratchpad);
    return ret;
}

static int __init init_crypto_test(void)
{
	pr_info("Beginning crypto test...\n");
	int retval;
	if ((retval = test_blkcipher()) != 0) pr_info("Test failed with code %d\n", retval);
	pr_info("Finished crypto test\n");
	return 0;
}

static void __exit cleanup_crypto_test(void)
{
	pr_info("Removing crypto test module\n");
}

module_init(init_crypto_test);
module_exit(cleanup_crypto_test);
