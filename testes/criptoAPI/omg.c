#include <linux/module.h> //Needed by all modules
#include <linux/kernel.h> //Needed for KERN_INFO
#include <linux/init.h> //Needed for the macros

#include <sys/ioctl.h>
#include <crypto/cryptodev.h>

#define	DATA_SIZE	8*1024
#define	BLOCK_SIZE	16
#define	KEY_SIZE	16

//https://github.com/cryptodev-linux/cryptodev-linux/blob/master/tests/cipher.c

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Triplice alianca");
MODULE_DESCRIPTION("Testing the crypto module");
MODULE_SUPPORTED_DEVICE("mycryptoromance");


static int test_aes(int cfd)
{
	uint8_t plaintext1_raw[BLOCK_SIZE + 63], *plaintext1;
	uint8_t ciphertext1[BLOCK_SIZE] = { 0xdf, 0x55, 0x6a, 0x33, 0x43, 0x8d, 0xb8, 0x7b, 0xc4, 0x1b, 0x17, 0x52, 0xc5, 0x5e, 0x5e, 0x49 };
	uint8_t iv1[BLOCK_SIZE];
	uint8_t key1[KEY_SIZE] = { 0xff, 0xff, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
	uint8_t plaintext2_data[BLOCK_SIZE] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xc0, 0x00 };
	uint8_t plaintext2_raw[BLOCK_SIZE + 63], *plaintext2;
	uint8_t ciphertext2[BLOCK_SIZE] = { 0xb7, 0x97, 0x2b, 0x39, 0x41, 0xc4, 0x4b, 0x90, 0xaf, 0xa7, 0xb2, 0x64, 0xbf, 0xba, 0x73, 0x87 };
	uint8_t iv2[BLOCK_SIZE];
	uint8_t key2[KEY_SIZE];

	struct session_op sess;
	struct crypt_op cryp;

	memset(&sess, 0, sizeof(sess));
	memset(&cryp, 0, sizeof(cryp));

	/* Get crypto session for AES128 */
	sess.cipher = CRYPTO_AES_CBC;
	sess.keylen = KEY_SIZE;
	sess.key = key1;
	if (ioctl(cfd, CIOCGSESSION, &sess)) {
		perror("ioctl(CIOCGSESSION)");
		return 1;
	}

	plaintext1 = plaintext1_raw;
	memset(plaintext1, 0x0, BLOCK_SIZE);
	memset(iv1, 0x0, sizeof(iv1));

	/* Encrypt data.in to data.encrypted */
	cryp.ses = sess.ses;
	cryp.len = BLOCK_SIZE;
	cryp.src = plaintext1;
	cryp.dst = plaintext1;
	cryp.iv = iv1;
	cryp.op = COP_ENCRYPT;
	if (ioctl(cfd, CIOCCRYPT, &cryp)) {
		perror("ioctl(CIOCCRYPT)");
		return 1;
	}

	/* Verify the result */
	if (memcmp(plaintext1, ciphertext1, BLOCK_SIZE) != 0) {
		fprintf(stderr,
			"FAIL: Decrypted data are different from the input data.\n");
		return 1;
	}

	/* Test 2 */

	memset(key2, 0x0, sizeof(key2));
	memset(iv2, 0x0, sizeof(iv2));

	/* Get crypto session for AES128 */
	sess.cipher = CRYPTO_AES_CBC;
	sess.keylen = KEY_SIZE;
	sess.key = key2;
	if (ioctl(cfd, CIOCGSESSION, &sess)) {
		perror("ioctl(CIOCGSESSION)");
		return 1;
	}

	plaintext2 = plaintext2_raw;
	memcpy(plaintext2, plaintext2_data, BLOCK_SIZE);

	/* Encrypt data.in to data.encrypted */
	cryp.ses = sess.ses;
	cryp.len = BLOCK_SIZE;
	cryp.src = plaintext2;
	cryp.dst = plaintext2;
	cryp.iv = iv2;
	cryp.op = COP_ENCRYPT;
	if (ioctl(cfd, CIOCCRYPT, &cryp)) {
		perror("ioctl(CIOCCRYPT)");
		return 1;
	}

	/* Verify the result */
	if (memcmp(plaintext2, ciphertext2, BLOCK_SIZE) != 0) {
		int i;
		fprintf(stderr,
			"FAIL: Decrypted data are different from the input data.\n");
		printf("plaintext:");
		for (i = 0; i < BLOCK_SIZE; i++) {
			if ((i % 30) == 0)
				printf("\n");
			printf("%02x ", plaintext2[i]);
		}
		printf("ciphertext:");
		for (i = 0; i < BLOCK_SIZE; i++) {
			if ((i % 30) == 0)
				printf("\n");
			printf("%02x ", ciphertext2[i]);
		}
		printf("\n");
		return 1;
	}

	if (debug) printf("AES Test passed\n");

	/* Finish crypto session */
	if (ioctl(cfd, CIOCFSESSION, &sess.ses)) {
		perror("ioctl(CIOCFSESSION)");
		return 1;
	}

	return 0;
}


static int __init init_crypto_test(void)
{
	pr_info("Beginning crypto test...\n");
	int retval;
	int cfd;
	int fd = open("/dev/crypto", O_RDWR, 0);
	
	/* Cloning file descriptor */
	if (ioctl(fd, CRIOGET, &cfd)) {
		perror("ioctl(CRIOGET)");
		return 1;
	}

	/* Set close-on-exec (not really neede here) */
	if (fcntl(cfd, F_SETFD, 1) == -1) {
		perror("fcntl(F_SETFD)");
		return 1;
	}
	if ((retval = test_aes(cfd)) != 0) pr_info("Test failed with code %d\n", retval);
	//if ((retval = test_blkcipher()) != 0) pr_info("Test failed with code %d\n", retval);
	pr_info("Finished crypto test\n");
	return 0;
}

static void __exit cleanup_crypto_test(void)
{
	pr_info("Removing crypto test module\n");
}

module_init(init_crypto_test);
module_exit(cleanup_crypto_test);
