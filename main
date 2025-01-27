#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <zlib.h>
#include <openssl/evp.h>
#include <openssl/aes.h>

// Function to compress a file
int compress_file(const char *source, const char *dest) {
    FILE *src = fopen(source, "rb");
    FILE *dst = fopen(dest, "wb");
    if (!src || !dst) {
        perror("File opening failed");
        return -1;
    }

    z_stream strm = {0};
    deflateInit(&strm, Z_BEST_COMPRESSION);

    unsigned char in[4096];
    unsigned char out[4096];

    int flush;
    do {
        strm.avail_in = fread(in, 1, sizeof(in), src);
        if (ferror(src)) {
            deflateEnd(&strm);
            return -1;
        }
        flush = feof(src) ? Z_FINISH : Z_NO_FLUSH;
        strm.next_in = in;

        do {
            strm.avail_out = sizeof(out);
            strm.next_out = out;
            deflate(&strm, flush);
            fwrite(out, 1, sizeof(out) - strm.avail_out, dst);
        } while (strm.avail_out == 0);
    } while (flush != Z_FINISH);

    deflateEnd(&strm);
    fclose(src);
    fclose(dst);
    return 0;
}

// Function to encrypt a file
int encrypt_file(const char *source, const char *dest, const unsigned char *key, const unsigned char *iv) {
    FILE *src = fopen(source, "rb");
    FILE *dst = fopen(dest, "wb");
    if (!src || !dst) {
        perror("File opening failed");
        return -1;
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);

    unsigned char in[4096];
    unsigned char out[4096 + EVP_MAX_BLOCK_LENGTH];
    int out_len;

    while (1) {
        int in_len = fread(in, 1, sizeof(in), src);
        if (in_len <= 0) break;
        EVP_EncryptUpdate(ctx, out, &out_len, in, in_len);
        fwrite(out, 1, out_len, dst);
    }

    EVP_EncryptFinal_ex(ctx, out, &out_len);
    fwrite(out, 1, out_len, dst);

    EVP_CIPHER_CTX_free(ctx);
    fclose(src);
    fclose(dst);
    return 0;
}

int main(int argc, char *argv[]) {
    if (argc != 5) {
        fprintf(stderr, "Usage: %s <source> <compressed> <encrypted> <key>\n", argv[0]);
        return 1;
    }

    const char *source = argv[1];
    const char *compressed = argv[2];
    const char *encrypted = argv[3];
    const unsigned char *key = (unsigned char *)argv[4];
    unsigned char iv[16] = {0}; // Initialization vector (IV) should be random in real applications

    if (compress_file(source, compressed) != 0) {
        fprintf(stderr, "Compression failed\n");
        return 1;
    }

    if (encrypt_file(compressed, encrypted, key, iv) != 0) {
        fprintf(stderr, "Encryption failed\n");
        return 1;
    }

    printf("File compressed and encrypted successfully\n");
    return 0;
}
