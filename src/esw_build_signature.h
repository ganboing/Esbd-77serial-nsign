// SPDX-License-Identifier: GPL-2.0
/*
 * This file mainly describes the data structure
 *
 * Copyright 2024 Beijing ESWIN Computing Technology Co., Ltd.
 *   Authors:
 *    liangshuang <liangshuang@eswincomputing.com>
 *
 */

#ifndef HEADER_ESW_BUILD_SIGNATURE_H
#define HEADER_ESW_BUILD_SIGNATURE_H

#pragma once

#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <config.h>
#include <vector>

using namespace std;

#undef __SIGNATURE_PLAIN__
#undef __DEBUG_FILE_PATH__

//#define ENABEL_ENCRYPTION 0

typedef enum {
    RES_OK = 0,
    RES_BIN_FILE_NOT_EXIST,
    RES_HEX_FILE_PATH_ERROR
} RESULT_STATUS;

typedef struct {
    uint8_t len;
    uint8_t addr[2];
    uint8_t type;
    uint8_t *data;
} HEX_FORMAT;

typedef struct BTR_LOADABLE_INFO_ST {
    uint32_t load_addr;
    uint32_t init_ofs;
    uint32_t destory_ofs;
    uint32_t ioctl_ofs;
    uint32_t load_flags;
    uint32_t irq_num;
    uint32_t irq_ofs;
} BTR_LOADABLE_INFO_T;

typedef struct UART_LINK_INFO {
    uint32_t sign_link_addr;
    uint32_t image_link_addr;
} UART_LINK_INFO;

#ifdef WIN32
#pragma pack(4)
typedef struct __BTR_BOOT_CHAIN_ENTRY_ST {
    uint32_t version;
    uint64_t offset;      /* signature offset between offset 0 */
    uint64_t size;        /* signature size + payload size + gap */
    uint8_t sign_type;    /* signature type: ECDSA|RSA|PLAINTEXT */
    uint8_t key_index;    /* which key to verify the signature */
    uint8_t payload_type; /* Payload type */
    uint8_t last_flag;    /* wether this payload   is the last one*/
    uint8_t reserved0[4];
    uint32_t reserved1;
    uint32_t reserved2;
} BTR_BOOT_CHAIN_ENTRY_T;
#else
typedef struct __attribute__((__packed__)) __BTR_BOOT_CHAIN_ENTRY_ST {
    uint32_t version;
    uint64_t offset;      /* signature offset between offset 0 */
    uint64_t size;        /* signature size + payload size + gap */
    uint8_t sign_type;    /* signature type: ECDSA|RSA|PLAINTEXT */
    uint8_t key_index;    /* which key to verify the signature */
    uint8_t payload_type; /* Payload type */
    uint8_t last_flag;    /* wether this payload   is the last one*/
    uint8_t reserved0[4];
    uint32_t reserved1;
    uint32_t reserved2;
} BTR_BOOT_CHAIN_ENTRY_T;
#endif

typedef struct __BTR_BOOT_CHAIN_ST {
    uint32_t magic;                    /* Must be 0x42575345, "ESWB */
    uint32_t num_entries;              /* number of entries following this structure */
    BTR_BOOT_CHAIN_ENTRY_T entries[0]; /* entries */
} BTR_BOOT_CHAIN_T;

typedef struct __attribute__((__packed__)) __BTR_BOOT_CHAIN_SIG_ST {
    uint32_t magic;
    uint32_t reserved0;
    uint64_t link_addr; /* in use for loadable service */
    uint64_t payload_offset;
    uint64_t payload_size;  /* size in byte */
    uint64_t load_addr;     /* where to load the image */
    uint64_t entry_addr;    /* Entry address of the program and CPU will jump into */
    uint8_t payload_flags;  /* Payload is encrypted or not */
    uint8_t digest_mthd;    /* digest algorithm use SHA256 or SM3 */
    uint8_t encrypted_mthd; /* Payload encrypted algorithm */
    uint8_t vid;            /* vendor id */
    uint8_t reserved1;
    uint8_t lang[3];
    uint64_t mid;         /* market id */
    uint8_t payload_type; /* Payload type */
    uint8_t boot_flags;   /* Boot by SCPU or MCPU */
    uint8_t reserved2[6];
    uint64_t devid;     /* device id */
    uint8_t params[16]; /* Parameters for next boot stage */
    uint8_t reserved3[16];
    BTR_LOADABLE_INFO_T load_info;
    uint32_t reserved4;
    uint8_t digest[BTR_SHA256_DIGEST_SIZE];
} BTR_BOOT_CHAIN_SIG_ST;

class generator_signature
{
 private:
    void *rsa;
    uint8_t *encrypted_str;
    uint32_t encrypted_len;
    uint8_t *decrypted_str;
    uint32_t decrypted_len;
    uint8_t *signature_str;
    uint32_t signature_str_size;
    uint8_t *encrypted_str2;
    uint32_t encrypted_len2;
    uint8_t *sign_data;
    uint8_t *hash;
    uint32_t hash_size;
    uint32_t sign_size;
    const char *password;

 private:

    uint32_t sign_algorithm;
    uint32_t sign_link_addr;
    uint32_t image_link_addr;
    uint8_t keyid;
    char *payload_file_path;

    uint32_t version;
    uint32_t magic;
    uint32_t reserved0;
    uint64_t link_addr; /* in use for loadable service */
    uint64_t payload_offset;
    uint64_t payload_size;  /* size in byte */
    uint64_t load_addr;     /* where to load the image */
    uint64_t entry_addr;    /* Entry address of the program and CPU will jump into */
    uint8_t payload_flags;  /* Payload is encrypted or not */
    uint8_t digest_mthd;    /* digest algorithm use SHA256 or SM3 */
    uint8_t encrypted_mthd; /* Payload encrypted algorithm */
    uint8_t vid;            /* vendor id */
    uint8_t last_flag;
    uint8_t reserved1;
    uint8_t lang[3];
    uint64_t mid;         /* market id */
    uint8_t payload_type; /* Payload type */
    uint8_t boot_flags;   /* Boot by SCPU or MCPU */
    uint8_t reserved2[6];
    uint64_t devid;     /* device id */
    uint8_t params[16]; /* Parameters for next boot stage */
    uint8_t reserved3[16];
    uint8_t digest[BTR_SHA256_DIGEST_SIZE];
    BTR_LOADABLE_INFO_T load_info;
    uint32_t reserved4;

 public:
    generator_signature();
    ~generator_signature();
    int asymmetric_encypt(uint32_t len);
    int symmetric_encypt();
    int set_config_parameter(string parameter, string value);
    int generate_sign_file();
    void set_last_flag();
    void adjust_param(bool is_last);
 private:
    void set_default_param();
    int set_boot_entry(char *filename);
    int build_signature_data();
    int create_sign_file();
    int save_hex_file();
    int hash_calc();
#if ENABEL_ENCRYPTION
    int sha256_digest(const char *path, uint32_t *file_size, uint8_t *psha256);
    int sm3_digest(const char *path, uint32_t *FSize, uint8_t *psha256);
    int rsa_pubk_decrypt(uint8_t *from, int flen);
    int rsa_privk_encrypt(uint8_t *from, int flen);
    int ecdsa_pubk_verify(unsigned char *buffer, unsigned int buf_len);
    int ecdsa_privk_sign(uint8_t *hash_value, uint32_t hash_size);
    int ecdsa_key_split();
#endif
};

#endif  // ESW_BUILD_SIGNATURE_H
