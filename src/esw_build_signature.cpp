// SPDX-License-Identifier: GPL-2.0
/*
 * This file mainly implements the functions of chief sign, uart sign, and image packaging
 *
 * Copyright 2024 Beijing ESWIN Computing Technology Co., Ltd.
 *   Authors:
 *    liangshuang <liangshuang@eswincomputing.com>
 *
 */

#include <esw_build_signature.h>
#include <stdlib.h>
#include <fstream>
#include <iostream>
#include <string>

#ifdef WIN32
#include <direct.h>
#include <Windows.h>
#else
#include <sys/stat.h>
#include <sys/types.h>
#endif

#define DEBUG_ON 0
#if DEBUG_ON
#define ndebug(format, ...) printf("%s %s:%5d " format, "[D]", __FUNCTION__, __LINE__, ##__VA_ARGS__)
#else
#define ndebug(format, ...)
#endif

#define NSIGN_VERSION "2.0.0"

#define STR_SIZE_OF(X) (sizeof(X) * 2)

#define SCPU_DEFAULT_ADDR 0x59000000
#define MCPU_DEFAULT_ADDR 0x80000000
#define PAYLOADE_DEFAULT_TYPE 0x70

static int bootchain_link_addr = 0x0;
int g_sign_idx = 0;
static int sign_count = 0;
static int cmd = 0;
static long g_entry_offset = 0x200;
static char* bin_file_list[IMAGE_MAX_COUNT];
static char* sign_file_list[IMAGE_MAX_COUNT];
static char* bin2hex_sign_file_list[IMAGE_MAX_COUNT];
static char* bin2hex_image_file_list[IMAGE_MAX_COUNT];
static BTR_BOOT_CHAIN_ENTRY_T boot_chain_entry[IMAGE_MAX_COUNT];
static UART_LINK_INFO uart_link_info[IMAGE_MAX_COUNT];
static const char* output_path = (char*)"default";
static BTR_BOOT_CHAIN_T btr_boot_chain;
static unsigned char buffer_hex[MAX_BUFFER_OF_ONE_LINE];
vector<generator_signature*> vec_sign;

#ifndef WIN32
char* inter_hex_file_path = (char*)"/out/others/sign/sign_data.hex";
char* bootchain_bin_path = (char*)"/out/uart/bootchain.bin";
char* bootchain_hex_path = (char*)"/out/uart/bootchain.hex";
const char* uart_boot_path = (char*)"/out/uart/uart_boot.hex";
const char* chief_boot_path = (char*)"/out/chief/chief_boot.bin";
const char* config_file_path = "/config.txt";
#else
char* inter_hex_file_path = (char*)"\\out\\others\\sign\\sign_data.hex";
char* bootchain_bin_path = (char*)"\\out\\uart\\bootchain.bin";
char* bootchain_hex_path = (char*)"\\out\\uart\\bootchain.hex";
const char* uart_boot_path = (char*)"\\out\\uart\\uart_boot.hex";
const char* chief_boot_path = (char*)"\\out\\chief\\chief_boot.bin";
const char* config_file_path = "\\config.txt";
#endif

int create_data_dir(const char* dir)
{
    char dir_tmp[256] = {0};
    int ret = 0;
    int i = 0;

#ifdef WIN32
    char c = '\\';
#else
    char c = '/';
#endif

    for (i = 0; i < strlen(dir); i++) {
        if (dir[i] == c) {
            memcpy(dir_tmp, dir, i + 1);
        }
        if ((dir_tmp[0] != 0) && (0 != access(dir_tmp, 0))) {
            // create this folder
#ifdef WIN32
            ret = mkdir(dir_tmp);
#else
            ret = mkdir(dir_tmp, 0775);
#endif
            if (ret) {
                printf("error: create dir(%s) failed.\r\n", dir_tmp);
                return ERR_CREATEDIR;
            }
            ndebug("create dir:%s success\r\n", dir_tmp);
        }
    }

    return 0;
}

static int create_dir()
{
    int ret = 0;

    ret = create_data_dir(inter_hex_file_path);
    if (ret) return ret;

    ret = create_data_dir(bootchain_bin_path);
    if (ret) return ret;

    ret = create_data_dir(chief_boot_path);
    if (ret) return ret;

    return 0;
}

char* change_file_name(char* file_name, int num)
{
    string split_path, split_tpye, i_str, file_tmp;
    string s(file_name);
    split_path = s.substr(0, s.length() - 4);
    split_tpye = s.substr(s.length() - 4, s.length());
    int i_tmp = num;
    i_str = to_string(i_tmp);
    file_tmp = split_path.append(i_str).append(split_tpye);
    file_name = new char[file_tmp.length() + 1];
    strcpy(file_name, file_tmp.c_str());

    return file_name;
}

static char* replace_file_name(char* file_name, const char* suffix)
{
    string split_path, split_tpye, file_tmp;
    string s(file_name);
    split_path = s.substr(0, s.length() - 3);
    file_tmp = split_path.append(suffix);
    file_name = new char[file_tmp.length() + 1];
    strcpy(file_name, file_tmp.c_str());

    return file_name;
}

static void trim(string& s)
{
    const string delim(" \t\r");
    s.erase(0, s.find_first_not_of(delim));
    s.erase(s.find_last_not_of(delim) + 1);
}

static void trim(char* str_in, char* str_out)
{
    char *start, *end, *temp;
    temp = str_in;

    while (*temp == ' ') {
        ++temp;
    }
    start = temp;
    temp = str_in + strlen(str_in) - 1;

    while (*temp == ' ') {
        --temp;
    }
    end = temp;
    for (str_in = start; str_in <= end;) {
        *str_out++ = *str_in++;
    }

    *str_out = '\0';
}

static void align_str(string& str, int align_len)
{
    while (str.size() < align_len) {
        str = "0" + str;
    }
}

char* file_path_joint(const char* file_path)
{
    char* current_path;
    char* f_path;
#ifdef WIN32
    char path_test[512] = {0};
    GetCurrentDirectory(sizeof(path_test), path_test);
    current_path = path_test;
#else
    current_path = getcwd(NULL, 0);
#endif
    string s = current_path;

#ifdef __DEBUG_FILE_PATH__
    size_t index = s.rfind("/");
    string path = s.substr(0, index).append(file_path);
#else

#ifdef WIN32
    string path = s.append(file_path);
#else
    string path = s.append(file_path);
#endif

#endif

    f_path = new char[path.length() + 2]();
    memset(f_path, 0, path.length() + 2);
    strncpy(f_path, path.c_str(), path.length());

    return f_path;
}

void write_str_to_memory(string str, char* mem)
{
    if (str.size() % 2 != 0) {
        str = "0" + str;
    }

    for (string::size_type ix = 0; ix != str.size(); ix = ix + 2) {
        basic_string<char> tmp = str.substr(ix, 2);
        char* s = NULL;
        char i = (char)strtol(tmp.c_str(), &s, 16);
        memcpy(mem, &i, 1);
        mem++;
    }
}

int dump_hex_to_file(FILE* fp, const uint8_t* buffer, const uint32_t size)
{
    uint32_t i;
    if (!buffer) {
        return 0;
    }
    for (i = 0; i < size; i++) {
        if (i && (i % 16) == 0) {
            fprintf(fp, "\r\n");
        }
        fprintf(fp, "%02X", (unsigned char)buffer[i]);
    }
    fprintf(fp, "\r\n");
    if (ferror(fp)) return ERR_IO;
    return 0;
}

#if ENABEL_ENCRYPTION
#define ENCYPT_VERSION "encrypted"
extern int encrypt_prepare();
extern int create_rsa_key();
extern int create_ecdsa_key();

#else
#define ENCYPT_VERSION "unencrypted"
int encrypt_prepare() { return 0; }

int create_rsa_key() { return ERR_UNSUPPORTED; }

int create_ecdsa_key() { return ERR_UNSUPPORTED; }

int generator_signature::asymmetric_encypt(uint32_t len) { return 0; }

int generator_signature::symmetric_encypt() { return 0; }

int generator_signature::hash_calc() { return 0; }

#endif

generator_signature::generator_signature()
{
    rsa = NULL;
    encrypted_len = 0;
    decrypted_len = 0;
    sign_size = 144 + 32;
    signature_str = NULL;
    signature_str_size = 400 + 32;
    encrypted_str = NULL;
    encrypted_str2 = NULL;
    decrypted_str = NULL;
    hash_size = 0;
    hash = NULL;

    set_default_param();
}

int generator_signature::set_boot_entry(char* filename)
{
    FILE* Binfp = NULL;
    uint64_t file_size, img_size;

    payload_offset = g_entry_offset;
    uint64_t* p_offset = (uint64_t*)&payload_offset;
    uint64_t* p_size = (uint64_t*)&payload_size;
    uint8_t* p_sign_algo = (uint8_t*)&sign_algorithm;
    uint8_t* p_key_index = (uint8_t*)&keyid;
    uint32_t* p_version = (uint32_t*)&version;
    uint8_t* p_payloadtype = (uint8_t*)&payload_type;
    uint8_t* p_last_flag = (uint8_t*)&last_flag;

    //------------get payload_file_path file size-----------
    Binfp = fopen(filename, "rb");
    if (Binfp == NULL) {
        printf("error: open file(%s) failed!\r\n", filename);
        return ERR_IO;
    }
    fseek(Binfp, 0, SEEK_END);
    file_size = ftell(Binfp);
    fseek(Binfp, 0, SEEK_SET);
    payload_size = file_size;
    printf("input file:%s\r\n", filename);
    printf("file size:%ld\r\n", file_size);
    printf("payload_type:0x%x last_flag:%d\r\n", payload_type, last_flag);

    //------------set boot entry parameter-----------
    memcpy(&boot_chain_entry[g_sign_idx].offset, p_offset, sizeof(uint64_t));
    memcpy(&boot_chain_entry[g_sign_idx].size, p_size, sizeof(uint64_t));
    memcpy(&boot_chain_entry[g_sign_idx].sign_type, p_sign_algo, sizeof(uint8_t));
    memcpy(&boot_chain_entry[g_sign_idx].key_index, p_key_index, sizeof(uint8_t));
    memcpy(&boot_chain_entry[g_sign_idx].version, p_version, sizeof(uint32_t));
    memcpy(&boot_chain_entry[g_sign_idx].payload_type, p_payloadtype, sizeof(uint8_t));
    memcpy(&boot_chain_entry[g_sign_idx].last_flag, p_last_flag, sizeof(uint8_t));

    g_entry_offset = g_entry_offset + SIGN_SIZE + payload_size + IMAGE_GAP;
    g_entry_offset = (g_entry_offset / IMAGE_ALIGN + 1) * IMAGE_ALIGN;
    return 0;
}

int generator_signature::create_sign_file()
{
    int ret = 0, length = 0;
    char* tmp_file = payload_file_path;

    ret = symmetric_encypt();
    if (ret < 0) {
        printf("error: symmetric encypt failed!ret:%d\r\n", ret);
        return ret;
    }

    bin_file_list[g_sign_idx] = payload_file_path;
    ret = set_boot_entry(tmp_file);
    if (ret < 0) {
        return ret;
    }

    /* set uartlink info */
    if (cmd == CMD_UART_SIGN) {
        uint32_t* p_sign_link_addr = (uint32_t*)&sign_link_addr;
        uint32_t* p_image_link_addr = (uint32_t*)&image_link_addr;
        memcpy(&uart_link_info[g_sign_idx].sign_link_addr, p_sign_link_addr, sizeof(uint32_t));
        memcpy(&uart_link_info[g_sign_idx].image_link_addr, p_image_link_addr, sizeof(uint32_t));
    }

    /* build sign data */
    if (ret = build_signature_data()) {
        printf("error: build_signature_dataV failed!\r\n");
        return ret;
    }

    return ret;
}

int generator_signature::build_signature_data()
{
    uint32_t len = 0;
    int ret = 0;

    ret = hash_calc();
    if (ret) {
        return ret;
    }

    //-----------------copy signature_str to sign_data-------------
    memset(sign_data, 0, sign_size);
    memset(signature_str, 0, signature_str_size);

    memcpy(&signature_str[len], &magic, sizeof(magic));
    len += sizeof(magic);

    memcpy(&signature_str[len], &reserved0, sizeof(reserved0));
    len += sizeof(reserved0);

    memcpy(&signature_str[len], &link_addr, sizeof(link_addr));
    len += sizeof(link_addr);

    memcpy(&signature_str[len], &payload_offset, sizeof(payload_offset));
    len += sizeof(payload_offset);

    memcpy(&signature_str[len], &payload_size, sizeof(payload_size));
    len += sizeof(payload_size);

    memcpy(&signature_str[len], &load_addr, sizeof(load_addr));
    len += sizeof(load_addr);

    memcpy(&signature_str[len], &entry_addr, sizeof(entry_addr));
    len += sizeof(entry_addr);

    memcpy(&signature_str[len], &payload_flags, sizeof(payload_flags));
    len += sizeof(payload_flags);

    memcpy(&signature_str[len], &digest_mthd, sizeof(digest_mthd));
    len += sizeof(digest_mthd);

    memcpy(&signature_str[len], &encrypted_mthd, sizeof(encrypted_mthd));
    len += sizeof(encrypted_mthd);

    memcpy(&signature_str[len], &vid, sizeof(vid));
    len += sizeof(vid);

    memcpy(&signature_str[len], &reserved1, sizeof(reserved1));
    len += sizeof(reserved1);

    memcpy(&signature_str[len], &lang, sizeof(lang));
    len += sizeof(lang);

    memcpy(&signature_str[len], &mid, sizeof(mid));
    len += sizeof(mid);

    memcpy(&signature_str[len], &payload_type, sizeof(payload_type));
    len += sizeof(payload_type);

    memcpy(&signature_str[len], &boot_flags, sizeof(boot_flags));
    len += sizeof(boot_flags);

    memcpy(&signature_str[len], &reserved2, sizeof(reserved2));
    len += sizeof(reserved2);

    memcpy(&signature_str[len], &devid, sizeof(devid));
    len += sizeof(devid);

    memcpy(&signature_str[len], &params, sizeof(params));
    len += sizeof(params);

    memcpy(&signature_str[len], &reserved3, sizeof(reserved3));
    len += sizeof(reserved3);

    memcpy(&signature_str[len], &load_info, sizeof(load_info));
    len += sizeof(load_info);

    memcpy(&signature_str[len], &reserved4, sizeof(reserved4));
    len += sizeof(reserved4);

    memcpy(&digest, hash, hash_size);
    memcpy(&signature_str[len], &digest, sizeof(digest));
    len += sizeof(digest);

    memcpy(&sign_data[0], &signature_str[0], len);

    ret = asymmetric_encypt(len);

    return ret;
}

int generator_signature::save_hex_file()
{
    FILE* outp = NULL;
    uint32_t ret = 0;

    char* tmp_file;
    tmp_file = inter_hex_file_path;
    tmp_file = change_file_name(tmp_file, g_sign_idx);
    if ((outp = fopen(tmp_file, "wb")) == NULL) {
        printf("error: Cannot open output file(%s).\n", tmp_file);
        return ERR_OPENFILE;
    }
    //--------------save encrypt sign_data to hex file--------------
    if (sign_algorithm == BTR_SIGN_TYPE_RSA_2048) {
        if ((ret = dump_hex_to_file(outp, encrypted_str, encrypted_len))) {
            return ret;
        }
    } else if (sign_algorithm == BTR_SIGN_TYPE_ECDSA) {
        if ((ret = dump_hex_to_file(outp, signature_str, SIGN_SIZE))) {
            return ret;
        }
    } else {
        if ((ret = dump_hex_to_file(outp, sign_data, sign_size))) {
            return ret;
        }
    }

    sign_file_list[g_sign_idx] = tmp_file;
    fflush(outp);
    fclose(outp);

    return ret;
}

void generator_signature::set_default_param()
{
    char tmp[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    magic = MAGIC_DEFAULT;
    reserved0 = RESERVED0_DEFAULT;
    link_addr = LINK_ADDR_DEFAULT;
    vid = VID_DEFAULT;
    reserved1 = RESERVED1_DEFAULT;
    memset(&lang, 0x0, 3);
    mid = MID_DEFAULT;
    memset(&reserved2, 0x0, 6);
    devid = DEVID_DEFAULT;
    memcpy(params, tmp, 16);
    memset(&reserved3, 0x0, 16);
    memset(&load_info, 0x0, 28);
    reserved4 = RESERVED4_DEFAULT;

    encrypted_len2 = 0;
    sign_algorithm = 0;
    sign_link_addr = 0;
    image_link_addr = 0;
    keyid = 0;
    payload_file_path = NULL;
    version = 0;
    payload_offset = 0;
    payload_size = 0;
    load_addr = 0;
    entry_addr = 0;
    payload_flags = 0;
    digest_mthd = 0;
    encrypted_mthd = 0;
    last_flag = 0;
    payload_type = 0;
    boot_flags = 0;
    memset(digest, 0, BTR_SHA256_DIGEST_SIZE);
}

int generator_signature::generate_sign_file()
{
    int ret = 0;
    signature_str = new unsigned char[signature_str_size]();
    encrypted_str = new unsigned char[(DEF_KEYLEN) >> 3]();
    decrypted_str = new unsigned char[sign_size]();
    sign_data = new unsigned char[sign_size]();
    hash_size = HASH_SHA256_LEN;
    hash = new unsigned char[hash_size]();

    if ((ret = create_sign_file())) {
        printf("error: create sign file failed!\r\n");
        goto Failed;
    }
    if ((ret = save_hex_file())) {
        printf("error: save hex file failed!\r\n");
        goto Failed;
    }

Failed:
    delete signature_str;
    delete decrypted_str;
    delete encrypted_str;
    delete sign_data;
    delete hash;

    return ret;
}
void generator_signature::set_last_flag()
{
    last_flag = 1;
}
void generator_signature::adjust_param(bool is_last)
{
    if (cmd == CMD_CHIEF_SIGN || cmd == CMD_UART_SIGN) {
        last_flag = uint8_t(is_last);
        if (boot_flags == 0) {
            if (!load_addr && !entry_addr) {
                load_addr = SCPU_DEFAULT_ADDR;
                entry_addr = SCPU_DEFAULT_ADDR;
            }
        }else if (boot_flags == 1) {
            if (!load_addr && !entry_addr) {
                load_addr = MCPU_DEFAULT_ADDR;
                entry_addr = MCPU_DEFAULT_ADDR;
            }
        }
    }
}

string parameter_set[36] = {
    "sign_algorithm",   // 0
    "in",               // 1
    "sign_link_addr",   // 2
    "image_link_addr",  // 3
    "cmd",              // 4
    "version",          // 5
    "magic",            // 6
    "reserved0",        // 7
    "link_addr",        // 8
    "payload_size",     // 9
    "load_addr",        // 10
    "entry_addr",       // 11
    "payload_flags",    // 12
    "digest_mthd",      // 13
    "encrypted_mthd",   // 14
    "vid",              // 15
    "reserved1",        // 16
    "mid",              // 17
    "payload_type",     // 18
    "boot_flags",       // 19
    "reserved2",        // 20
    "devid",            // 21
    "params",           // 22
    "reserved3",        // 23
    "digest",           // 24
    "dl_load_addr",     // 25
    "dl_init_ofs",      // 26
    "dl_destory_ofs",   // 27
    "dl_ioctl_ofs",     // 28
    "dl_load_flags",    // 29
    "dl_irq_num",       // 30
    "dl_irq_ofs",       // 31
    "keyid",            // 32
    "load_info",        // 33
    "reserved4",        // 34
    "lang",             // 35
};

int generator_signature::set_config_parameter(string parameter, string value)
{
    void* tmp_str = NULL;
    string str;
    char* optarg;
    int count = ERR_ARGUMENT;
    for (int i = 0; i < sizeof(parameter_set); i++) {
        if (parameter == parameter_set[i]) {
            count = i;
            break;
        }
    }
    optarg = new char[value.length() + 1];
    strcpy(optarg, value.c_str());
    str = optarg;

    ndebug("%d --- %s\n", count, str.c_str());

    if (count >= 0) {
        switch (count) {
            case 0:
                if (!STRCASECMP(optarg, "RSA")) {
                    sign_algorithm = BTR_SIGN_TYPE_RSA_2048;
                } else if (!STRCASECMP(optarg, "ECDSA")) {
                    sign_algorithm = BTR_SIGN_TYPE_ECDSA;
                } else if (!STRCASECMP(optarg, "plaintext")) {
                    sign_algorithm = BTR_SIGN_TYPE_PLAINTEXT;
                } else
                    return ERR_ARGUMENT;
                break;

            case 1:
                payload_file_path = optarg;
                break;

            case 2:
                sign_link_addr = stol(str, 0, 16);
                break;

            case 3:
                image_link_addr = stol(str, 0, 16);
                break;

            case 4: {
                if (!STRCASECMP(optarg, CMD_GENKEY_TEXT)) {
                    cmd = CMD_GENKEY;
                } else if (!STRCASECMP(optarg, CMD_UART_SIGN_TEXT)) {
                    cmd = CMD_UART_SIGN;
                } else if (!STRCASECMP(optarg, CMD_CHIEF_SIGN_TEXT)) {
                    cmd = CMD_CHIEF_SIGN;
                } else
                    return ERR_ARGUMENT;
            } break;

            case 5: {
                version = stoi(str, 0, 16);
            } break;

            case 6: {
                tmp_str = &magic;
                write_str_to_memory(str, (char*)tmp_str);
            } break;

            case 7: {
                tmp_str = &reserved0;
                write_str_to_memory(str, (char*)tmp_str);
            } break;

            case 8: {
                link_addr = stoul(str, 0, 16);
            } break;

            case 9: {
                tmp_str = &payload_size;
                write_str_to_memory(str, (char*)tmp_str);
            } break;

            case 10: {
                load_addr = stoul(str, 0, 16);
            } break;

            case 11: {
                entry_addr = stoul(str, 0, 16);
            } break;

            case 12: {
                if (!STRCASECMP(optarg, "plaintext")) {
                    payload_flags = 0x0;
                } else if (!STRCASECMP(optarg, "encrypted")) {
                    payload_flags = 0x1;
                } else
                    return ERR_ARGUMENT;
            } break;

            case 13: {
                if (!STRCASECMP(optarg, "SHA")) {
                    digest_mthd = 0x0;
                } else if (!STRCASECMP(optarg, "SM3")) {
                    digest_mthd = 0x1;
                } else
                    return ERR_ARGUMENT;
            } break;

            case 14: {
                if (!STRCASECMP(optarg, "plaintext")) {
                    encrypted_mthd = 0x0;
                } else if (!STRCASECMP(optarg, "AES")) {
                    encrypted_mthd = 0x1;
                } else if (!STRCASECMP(optarg, "SM4")) {
                    encrypted_mthd = 0x2;
                } else
                    return ERR_ARGUMENT;
            } break;

            case 15: {
                tmp_str = &vid;
                write_str_to_memory(str, (char*)tmp_str);
            } break;

            case 16: {
                tmp_str = &reserved1;
                write_str_to_memory(str, (char*)tmp_str);
            } break;

            case 17: {
                align_str(str, STR_SIZE_OF(mid));
                tmp_str = &mid;
                write_str_to_memory(str, (char*)tmp_str);
            } break;

            case 18: {
                if (!STRCASECMP(optarg, "PUBKEY_RSA"))
                    payload_type = 0x0;
                else if(!STRCASECMP(optarg, "PUBKEY_ECC"))
                    payload_type = 0x01;
                else if(!STRCASECMP(optarg, "DDR"))
                    payload_type = 0x10;
                else if(!STRCASECMP(optarg, "D2D"))
                    payload_type = 0x20;
                else if(!STRCASECMP(optarg, "BOOTLOADER"))
                    payload_type = 0x30;
                else if(!STRCASECMP(optarg, "KERNEL"))
                    payload_type = 0x40;
                else if(!STRCASECMP(optarg, "ROOTFS"))
                    payload_type = 0x50;
                else if(!STRCASECMP(optarg, "APP"))
                    payload_type = 0x60;
                else if(!STRCASECMP(optarg, "FIRMWARE"))
                    payload_type = 0x70;
                else if(!STRCASECMP(optarg, "PATCH"))
                    payload_type = 0x80;
                else if(!STRCASECMP(optarg, "LOADABLE_SRVC"))
                    payload_type = 0x90;
                else
                    return ERR_ARGUMENT;
            } break;

            case 19: {
                if (!STRCASECMP(optarg, "SCPU"))
                    boot_flags = 0x0;
                else if(!STRCASECMP(optarg, "MCPU"))
                    boot_flags = 0x01;
                else
                    return ERR_ARGUMENT;
            } break;

            case 20: {
                tmp_str = &reserved2;
                write_str_to_memory(str, (char*)tmp_str);
            } break;

            case 21: {
                tmp_str = &devid;
                align_str(str, STR_SIZE_OF(devid));
                write_str_to_memory(str, (char*)tmp_str);
            } break;

            case 22: {
                tmp_str = &params;
                write_str_to_memory(str, (char*)tmp_str);
            } break;

            case 23: {
                tmp_str = &reserved3;
                write_str_to_memory(str, (char*)tmp_str);
            } break;

            case 24: {
                tmp_str = &digest;
                write_str_to_memory(str, (char*)tmp_str);
            } break;

            case 25:
                load_info.load_addr = stoi(str, 0, 16);
                break;

            case 26:
                load_info.init_ofs = stoi(str, 0, 16);
                break;

            case 27:
                load_info.destory_ofs = stoi(str, 0, 16);
                break;

            case 28:
                load_info.ioctl_ofs = stoi(str, 0, 16);
                break;

            case 29:
                load_info.load_flags = stoi(str, 0, 16);
                break;

            case 30:
                load_info.irq_num = stoi(str, 0, 16);
                break;

            case 31:
                load_info.irq_ofs = stoi(str, 0, 16);
                break;

            case 32: {
                tmp_str = &keyid;
                write_str_to_memory(str, (char*)tmp_str);
            } break;

            case 33: {
                tmp_str = &load_info;
                write_str_to_memory(str, (char*)tmp_str);
            } break;

            case 34: {
                reserved4 = stoi(str, 0, 16);
            } break;

            case 35: {
                tmp_str = &lang;
                write_str_to_memory(str, (char*)tmp_str);
            } break;

            default:
                return ERR_ARGUMENT;
        }
    }
    return count;
}

uint16_t bin_format_encode(uint8_t* dest, HEX_FORMAT* p)
{
    uint16_t offset = 0;
    uint8_t check = 0, num = 0;
    sprintf((char*)&dest[offset], ":%02X%02X%02X%02X", p->len, p->addr[0], p->addr[1], p->type);
    offset += 9;
    check = p->len + p->addr[0] + p->addr[1] + p->type;
    while (num < p->len) {
        sprintf((char*)&dest[offset], "%02X", p->data[num]);
        check += p->data[num];
        offset += 2;
        num++;
    }
    check = ~check + 1;
    sprintf((char*)&dest[offset], "%02X", check);
    offset += 2;
    return offset;
}

RESULT_STATUS binfile_to_fexfile(const char* src, uint32_t base_add, const char* dest)
{
    FILE *src_file, *dest_file;
    uint16_t tmp;
    HEX_FORMAT hex_for;
    uint32_t low_addr = base_add, hign_addr = 0x8000;
    uint32_t base_hign = base_add & 0xffff0000;
    uint32_t low_addr_flag = 0, hign_addr_flag = 0;
    uint8_t buffer_bin[NUMBER_OF_ONE_LINE];
    uint32_t src_file_length;
    uint32_t src_file_quotient, cur_file_page = 0;
    uint8_t src_file_remainder;
    uint8_t tmp_data[8];
    uint8_t update_base_addr = 1;

    src_file = fopen(src, "rb");
    if (!src_file) {
        printf("error: open file(%s) failed!\r\n", src);
        return RES_BIN_FILE_NOT_EXIST;
    }
    dest_file = fopen(dest, "w");
    if (!dest_file) {
        printf("error: open file(%s) failed!\r\n", dest);
        return RES_HEX_FILE_PATH_ERROR;
    }
    fseek(src_file, 0, SEEK_END);
    src_file_length = ftell(src_file);
    fseek(src_file, 0, SEEK_SET);
    src_file_quotient = (uint32_t)(src_file_length / NUMBER_OF_ONE_LINE);
    src_file_remainder = (uint8_t)(src_file_length % NUMBER_OF_ONE_LINE);
    hex_for.data = buffer_bin;
    while (cur_file_page < src_file_quotient) {
        fread(buffer_bin, 1, NUMBER_OF_ONE_LINE, src_file);
        hex_for.len = NUMBER_OF_ONE_LINE;
        if (update_base_addr == 1) {
            update_base_addr = 0;
            hign_addr = low_addr & 0xffff0000;
            tmp_data[0] = (uint8_t)((hign_addr & 0xff000000) >> 24);
            tmp_data[1] = (uint8_t)((hign_addr & 0xff0000) >> 16);
            hex_for.type = 4;
            hex_for.data = tmp_data;
            hex_for.addr[0] = 0;
            hex_for.addr[1] = 0;
            hex_for.len = 2;
            tmp = bin_format_encode(buffer_hex, &hex_for);
            fwrite(buffer_hex, 1, tmp, dest_file);
            fprintf(dest_file, "\n");
            hex_for.data = buffer_bin;
            hex_for.len = NUMBER_OF_ONE_LINE;
            // continue;
        }
        hex_for.addr[0] = (uint8_t)((low_addr & 0xff00) >> 8);
        hex_for.addr[1] = (uint8_t)(low_addr & 0xff);
        hex_for.type = 0;
        tmp = bin_format_encode(buffer_hex, &hex_for);
        fwrite(buffer_hex, 1, tmp, dest_file);
        fprintf(dest_file, "\n");
        ;
        cur_file_page++;
        low_addr += NUMBER_OF_ONE_LINE;
        low_addr_flag = low_addr & 0x0000ffff;
        hign_addr_flag = low_addr & 0xffff0000;
        if ((low_addr_flag == 0x0000) && (hign_addr_flag > base_hign)) {
            update_base_addr = 1;
            hign_addr += 0x00010000;
        }
    }
    if (src_file_remainder != 0) {
        fread(buffer_bin, 1, src_file_remainder, src_file);
        hex_for.addr[0] = (uint8_t)((low_addr & 0xff00) >> 8);
        hex_for.addr[1] = (uint8_t)(low_addr & 0x00ff);
        hex_for.len = src_file_remainder;
        hex_for.type = 0;
        tmp = bin_format_encode(buffer_hex, &hex_for);
        fwrite(buffer_hex, 1, tmp, dest_file);
        fprintf(dest_file, "\n");
        ;
    }
    hex_for.addr[0] = 0;
    hex_for.addr[1] = 0;
    hex_for.type = 1;
    hex_for.len = 0;
    tmp = bin_format_encode(buffer_hex, &hex_for);
    fwrite(buffer_hex, 1, tmp, dest_file);
    fprintf(dest_file, "\n");
    ;
    fclose(src_file);
    fclose(dest_file);
    return RES_OK;
}

int get_sign_data(const char* filename, char* ch)
{
    ifstream infile(filename);
    string str;
    int offset = 0;
    if (!infile) {
        printf("error: open file(%s) failed!\r\n", filename);
        return ERR_OPENFILE;
    }

    for (size_t i = 0; i < 16; i++) {
        if (getline(infile, str)) {
            trim(str);
            write_str_to_memory(str, &ch[offset]);
            offset += 16;
        }
    }
    return 0;
}

int create_uart_sign_file()
{
    FILE* fw;
    const char* image_path = NULL;
    char* sign_file;
    char* bin2hex_sign_file;
    char* bin2hex_image_file;
    char image_sign[SIGN_SIZE] = {};

    /* 1.create bootchain.bin file and write bootchain */
    btr_boot_chain.magic = ESW_BOOTCHAIN_MAGIC;
    btr_boot_chain.num_entries = sign_count;
    fw = fopen(bootchain_bin_path, "wb");
    if (fw == NULL) {
        printf("error: open file(%s) failed! Please check if the path exists and has write permission.\r\n",
            bootchain_bin_path);
        return ERR_OPENFILE;
    }
    int length = sizeof(btr_boot_chain) / sizeof(int);
    for (int i = 0; i < length; i++) {
        fwrite(((int*)&btr_boot_chain) + i, sizeof(int), 1, fw);
    }
    for (size_t j = 0; j < sign_count; j++) {
        length = sizeof(boot_chain_entry[j]) / sizeof(int);
        for (int i = 0; i < length; i++) {
            fwrite(((int*)&boot_chain_entry[j]) + i, sizeof(int), 1, fw);
        }
    }
    fclose(fw);
    if (0 != binfile_to_fexfile(bootchain_bin_path, bootchain_link_addr, bootchain_hex_path)) {
        printf("error bin2hex\n");
        return -1;
    }

    /* 2.write boot_image signature and boot image into file */
    for (int j = 0; j < sign_count; j++) {
        sign_file = replace_file_name(sign_file_list[j], "bin");
        fw = fopen(sign_file, "wb");
        if (fw == NULL) {
            printf("error: open file(%s) failed!\r\n", sign_file);
            return ERR_OPENFILE;
        }
        get_sign_data(sign_file_list[j], image_sign);
        for (size_t i = 0; i < 256; i++) {
            fwrite(image_sign + i, 1, 1, fw);
        }
        fclose(fw);
        bin2hex_sign_file = sign_file_list[j];
        if (0 != binfile_to_fexfile(sign_file, uart_link_info[j].sign_link_addr, bin2hex_sign_file)) {
            printf("error bin2hex\n");
            return -1;
        }
        bin2hex_sign_file_list[j] = bin2hex_sign_file;
        remove(sign_file);
        bin2hex_image_file = replace_file_name(bin_file_list[j], "hex");
        if (0 != binfile_to_fexfile(bin_file_list[j], uart_link_info[j].image_link_addr, bin2hex_image_file)) {
            printf("error bin2hex\n");
            return -1;
        }
        bin2hex_image_file_list[j] = bin2hex_image_file;
    }

    /* 3.package hex file into boot_pkg */
    if (!memcmp(output_path, "default", 7)) {
        printf("output path:%s.\r\n", uart_boot_path);
    } else {
        uart_boot_path = output_path;
        printf("output path:%s.\r\n", output_path);
    }

    if (0 == access(uart_boot_path, 0)) {
        remove(uart_boot_path);
    }

    char buffer[64];
    ifstream cin_bootchain(bootchain_hex_path);
    ofstream cout(uart_boot_path, ios::app | ios::binary);

    while (cin_bootchain.getline(buffer, 64)) {
        cout << buffer << endl;
    }

    cin_bootchain.close();
    for (size_t i = 0; i < sign_count; i++) {
        ofstream cout(uart_boot_path, ios::app | ios::binary);
        ifstream cin_sign(bin2hex_sign_file_list[i]);

        while (cin_sign.getline(buffer, 64)) {
            cout << buffer << endl;
        }

        cin_sign.close();
        ifstream cin_image(bin2hex_image_file_list[i]);
        while (cin_image.getline(buffer, 64)) {
            cout << buffer << endl;
        }
        cin_image.close();
        cout.close();
    }

    remove(bootchain_bin_path);
    remove(bootchain_hex_path);
    for (size_t i = 0; i < sign_count; i++) {
        remove(bin2hex_image_file_list[i]);
    }

    printf("generate uart boot finish.\r\n");
    return 0;
}

int create_chief_sign_file()
{
    FILE* fr = NULL;
    FILE* fw = NULL;
    unsigned char tmp;
    int i = 0, image_size = 0, ret = 0;
    uint64_t len = 0;
    const char* image_path = NULL;
    char image_sign[SIGN_SIZE] = {};

    if (!memcmp(output_path, "default", 7)) {
        printf("output_path=%s.\r\n", chief_boot_path);
    } else {
        chief_boot_path = output_path;
        printf("output_path=%s.\r\n", output_path);
    }

    /* 1.create bootchain.bin file and write bootchain */
    btr_boot_chain.magic = ESW_BOOTCHAIN_MAGIC;
    btr_boot_chain.num_entries = sign_count;
    fw = fopen(chief_boot_path, "wb");
    if (fw == NULL) {
        printf("error: open file(%s) failed! Please check if the path exists and has write permission.\r\n",
                chief_boot_path);
        return ERR_OPENFILE;
    }

    int length = sizeof(btr_boot_chain) / sizeof(int);
    for (i = 0; i < length; i++) {
        fwrite(((int*)&btr_boot_chain) + i, sizeof(int), 1, fw);
    }
    for (size_t j = 0; j < sign_count; j++) {
        length = sizeof(boot_chain_entry[j]) / sizeof(int);
        for (i = 0; i < length; i++) {
            fwrite(((int*)&boot_chain_entry[j]) + i, sizeof(int), 1, fw);
        }
    }

    /* 2.write boot_image signature and boot image into file */
    for (int j = 0; j < sign_count; j++) {
        fseek(fw, (long)boot_chain_entry[j].offset, SEEK_SET);
        get_sign_data(sign_file_list[j], image_sign);
        /* write sign */
        for (i = 0; i < 256; i++) fwrite(image_sign + i, 1, 1, fw);
        /* write bin */
        image_path = bin_file_list[j];
        fr = fopen(image_path, "rb");
        if (fr == NULL) {
            printf("error: open file(%s) failed!\r\n", image_path);
            return ERR_OPENFILE;
        }
        fseek(fr, 0, SEEK_END);
        len = ftell(fr);
        fseek(fr, 0, SEEK_SET);
        printf("image%d size is %ld,sign_algorithm is %d,offset is 0x%lx\r\n", j, len, boot_chain_entry[j].sign_type,
               boot_chain_entry[j].offset);
        for (i = 0; i < len; i++) {
            fread(&tmp, 1, 1, fr);
            fwrite(&tmp, 1, 1, fw);
        }
    }
    fclose(fw);
    fclose(fr);

    return ret;
}

static void help_message()
{
    printf("\r\nEswin. (2024)\r\n");
    printf("nsign version %s.\r\n", NSIGN_VERSION);
    printf("nsign [config file path]\r\n");
    printf("      [--help]\r\n");
    printf("\r\n");
}

int execute_cmd()
{
    int ret = 0;
    if (cmd == CMD_UART_SIGN) {
        if ((ret = create_uart_sign_file())) {
            return ret;
        }
    } else if (cmd == CMD_CHIEF_SIGN) {
        if ((ret = create_chief_sign_file())) {
            return ret;
        }
    } else if (cmd == CMD_GENKEY) {
        if ((ret = create_rsa_key())) {
            printf("error:create rsa key failed.ret:%d", ret);
            return ret;
        }

        if ((ret = create_ecdsa_key())) {
            printf("error:create ecdsa key failed.ret:%d", ret);
            return ret;
        }
    } else
        return ERR_CMD;

    return 0;
}

static const char* error(int err)
{
    switch (err) {
        case ERR_FAILED: {
            return "Build signature failed.";
        } break;
        case ERR_GENERATE_KEY: {
            return "Generate Key pair failed.";
        } break;
        case ERR_ARGUMENT: {
            return "Invalid argument.";
        } break;
        case ERR_OPENFILE: {
            return "No such file or directory.";
        } break;
        case ERR_HASH: {
            return "hash failed.";
        } break;
        case ERR_IO: {
            return "IO Faulted.";
        } break;
        case ERR_READPRIVATEKEY: {
            return "Read private key failed.";
        } break;
        case ERR_ALLOC: {
            return "Cannot allocate memory.";
        } break;
        case ERR_PRIVATE_ENCRYPT: {
            return "Private encrypt failed.";
        } break;
        case ERR_GETECB: {
            return "Cannot read the ECB file.";
        } break;
        case ERR_WRITEPRIVATE: {
            return "Cannot write private key.";
        } break;
        case ERR_DECRYPT: {
            return "Decrypt failed.";
        } break;
        case ERR_FILESIZE: {
            return "File too short.";
        } break;
        case ERR_NUMBER: {
            return "Invalid number.";
        } break;
        case ERR_TIMEFORMAT: {
            return "Invalid time format.";
        }
        case ERR_GMTIME: {
            return "Call gettime failed.";
        } break;
        case ERR_NOERROR: {
            return "";
        } break;
        case ERR_CMD: {
            return "Unknown command.";
        } break;
        case ERR_BINARY: {
            return "No input file specified.";
        } break;
        case ERR_SIGNFILE: {
            return "No output file specified.";
        } break;
        case ERR_WRITEPUBLIC: {
            return "Write public failed.";
        } break;
        case ERR_CANCEL: {
            return "User Cancelled.";
        } break;
        case ERR_ARGSCOMBO: {
            return "Cannot export publicKey when the privateKey in an usbkey.";
        } break;
        case ERR_DEVNOTFOUND: {
            return "No usbkey could be found.";
        } break;
        case ERR_ARGPRIVATE: {
            return "Missing PrivateKey path.";
        } break;
        case ERR_SELECTFILE: {
            return "No such file in the usbkey.";
        } break;
        case ERR_MEM: {
            return "No memory available.";
        } break;
        case ERR_UNSUPPORTED: {
            return "This signature version isn't support this feature.";
        } break;
        case ERR_HEADER: {
            return "Invalid signature header.";
        } break;
        case ERR_INVALID_SIGN: {
            return "Signature self-check failed.";
        } break;
        case ERR_PARSEFILE: {
            return "Parse config file failed.";
        } break;
        case ERR_PERMISSION: {
            return "Don't have permissions.";
        } break;
    }
    return "Unknown error.";
}

static int copy_config_file(const char* conf_file)
{
    ifstream ifile(conf_file);
    ofstream ofile(config_file_path);

    if (!ifile.is_open()) {
        printf("error: open config file(%s)failed!\r\n", config_file_path);
        return ERR_OPENFILE;
    }

    if (!ofile.is_open()) {
        printf("error: open config file(%s)failed!\r\n", config_file_path);
        return ERR_OPENFILE;
    }

    string line;
    while (getline(ifile, line)) {
        ofile << line << endl;
    }

    ifile.close();
    ofile.close();

    return 0;
}

static int prepare()
{
    int ret = 0;
    char* current_path;
#ifdef WIN32
    char path_tmp[512] = {0};
    GetCurrentDirectory(sizeof(path_tmp), path_tmp);
    current_path = path_tmp;
#else
    current_path = getcwd(NULL, 0);
#endif

    if (0 != access(current_path, W_OK)) {
        printf("error: directory(%s) and subdirectory does not have writable permission!\r\n", current_path);
        return ERR_PERMISSION;
    }

    inter_hex_file_path = file_path_joint(inter_hex_file_path);
    bootchain_bin_path = file_path_joint(bootchain_bin_path);
    bootchain_hex_path = file_path_joint(bootchain_hex_path);
    uart_boot_path = file_path_joint(uart_boot_path);
    chief_boot_path = file_path_joint(chief_boot_path);

    ret = create_dir();
    if (ret) return ret;

    ret = encrypt_prepare();

    return ret;
}

int parse_config_file(const char* filename)
{
    ifstream infile(filename);
    string line, parameter, value;
    size_t pos;
    int left_bracket_cnt = 0;
    int right_bracket_cnt = 0;
    generator_signature* item = nullptr;

    int count, flag, ret = 0;
    char* cmd_name;
    if (!infile.is_open()) {
        printf("error:open config failed!\r\n");
        return ERR_OPENFILE;
    }

    while (getline(infile, line)) {
        if ((pos = line.find('{')) != string::npos) {
            left_bracket_cnt++;
            item = new generator_signature();
            if (item == nullptr) {
                printf("error: no memory!\n");
                infile.close();
                return ERR_ALLOC;
            }
            vec_sign.push_back(item);
            ndebug("new signature------------\r\n");
        } else if ((pos = line.find('}')) != string::npos) {
            right_bracket_cnt++;
            if (left_bracket_cnt != right_bracket_cnt) {
                printf("error: parse config file failed!\n");
                infile.close();
                return ERR_PARSEFILE;
            }
            sign_count = left_bracket_cnt;
            ndebug("sign_count=%d------------\r\n", sign_count);
        } else if ((pos = line.find('=')) != string::npos) {
            parameter = line.substr(0, pos);
            value = line.substr(pos + 1, line.length());
            trim(parameter);
            trim(value);

            if ("cmd" == parameter) {
                if (CMD_GENKEY_TEXT == value) {
                    cmd = CMD_GENKEY;
                } else if (CMD_UART_SIGN_TEXT == value) {
                    cmd = CMD_UART_SIGN;
                } else if (CMD_CHIEF_SIGN_TEXT == value) {
                    cmd = CMD_CHIEF_SIGN;
                } else {
                    printf("error: cmd error!\r\n");
                    infile.close();
                    return ERR_PARSEFILE;
                }
                ndebug("cmd=%d\n", cmd);
            } else if ("out" == parameter) {
                char* path = new char[value.length() + 1];
                strcpy(path, value.c_str());
                output_path = path;
            } else if ("bootchain_link_addr" == parameter) {
                bootchain_link_addr = stol(value.c_str(), 0, 16);
            } else {
                if (item == nullptr) {
                    printf("error: incorrect format of config file!\r\n");
                    infile.close();
                    return ERR_PARSEFILE;
                }
                ret = item->set_config_parameter(parameter, value);
                if (ret < 0) {
                    printf("error: incorrect (%s=%s)!\r\n", parameter.c_str(), value.c_str());
                    infile.close();
                    return ERR_PARSEFILE;
                }
            }
        }
    }

    infile.close();

    return 0;
}

int main(int argc, char** argv)
{
    generator_signature* generator = NULL;
    int ret = 0;

    try {
        printf("nsign version: %s-%s.\r\n", NSIGN_VERSION, ENCYPT_VERSION);
        ret = prepare();
        if (ret) {
            printf("error: prepare failed,ret:0x%x\r\n", ret);
            goto Failed;
        }

        config_file_path = file_path_joint(config_file_path);
        if (argv[1]) {
            if (!memcmp(argv[1], "--help", 6)) {
                help_message();
                return 0;
            } else {
                printf("config file path is:%s\r\n", argv[1]);
                ret = copy_config_file(argv[1]);
                if (ret) {
                    printf("error: copy config file failed,ret:0x%x\r\n", ret);
                    goto Failed;
                }
            }
        }

        ndebug("config_file_path:%s\n", config_file_path);

        ret = parse_config_file(config_file_path);
        if (ret) {
            printf("error: parse config file failed,ret:0x%x\r\n", ret);
            goto Failed;
        }
        if (cmd == CMD_GENKEY) {
            goto run;
        }

        ndebug("sign_count:%d output_path:%s\n", sign_count, output_path);
        if (!sign_count) {
            ret = ERR_PARSEFILE;
            printf("error: config file is invalid,ret:0x%x\r\n", ret);
            goto Failed;
        }

        for (int i = 0; i < sign_count; i++) {
            g_sign_idx = i;
            generator = vec_sign[i];
            generator->adjust_param((i == sign_count - 1));
            if (ret = generator->generate_sign_file()) {
                goto Failed;
            }
        }

run:
        ret = execute_cmd();
        if (ret) {
            goto Failed;
        }
        printf("\r\nSuccessful.\r\n");
        return 0;

Failed:
        printf("\r\nFailed: (%d:%s).\r\n", ret, error(ret));
        return -1;
    } catch (...) {
        try {
            throw;
        } catch (const exception& e) {
            std::cerr << "Caught an exception: " << typeid(e).name() << " with message " << e.what() << std::endl;
        } catch (...) {
            std::cerr << "Caught an unknown exception." << std::endl;
        }

        return -1;
    }
}
