#include "esw_build_signature.h"
#include <cassert>
#include <cerrno>
#include <unistd.h>
#include <fcntl.h>
#include <error.h>
#include <sys/mman.h>

static inline const char* str_payload_type(uint8_t type)
{
	switch (type) {
	case 0x0:
		return "PUBKEY_RSA";
	case 0x1:
		return "PUBKEY_ECC";
	case 0x10:
		return "DDR";
	case 0x20:
		return "D2D";
	case 0x30:
		return "BOOTLOADER";
	case 0x40:
		return "KERNEL";
	case 0x50:
		return "ROOTFS";
	case 0x60:
		return "APP";
	case 0x70:
		return "FIRMWARE";
	case 0x80:
		return "PATCH";
	case 0x90:
		return "LOADABLE_SRVC";
	default:
		return "UNKNONW";
	}
}


int main(int argc, char **argv) {
	int fd = open(argv[1], O_RDONLY);
	off_t size = lseek(fd, 0, SEEK_END);
	void *mapped = mmap(NULL, size, PROT_READ, MAP_SHARED, fd, 0);
	if (mapped == MAP_FAILED)
		error(1, errno, "failed to map firmware image");
	BTR_BOOT_CHAIN_T *header = (BTR_BOOT_CHAIN_T*)mapped;
	if (header->magic != 0x42575345)
		error(1, 0, "ESWB header not found");
	printf("Number of entries: %u\n", header->num_entries);
	for (uint32_t i = 0; i < header->num_entries; ++i) {
		BTR_BOOT_CHAIN_ENTRY_T *entry = &header->entries[i];
		printf("Entry %u: offset=0x%lx size=%lu (0x%lx) "
			"sign_type=%hhu key_index=%hhu "
			"payload_type=%hhu (%s) last=%hhu\n",
			i, entry->offset, entry->size, entry->size,
			entry->sign_type, entry->key_index,
			entry->payload_type, str_payload_type(entry->payload_type),
			entry->last_flag);
		BTR_BOOT_CHAIN_SIG_ST *pheader = (BTR_BOOT_CHAIN_SIG_ST*)(mapped + entry->offset);
		printf("  link_addr=0x%lx payload_off=0x%lx payload_size=%lu (0x%lx) "
			"load_addr=0x%lx entry_addr=0x%lx type=%hhu (%s) boot=%hhu\n",
			pheader->link_addr, pheader->payload_offset,
			pheader->payload_size, pheader->payload_size,
			pheader->load_addr, pheader->entry_addr,
			pheader->payload_type, str_payload_type(pheader->payload_type),
			pheader->boot_flags);
		char *filename = NULL;
		asprintf(&filename, "%s.%lx-%lx.bin", str_payload_type(entry->payload_type),
			entry->offset + 0x100, entry->offset + 0x100 + entry->size);
		FILE *fp = fopen(filename, "w");
		if (!fp)
			error(1, errno, "failed to open file %s for writing", filename);
		if (fwrite(mapped + entry->offset + 0x100, entry->size, 1, fp) != 1)
			error(1, 0, "fwrite: incomplete write");
		fclose(fp);
	}
}
