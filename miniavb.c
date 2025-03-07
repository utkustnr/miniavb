#include <endian.h>
#include <openssl/sha.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
  char magic[5];
  uint32_t version_major;
  uint32_t version_minor;
  uint64_t auth_size;
  uint64_t aux_size;
  uint32_t algorithm;
  uint64_t pubkey_offset;
  uint64_t pubkey_size;
  uint64_t descriptors_offset;
  uint64_t descriptors_size;
  uint64_t rollback_index;
  uint32_t flags;
  uint32_t rollback_location;
  char release_str[48];
} AvbVBMetaHeader;

typedef struct {
  char *key;
  char *val;
} Property;

const char *ALGORITHMS[] = {
    [1] = "SHA256_RSA2048", [2] = "SHA256_RSA4096", [3] = "SHA256_RSA8192",
    [4] = "SHA512_RSA2048", [5] = "SHA512_RSA4096", [6] = "SHA512_RSA8192"};

static void parse_header(const uint8_t *data, AvbVBMetaHeader *hdr) {
  memcpy(hdr->magic, data, 4);
  hdr->magic[4] = '\0';

  hdr->version_major = be32toh(*(uint32_t *)(data + 4));
  hdr->version_minor = be32toh(*(uint32_t *)(data + 8));
  hdr->auth_size = be64toh(*(uint64_t *)(data + 12));
  hdr->aux_size = be64toh(*(uint64_t *)(data + 20));
  hdr->algorithm = be32toh(*(uint32_t *)(data + 28));
  hdr->pubkey_offset = be64toh(*(uint64_t *)(data + 64));
  hdr->pubkey_size = be64toh(*(uint64_t *)(data + 72));
  hdr->descriptors_offset = be64toh(*(uint64_t *)(data + 96));
  hdr->descriptors_size = be64toh(*(uint64_t *)(data + 104));
  hdr->rollback_index = be64toh(*(uint64_t *)(data + 112));
  hdr->flags = be32toh(*(uint32_t *)(data + 120));
  hdr->rollback_location = be32toh(*(uint32_t *)(data + 124));

  memcpy(hdr->release_str, data + 128, 47);
  hdr->release_str[47] = '\0';
  char *null_pos = memchr(hdr->release_str, 0, 47);
  if (null_pos)
    *null_pos = '\0';
}

static int parse_descriptors(const uint8_t *data, size_t len, Property **props,
                             size_t *count) {
  size_t pos = 0;
  *count = 0;
  *props = NULL;

  while (pos + 16 <= len) {
    uint64_t tag = be64toh(*(uint64_t *)(data + pos));
    uint64_t size = be64toh(*(uint64_t *)(data + pos + 8));
    size_t pos_before_header = pos;
    pos += 16; // Skip header

    if (tag != 0) {
      pos = pos_before_header + 16 + size; // Full descriptor size
      continue;
    }

    if (pos + 16 > len)
      break;
    uint64_t key_size = be64toh(*(uint64_t *)(data + pos));
    uint64_t val_size = be64toh(*(uint64_t *)(data + pos + 8));
    pos += 16;

    if (pos + key_size + 1 + val_size > len) {
      pos = pos_before_header + 16 + size; // Advance despite error
      continue;
    }

    Property p;
    p.key = malloc(key_size + 1);
    memcpy(p.key, data + pos, key_size);
    p.key[key_size] = '\0';
    pos += key_size + 1;

    p.val = malloc(val_size + 1);
    memcpy(p.val, data + pos, val_size);
    p.val[val_size] = '\0';
    pos += val_size;

    // Advance to end of descriptor (including padding)
    pos = pos_before_header + 16 + size;

    *props = realloc(*props, (*count + 1) * sizeof(Property));
    (*props)[(*count)++] = p;
  }
  return 0;
}

int main(int argc, char **argv) {
  if (argc != 2) {
    fprintf(stderr, "Usage: %s <path/to/vbmeta.img> OR <path/to/block>\n", argv[0]);
    return 1;
  }

  FILE *f = fopen(argv[1], "rb");
  if (!f) {
    perror("fopen");
    return 1;
  }

  uint8_t header_buf[256];
  if (fread(header_buf, 1, 256, f) != 256) {
    perror("fread header");
    fclose(f);
    return 1;
  }

  AvbVBMetaHeader hdr;
  parse_header(header_buf, &hdr);

  fseek(f, 256 + hdr.auth_size, SEEK_SET);
  uint8_t *aux_data = malloc(hdr.aux_size);
  if (!aux_data || fread(aux_data, 1, hdr.aux_size, f) != hdr.aux_size) {
    perror("Reading aux data");
    free(aux_data);
    fclose(f);
    return 1;
  }

  uint8_t *pubkey = aux_data + hdr.pubkey_offset;
  uint8_t sha1[SHA_DIGEST_LENGTH];
  SHA1(pubkey, hdr.pubkey_size, sha1);

  Property *props = NULL;
  size_t prop_count = 0;
  if (hdr.descriptors_size > 0) {
    parse_descriptors(aux_data + hdr.descriptors_offset, hdr.descriptors_size,
                      &props, &prop_count);
  }

  printf("Minimum libavb version:   %u.%u\n", hdr.version_major,
         hdr.version_minor);
  printf("Header Block:             256 bytes\n");
  printf("Authentication Block:     %lu bytes\n", hdr.auth_size);
  printf("Auxiliary Block:          %lu bytes\n", hdr.aux_size);
  printf("Total Block Size:         %lu bytes\n",
         256 + hdr.auth_size + hdr.aux_size);

  printf("Public key (sha1):        ");
  for (int i = 0; i < SHA_DIGEST_LENGTH; i++)
    printf("%02x", sha1[i]);
  printf("\n");

  printf("Algorithm:                %s\n",
         (hdr.algorithm >= 1 && hdr.algorithm <= 6) ? ALGORITHMS[hdr.algorithm]
                                                    : "UNKNOWN");
  printf("Rollback Index:           %lu\n", hdr.rollback_index);
  printf("Flags:                    %u\n", hdr.flags);
  printf("Rollback Index Location:  %u\n", hdr.rollback_location);
  printf("Release String:           %s\n", hdr.release_str);

  for (size_t i = 0; i < prop_count; i++) {
    printf("Props: %s -> '%s'\n", props[i].key, props[i].val);
    free(props[i].key);
    free(props[i].val);
  }

  free(props);
  free(aux_data);
  fclose(f);
  return 0;
}
