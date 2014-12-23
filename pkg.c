
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "tools.h"
#include "paged_file.h"
#include "pkg.h"
#include "keys.h"

Key *keys = NULL;
int num_keys = 0;

static int
pkg_debug_decrypt (PagedFile *f, PagedFileCryptOperation operation,
    u8 *ptr, u32 len, void *user_data)
{
  u64 *crypt_offset = user_data;
  u8 key[0x40];
  u8 bfr[0x14];
  u64 i;
  s64 seek;

  if (operation == PAGED_FILE_CRYPT_DECRYPT ||
      operation == PAGED_FILE_CRYPT_ENCRYPT) {
    memset(key, 0, 0x40);
    memcpy(key, f->key, 8);
    memcpy(key + 0x08, f->key, 8);
    memcpy(key + 0x10, f->key + 8, 8);
    memcpy(key + 0x18, f->key + 8, 8);
    seek = (signed) ((f->page_pos + f->pos) - *crypt_offset) / 0x10;
    if (seek > 0)
      wbe64(key + 0x38, be64(key + 0x38) + seek);

    for (i = 0; i < len; i++) {
      if (i % 16 == 0) {
        sha1(key, 0x40, bfr);
        wbe64(key + 0x38, be64(key + 0x38) + 1);
      }
      ptr[i] ^= bfr[i & 0xf];
    }
  }

  return TRUE;
}

static int
pkg_open (const char *filename, PagedFile *in,
    PKG_HEADER *header, PKG_FILE_HEADER **files)
{
  Key *gpkg_key;
  u32 i;

  if (!paged_file_open (in, filename, TRUE))
    die ("Unable to open package file\n");

  paged_file_read (in, header, sizeof(PKG_HEADER));
  PKG_HEADER_FROM_BE (*header);

  if (header->magic != 0x7f504b47)
    goto error;

  paged_file_seek (in, header->data_offset);
  if (header->pkg_type == 0x80000001) {
    if (keys == NULL) {
      keys = keys_load (&num_keys);
      if (keys == NULL)
        die ("Unable to load necessary keys from\n");
    }

    gpkg_key = keys_find_by_name (keys, num_keys, "Game PKG");
    paged_file_crypt (in, gpkg_key->key, header->k_licensee,
        PAGED_FILE_CRYPT_AES_128_CTR, NULL, NULL);
  } else {
    paged_file_crypt (in, header->digest, header->k_licensee,
        PAGED_FILE_CRYPT_CUSTOM, pkg_debug_decrypt, &header->data_offset);
  }

  *files = malloc (header->item_count * sizeof(PKG_FILE_HEADER));
  paged_file_read (in, *files, header->item_count * sizeof(PKG_FILE_HEADER));

  for (i = 0; i < header->item_count; i++) {
    PKG_FILE_HEADER_FROM_BE ((*files)[i]);
  }

  return TRUE;

 error:
  if (*files)
    free (*files);
  *files = NULL;

  paged_file_close (in);

  return FALSE;
}

int
pkg_list (const char *filename)
{
  PagedFile in = {0};
  PKG_HEADER header;
  PKG_FILE_HEADER *files = NULL;
  char *pkg_file_path = NULL;
  u32 i;

  if (!pkg_open (filename, &in, &header, &files))
    die ("Unable to open pkg file\n");

  printf ("PKG type : %X\n", header.pkg_type);
  printf ("Item count : %d\n", header.item_count);
  printf ("Content ID : %s\n", header.contentid);
  printf ("Digest : ");
  print_hash (header.digest, 0x10);
  printf ("\nKLicensee : ");
  print_hash (header.k_licensee, 0x10);
  printf ("\n\n");

  for (i = 0; i < header.item_count; i++) {
    paged_file_seek (&in, files[i].filename_offset + header.data_offset);
    pkg_file_path = malloc (files[i].filename_size + 1);
    paged_file_read (&in, pkg_file_path, files[i].filename_size);
    pkg_file_path[files[i].filename_size] = 0;
    printf ("File %d : %s\n\tSize : %llu\n\tFlags : %X\n", i, pkg_file_path,
        files[i].data_size, files[i].flags);
    free (pkg_file_path);
  }

  paged_file_close (&in);
  return TRUE;

}

int
pkg_unpack (const char *filename, const char *destination)
{
  PagedFile in = {0};
  PagedFile out = {0};
  char out_dir[1024];
  char *pkg_file_path = NULL;
  char path[1024];
  PKG_HEADER header;
  PKG_FILE_HEADER *files = NULL;
  int ret = TRUE;
  u32 i;

  if (!pkg_open (filename, &in, &header, &files))
    die ("Unable to open pkg file\n");

  if (destination == NULL) {
    strncpy (out_dir, header.contentid, sizeof(out_dir));
  } else {
    strncpy (out_dir, destination, sizeof(out_dir));
  }
  mkdir_recursive (out_dir);

  for (i = 0; i < header.item_count; i++) {
    int j;

    paged_file_seek (&in, files[i].filename_offset + header.data_offset);
    pkg_file_path = malloc (files[i].filename_size + 1);
    paged_file_read (&in, pkg_file_path, files[i].filename_size);
    pkg_file_path[files[i].filename_size] = 0;

    snprintf (path, sizeof(path), "%s/%s", out_dir, pkg_file_path);
    if ((files[i].flags & 0xFF) == 4) {
      mkdir_recursive (path);
    } else {
      j = strlen (path);
      while (j > 0 && path[j] != '/') j--;
      if (j > 0) {
        path[j] = 0;
        mkdir_recursive (path);
        path[j] = '/';
      }
      paged_file_seek (&in, files[i].data_offset + header.data_offset);
      printf ("Opening file %s\n", path);
      if (!paged_file_open (&out, path, FALSE))
        die ("Unable to open output file\n");
      paged_file_splice (&out, &in, files[i].data_size);
      paged_file_close (&out);
    }
  }

  paged_file_close (&in);
  paged_file_close (&out);
  return ret;
}

int
pkg_extract_sig (const char *filename)
{
  PagedFile in = {0};
  char *pkg_file_path = NULL;
  PKG_HEADER header;
  PKG_FILE_HEADER *files = NULL;
  char *file = NULL;
  char *ext = NULL;
  u8 signature[0x28];
  int ret = TRUE;
  u32 i;

  if (!pkg_open (filename, &in, &header, &files))
    die ("Unable to open pkg file\n");

  printf ("Checking : %s\n", filename);

  for (i = 0; i < header.item_count; i++) {
    paged_file_seek (&in, files[i].filename_offset + header.data_offset);
    pkg_file_path = malloc (files[i].filename_size + 1);
    paged_file_read (&in, pkg_file_path, files[i].filename_size);
    pkg_file_path[files[i].filename_size] = 0;

    if ((files[i].flags & 0xFF) != 4) {
      int j;
      j = strlen (pkg_file_path);
      while (j > 0 && pkg_file_path[j] != '/') j--;
      file = pkg_file_path + j + 1;
      j = strlen (pkg_file_path);
      while (j > 0 && pkg_file_path[j] != '.') j--;
      ext = pkg_file_path + j + 1;
      if (strcmp (file, "EBOOT.BIN") != 0 &&
          strcmp (ext, "self") != 0 &&
          strcmp (ext, "SELF") != 0 &&
          strcmp (ext, "sprx") != 0)
        continue;
      printf ("Found file : %s\n", pkg_file_path);

      paged_file_seek (&in, files[i].data_offset + header.data_offset + files[i].data_size - 0x30);
      paged_file_read (&in, signature, 0x28);
      printf ("Signature : \n");
      hex_dump (signature, 0x28);
    }
  }

  paged_file_close (&in);
  return ret;
}

typedef struct
{
  uint32_t magic; /* PSF */
  uint32_t version; /* 1.1 */
  uint32_t name_table_offset;
  uint32_t data_table_offset;
  uint32_t num_entries;
} SFOHeader;
#define SFO_HEADER_FROM_LE(h)                                     \
  h.magic = FROM_LE (32, h.magic);                                \
  h.version = FROM_LE (32, h.version);                            \
  h.name_table_offset = FROM_LE (32, h.name_table_offset);        \
  h.data_table_offset = FROM_LE (32, h.data_table_offset);        \
  h.num_entries = FROM_LE (32, h.num_entries);

typedef struct
{
  uint16_t name_offset;
  uint16_t type;
  uint32_t length;
  uint32_t total_size;
  uint32_t data_offset;
} SFOEntry;
#define SFO_ENTRY_FROM_LE(h)                               \
  h.name_offset = FROM_LE (16, h.name_offset);             \
  h.type = FROM_LE (16, h.type);                           \
  h.length = FROM_LE (32, h.length);                       \
  h.total_size = FROM_LE (32, h.total_size);               \
  h.data_offset = FROM_LE (32, h.data_offset);

void
pkg_print_params (const char *filename)
{
  PagedFile in = {0};
  char *pkg_file_path = NULL;
  PKG_HEADER header;
  PKG_FILE_HEADER *files = NULL;
  SFOHeader h;
  SFOEntry *entries = NULL;
  char *names = NULL;
  char *result = NULL;
  uint32_t name_table_len;
  u32 i, j;

  if (!pkg_open (filename, &in, &header, &files))
    die ("Unable to open pkg file\n");

  for (i = 0; i < header.item_count; i++) {
    paged_file_seek (&in, files[i].filename_offset + header.data_offset);
    pkg_file_path = malloc (files[i].filename_size + 1);
    paged_file_read (&in, pkg_file_path, files[i].filename_size);
    pkg_file_path[files[i].filename_size] = 0;

    if (strcmp (pkg_file_path, "PARAM.SFO") == 0) {
      paged_file_seek (&in, files[i].data_offset + header.data_offset);

      paged_file_read (&in, &h, sizeof(SFOHeader));
      SFO_HEADER_FROM_LE (h);

      if (h.magic != 0x46535000 || h.version != 0x101)
        continue;

      entries = calloc (h.num_entries, sizeof(SFOEntry));
      paged_file_read (&in, entries, sizeof(SFOEntry)* h.num_entries);

      name_table_len = h.data_table_offset - h.name_table_offset;
      names = malloc (name_table_len);
      paged_file_read (&in, names, name_table_len);

      for (j = 0; j < h.num_entries; j++) {
        SFO_ENTRY_FROM_LE (entries[j]);
        if (entries[j].type == 0x204) {
          result = malloc (entries[j].total_size);
          paged_file_seek (&in, files[i].data_offset + header.data_offset +
              h.data_table_offset + entries[j].data_offset);
          paged_file_read (&in, result, entries[j].total_size);
          printf ("%s : %s\n", names + entries[j].name_offset, result);
          free (result);
        }
      }
      free (entries);
      free (names);
      break;
    }
  }

  paged_file_close (&in);
}
