#include <stdio.h>
#include <stdlib.h>
#include "tools.h"
#include "common.h"

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

static void
print_params (const char *filename)
{
  FILE *in = NULL;
  SFOHeader h;
  SFOEntry *entries = NULL;
  char *names = NULL;
  char *result = NULL;
  uint32_t name_table_len;
  u32 j;

  in = fopen (filename, "rb");
  if (!in)
    die ("Unable to open pkg file\n");

  fread (&h, sizeof(SFOHeader), 1, in);
  SFO_HEADER_FROM_LE (h);

  if (h.magic != 0x46535000 || h.version != 0x101)
    die ("not a PARAM.sfo");

  entries = calloc (h.num_entries, sizeof(SFOEntry));
  fread (entries, sizeof(SFOEntry)* h.num_entries, 1, in);

  name_table_len = h.data_table_offset - h.name_table_offset;
  names = malloc (name_table_len);
  fread (names, name_table_len, 1, in);
  for (j = 0; j < h.num_entries; j++) {
    SFO_ENTRY_FROM_LE (entries[j]);
    if (entries[j].type == 0x204) {
      result = malloc (entries[j].total_size);
      fseek (in, h.data_table_offset + entries[j].data_offset, SEEK_SET);
      fread (result, entries[j].total_size, 1, in);
      printf ("%s : %s\n", names + entries[j].name_offset, result);
      free (result);
    }
  }
  free (entries);
  free (names);
  fclose (in);
}
