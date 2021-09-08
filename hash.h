#ifndef SCANLOGD_HASH_H
#define SCANLOGD_HASH_H

#include <stdint.h>

struct hash_item {
	uint8_t *id;
	struct hash_item *next;
	struct hash_item *prev;
	uint8_t *data;
};

struct hash_table;

struct hash_table* hash_create_table(size_t id_size, size_t data_size);
struct hash_item* hash_find_id(struct hash_table *table, uint8_t* id);
void hash_add(struct hash_table *table, struct hash_item *current);
void hash_remove(struct hash_table *table, struct hash_item *current);

#endif
