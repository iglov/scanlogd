/*
 * Copyright (c) 1998-2012 by Solar Designer
 * See LICENSE
 */

#define _BSD_SOURCE
#define _DEFAULT_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include "params.h"
#include "hash.h"

/**
 * Hash table internal item definition
 */
struct hash_item_list {
	unsigned int hash;
	struct hash_item *first;
	struct hash_item *last;
	unsigned int count;
};

/*
 * Hash table definition
 */
struct hash_table {
        struct hash_item_list *hash[HASH_SIZE];   /* Hash: pointers into the list */
        size_t item_data_size;
	size_t item_id_size;
	unsigned int total_count;
};

struct hash_table* hash_create_table(size_t id_size, size_t data_size)
{
	struct hash_table *ret = NULL;
	ret = (struct hash_table*) calloc(1, sizeof(struct hash_table));
	if(!ret)
	{
		fprintf(stderr, "hash_table calloc failed");
		return NULL;
	}

	ret->item_id_size = id_size;
	ret->item_data_size = data_size;

	return ret;
}

/*
 * Convert an IP address into a hash table index.
 */
static unsigned int hashfunc(uint8_t *data, uint8_t size)
{
	unsigned int value = 0;
	unsigned int hash = 0;
	for(int index = 0; index < size; index += sizeof(hash))
	{
		unsigned int tmp = 0;
		if((size - index) < sizeof(hash))
		{
			tmp = 0;
			for(int i = (size - index); i < size; i++)
			{
				tmp |= (data[i]) << (8 * (i % sizeof(hash)));
			}
		}
		else
			tmp = *((unsigned int*)&data[index]);

		value ^= tmp;
	}

	do {
		hash ^= value;
	} while ((value >>= HASH_LOG));

	debug_printf("hash value: %x\n", hash);

	return hash & (HASH_SIZE - 1);
}

struct hash_item* hash_find_id(struct hash_table *table, uint8_t* id)
{
	unsigned int hash;
	struct hash_item *current = NULL;

	/* Do we know this source address already? */

	hash = hashfunc(id, table->item_id_size);

	struct hash_item_list *list = table->hash[hash];
	if(!list) {
		list = (struct hash_item_list*) calloc(1, sizeof(struct hash_item_list));
		table->hash[hash] = list;
	}

        if ((current = table->hash[hash]->first)) {
	        do {
	                if (memcmp(id, current->id, table->item_id_size) == 0) break;
	        } while ((current = current->next));
	}

	debug_printf("hash_find_id: %x -> %p\n", *((uint32_t*)id), current);
	return current;
}

void hash_remove(struct hash_table *table, struct hash_item *current)
{
	if (current) {
                if (current->next) {
			if(current->prev)
	                        current->next->prev = current->prev;
			else {
				//update head
			        unsigned int hash = hashfunc(current->id, table->item_id_size);
			        table->hash[hash]->first = current->next;
			}
		}
		else {
			unsigned int hash = hashfunc(current->id, table->item_id_size);
			table->hash[hash]->last = current->prev;
		}

                if (current->prev)
			current->prev->next = current->next;

		table->total_count--;
        }
}

void hash_add(struct hash_table *table, struct hash_item *current)
{ //We add new entries always to the head of the list
	unsigned int hash = hashfunc(current->id, table->item_id_size);
	struct hash_item_list *items = table->hash[hash];
	
	if(items->first)
		items->first->prev = current;

	current->next = items->first;
	items->first = current;
	items->count++;
	table->total_count++;

	//TODO items lifetime
}

