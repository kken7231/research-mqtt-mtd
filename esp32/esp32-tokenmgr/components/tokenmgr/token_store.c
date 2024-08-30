#include "tokenmgr.h"

static const char *TAG = "tokenmgr_token_store";

token_store_entry_t *token_store_entry_init(const char *topic, bool access_type_is_pub) {
	token_store_entry_t *entry = (token_store_entry_t *)malloc(sizeof(token_store_entry_t));
	if (!entry) {
		ESP_LOGE(TAG, "Failed to allocate memory for a new token store");
		return NULL;
	}
	entry->topic = topic;
	entry->access_type_is_pub = access_type_is_pub;

	entry->all_random_data = NULL;
	entry->cur_random_data = NULL;
	entry->token_count = 0;
	entry->cur_token_idx = 0;

	entry->payload_aead_type = PAYLOAD_AEAD_NONE;
	entry->payload_encryption_key = NULL;

	entry->prev = NULL;
	entry->next = NULL;
	return entry;
}

void token_store_append(token_store_t *store, token_store_entry_t *new_entry) {
	if (!store->head) {
		store->head = new_entry;
		store->tail = new_entry;
	} else {
		new_entry->prev = store->tail;
		store->tail = new_entry;
	}
}

token_store_entry_t *token_store_search(token_store_t *store, const char *topic, bool access_type_is_pub) {
	token_store_entry_t *entry = store->head;
	while (entry) {
		if (((strcmp(topic, entry->topic) == 0) && (access_type_is_pub == entry->access_type_is_pub))) {
			break;
		}
		entry = entry->next;
	}
	return entry;
}
