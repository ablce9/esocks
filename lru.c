/*
 * Use of this source code is governed by a
 * license that can be found in the LICENSE file.
 *
 */

#include "def.h"
#include "lru.h"
#include "log.h"

static lru_node_t* lru_tail = NULL; // The tail of node
static lru_node_t* get_node(lru_node_t** node_pptr, void* key, lru_cmp_func* func);
static int cmp_func(const char* a, const char* b);

static int
cmp_func(const char* a, const char* b)
{
  return a && b ? strcmp(a, b) : 1;
}

const char*
lru_get_key(lru_node_t* p)
{
  if (p != NULL)
    return p->key;

  return NULL;
};

lru_node_t*
lru_init(void)
{
  time_t now = time(&now);
  lru_node_t* node_ptr;

  node_ptr = calloc(1, sizeof(struct lru_node_s));

  if (node_ptr != NULL) {
    node_ptr->next = NULL;
    node_ptr->prev = NULL;
    node_ptr->key = NULL;
  }

  return node_ptr;
}

void
lru_insert_left(lru_node_t** node, const char* key, void* data, size_t s)
{
  lru_node_t *ptr = *node;
  lru_node_t* next;
  time_t now = time(&now);

  ASSERT(ptr);

  next = calloc(1, sizeof(struct lru_node_s));
  ASSERT(next);

  ptr->next = next;
  next->prev = ptr;
  next->next = NULL;
  next->start = now;
  memcpy(&next->payload_ptr, &data, s);
  next->key = key;
  *node = next;

  if (!lru_tail) {
    log_i("lru_insert_left(): set tail to \"%s\"", next->key);
    lru_tail = next;
  }
}

lru_node_t*
lru_get_tail()
{
  return lru_tail;
}

lru_node_t*
lru_get_node(lru_node_t** node_pptr, void* key, lru_cmp_func* func)
{
  lru_node_t* ptr = *node_pptr;

  if (ptr != NULL && lru_tail)
    return !(ptr->key) ? NULL :  get_node(node_pptr, key, func);

  return NULL;
}

static lru_node_t*
get_node(lru_node_t** node_pptr, void* key, lru_cmp_func* func)
{
  lru_node_t* ptr = *node_pptr;
  lru_node_t* head = *node_pptr;
  lru_node_t* tail = lru_tail;
  time_t now = time(&now);

  while (ptr != NULL) {
    if (func(key, ptr->key) == 0) {

      if (func(key, head->key) == 0)
	; // Do nothing here

      else if (func(key, tail->key) == 0) {
	log_d(DEBUG, "get_node(): hits tail key \"%s\"", (char*)tail->key);

	// Detach a tail from a current list and assign a new tail.
	tail->next = NULL;
	tail->prev = NULL;
	lru_tail = tail->next == NULL ? ptr : tail->next;

	memcpy(&ptr->payload_ptr, &tail->payload_ptr, sizeof(*tail->payload_ptr));
	ptr->prev = tail->next == NULL ? NULL : head;
	ptr->next = NULL;

      } else {
	log_d(DEBUG, "get_node(): hits the middle of node key \"%s\"", ptr->key);

	ASSERT(ptr->prev != NULL);
	ASSERT(ptr->next != NULL);

	ptr->next->prev = ptr->prev;
	ptr->prev->next = ptr->next;

	ptr->next = NULL;
	ptr->prev = head;

	memcpy(ptr->payload_ptr, ptr->payload_ptr, sizeof(*ptr->payload_ptr));
	head->next = ptr;
      }

      ptr->start = now;
      *node_pptr = ptr;
      return ptr;
    }

    if (func(tail->key, ptr->key) == 0)
      break;

    ptr = ptr->prev;

  }
  return NULL;
}

void
lru_purge_all(lru_node_t** node_pptr)
{
  lru_node_t* ptr = *node_pptr;

  if (ptr != NULL) {
    log_d(DEBUG, "lru_purge_all(): remove \"%s\"", !ptr->key ? "myself" : ptr->key);
    ptr->key = NULL;
    ptr->payload_ptr = NULL;
    ptr->start = 0;

    lru_purge_all(&ptr->prev);
    free(ptr);
  }

  lru_tail = NULL;

}

void*
lru_get_oldest_payload(lru_node_t** node_pptr, long timeout)
{
  lru_node_t* tail = lru_tail;
  lru_node_t* current = *node_pptr;
  void *payload = NULL;
  time_t now = time(&now);

  while (tail)
    {
      if (now - tail->start >= timeout && tail->key) {
	log_i("lru_get_oldest_payload(): timeout event occurred and freeing \"%s\"",
	      tail->key);

	if (!cmp_func(tail->key, current->key)) {
	  log_d(DEBUG, "lru_get_oldest_payload(): pop tail \"%s\"",
		tail->key == NULL ? "myself" : tail->key);
	  lru_tail = tail->next;
	  tail->key = NULL;
	  payload = tail->payload_ptr;
	  tail->payload_ptr = NULL;
	  tail->start = 0;
	  tail = NULL;
	  free(tail);
	  *node_pptr = current;
	  break;
	}

	log_d(DEBUG, "lru_get_oldest_payload(): pop \"%s\"", tail->key);
	lru_tail = tail->next;
	tail->next ? tail->next->prev = NULL : NULL;
	tail->key = NULL;
	payload = tail->payload_ptr;
	tail->payload_ptr = NULL;
	tail->start = 0;
	tail = NULL;
	free(tail);
	*node_pptr = current;
	break;
      }

      break;
    }

  return payload;
}

void
lru_remove_oldest(lru_node_t** node_pptr, long timeout)
{
  lru_node_t* tail = lru_tail;
  lru_node_t* next = tail->next;
  lru_node_t* current = *node_pptr;
  time_t now = time(&now);

  for (;;)
    {
      if (now - tail->start >= timeout && tail) {

	if (tail->key == current->key) {
	  log_d(DEBUG, "pop \"%s\"", tail->key == NULL ? "myself" : tail->key);
	  lru_tail = tail->next;
	  tail->key = NULL;
	  tail->payload_ptr = NULL;
	  tail->start = 0;
	  tail = NULL;
	  free(tail);
	  break;
	}

	log_d(DEBUG, "pop \"%s\"", tail->key);
	next->prev = NULL;
	lru_tail = tail->next;
	tail->key = NULL;
	tail->payload_ptr = NULL;
	tail->start = 0;
	tail = NULL;
	free(tail);
	break;
      }

      break;
    }
}