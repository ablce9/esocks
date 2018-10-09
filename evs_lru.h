#ifndef EVS_LRU_H
#define EVS_LRU_H

#include <sys/time.h>
#include <sys/socket.h>

typedef int lru_cmp_func(const void*, const void*);
typedef int lru_get_key_func(void*);

typedef struct payload_s payload_t;

struct payload_s {
  const void* key;
  void*       val;
};

typedef struct lru_node_s lru_node_t;

struct lru_node_s {
  time_t      start;
  const char* key;
  void*       payload_ptr;
  lru_node_t* next;
  lru_node_t* prev;
};

const char* lru_get_key(lru_node_t* p);
void lru_purge_all(lru_node_t** node_pptr);
void lru_insert_left(lru_node_t** node_pptr, const char* key, void* data_p, size_t s);
/* wait for x nanosecond */
void lru_remove_oldest(lru_node_t** node_pptr, long timeout);
lru_node_t* lru_init(void);
lru_node_t* lru_get_node(lru_node_t** node, void* key, lru_cmp_func*);
lru_node_t*lru_get_tail(void);
void* lru_get_oldest_payload(lru_node_t** node_pptr, long timeout);

#endif
