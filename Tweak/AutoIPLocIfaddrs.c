#include "AutoIPLocIfaddrs.h"

#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>

typedef struct AutoIPLocIfaddrsAllocation {
    struct AutoIPLocIfaddrsAllocation *registry_next;
    struct ifaddrs *original_head;
    size_t node_count;
    struct ifaddrs nodes[];
} AutoIPLocIfaddrsAllocation;

static pthread_mutex_t g_registry_lock = PTHREAD_MUTEX_INITIALIZER;
static AutoIPLocIfaddrsAllocation *g_registry_head = NULL;

struct ifaddrs *AutoIPLocIfaddrsCloneAndRegister(
    struct ifaddrs *original_head,
    const struct ifaddrs *const *selected_nodes,
    size_t selected_count
) {
    if (!original_head || !selected_nodes || selected_count == 0) {
        return NULL;
    }

    if (selected_count > (SIZE_MAX - sizeof(AutoIPLocIfaddrsAllocation)) /
                             sizeof(struct ifaddrs)) {
        return NULL;
    }

    for (size_t i = 0; i < selected_count; ++i) {
        if (!selected_nodes[i]) return NULL;
    }

    const size_t allocation_size =
        sizeof(AutoIPLocIfaddrsAllocation) + selected_count * sizeof(struct ifaddrs);
    AutoIPLocIfaddrsAllocation *allocation = calloc(1, allocation_size);
    if (!allocation) return NULL;

    allocation->original_head = original_head;
    allocation->node_count = selected_count;

    for (size_t i = 0; i < selected_count; ++i) {
        allocation->nodes[i] = *selected_nodes[i];
        allocation->nodes[i].ifa_next =
            (i + 1 < selected_count) ? &allocation->nodes[i + 1] : NULL;
    }

    if (pthread_mutex_lock(&g_registry_lock) != 0) {
        free(allocation);
        return NULL;
    }
    allocation->registry_next = g_registry_head;
    g_registry_head = allocation;
    pthread_mutex_unlock(&g_registry_lock);

    return &allocation->nodes[0];
}

int AutoIPLocIfaddrsReleaseRegistered(
    struct ifaddrs *registered_head,
    AutoIPLocIfaddrsOriginalFree original_free
) {
    if (!registered_head || !original_free) return 0;

    AutoIPLocIfaddrsAllocation *matched = NULL;
    if (pthread_mutex_lock(&g_registry_lock) != 0) return 0;

    AutoIPLocIfaddrsAllocation **cursor = &g_registry_head;
    while (*cursor) {
        if (&(*cursor)->nodes[0] == registered_head) {
            matched = *cursor;
            *cursor = matched->registry_next;
            break;
        }
        cursor = &(*cursor)->registry_next;
    }
    pthread_mutex_unlock(&g_registry_lock);

    if (!matched) return 0;

    struct ifaddrs *original_head = matched->original_head;
    matched->original_head = NULL;
    original_free(original_head);
    free(matched);
    return 1;
}
