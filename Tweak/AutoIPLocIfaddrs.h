#ifndef AUTOIPLOC_IFADDRS_H
#define AUTOIPLOC_IFADDRS_H

#include <ifaddrs.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef void (*AutoIPLocIfaddrsOriginalFree)(struct ifaddrs *);

/*
 * Copies only the caller-selected node structures into a registered allocation.
 * Pointer-valued fields remain borrowed from original_head and therefore stay
 * valid until AutoIPLocIfaddrsReleaseRegistered invokes original_free.
 *
 * Selection policy is deliberately outside this module.
 */
struct ifaddrs *AutoIPLocIfaddrsCloneAndRegister(
    struct ifaddrs *original_head,
    const struct ifaddrs *const *selected_nodes,
    size_t selected_count
);

/* Returns 1 and releases the registered original+clone, or 0 if not registered. */
int AutoIPLocIfaddrsReleaseRegistered(
    struct ifaddrs *registered_head,
    AutoIPLocIfaddrsOriginalFree original_free
);

#ifdef __cplusplus
}
#endif

#endif
