#include "AutoIPLocIfaddrs.h"

#include <assert.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define THREAD_COUNT 8
#define ITERATIONS_PER_THREAD 1000

static atomic_int g_original_free_calls = 0;

static char *copy_string(const char *value) {
    const size_t length = strlen(value) + 1;
    char *copy = malloc(length);
    assert(copy != NULL);
    memcpy(copy, value, length);
    return copy;
}

static struct ifaddrs *make_chain(size_t count) {
    struct ifaddrs *head = NULL;
    struct ifaddrs **tail = &head;

    for (size_t i = 0; i < count; ++i) {
        struct ifaddrs *node = calloc(1, sizeof(*node));
        assert(node != NULL);
        char name[32];
        (void)snprintf(name, sizeof(name), "test%zu", i);
        node->ifa_name = copy_string(name);
        node->ifa_flags = (unsigned int)(100 + i);
        *tail = node;
        tail = &node->ifa_next;
    }
    return head;
}

static void free_original_chain(struct ifaddrs *head) {
    atomic_fetch_add(&g_original_free_calls, 1);
    while (head) {
        struct ifaddrs *next = head->ifa_next;
        free(head->ifa_name);
        free(head);
        head = next;
    }
}

static void test_clone_preserves_original_and_links(void) {
    struct ifaddrs *original = make_chain(3);
    struct ifaddrs *second = original->ifa_next;
    struct ifaddrs *third = second->ifa_next;
    const struct ifaddrs *selected[] = {original, third};

    struct ifaddrs *clone =
        AutoIPLocIfaddrsCloneAndRegister(original, selected, 2);
    assert(clone != NULL);
    assert(clone != original);
    assert(clone->ifa_next != NULL);
    assert(clone->ifa_next->ifa_next == NULL);
    assert(strcmp(clone->ifa_name, "test0") == 0);
    assert(strcmp(clone->ifa_next->ifa_name, "test2") == 0);
    assert(clone->ifa_flags == original->ifa_flags);
    assert(clone->ifa_next->ifa_flags == third->ifa_flags);

    /* The helper must not rewrite the original list or its ownership. */
    assert(original->ifa_next == second);
    assert(second->ifa_next == third);
    assert(third->ifa_next == NULL);

    assert(AutoIPLocIfaddrsReleaseRegistered(clone, free_original_chain) == 1);
    assert(atomic_load(&g_original_free_calls) == 1);
    assert(AutoIPLocIfaddrsReleaseRegistered(clone, free_original_chain) == 0);
    assert(atomic_load(&g_original_free_calls) == 1);
}

static void test_invalid_inputs_and_unregistered_head(void) {
    struct ifaddrs *original = make_chain(1);
    const struct ifaddrs *selected[] = {original};
    struct ifaddrs unknown = {0};
    const struct ifaddrs *null_selected[] = {NULL};

    assert(AutoIPLocIfaddrsCloneAndRegister(NULL, selected, 1) == NULL);
    assert(AutoIPLocIfaddrsCloneAndRegister(original, NULL, 1) == NULL);
    assert(AutoIPLocIfaddrsCloneAndRegister(original, selected, 0) == NULL);
    assert(AutoIPLocIfaddrsCloneAndRegister(original, null_selected, 1) == NULL);
    assert(AutoIPLocIfaddrsReleaseRegistered(&unknown, free_original_chain) == 0);

    free_original_chain(original);
}

static void test_multiple_allocations_release_out_of_order(void) {
    struct ifaddrs *original_a = make_chain(2);
    struct ifaddrs *original_b = make_chain(2);
    const struct ifaddrs *selected_a[] = {original_a};
    const struct ifaddrs *selected_b[] = {original_b->ifa_next};

    struct ifaddrs *clone_a =
        AutoIPLocIfaddrsCloneAndRegister(original_a, selected_a, 1);
    struct ifaddrs *clone_b =
        AutoIPLocIfaddrsCloneAndRegister(original_b, selected_b, 1);
    assert(clone_a != NULL && clone_b != NULL);

    assert(AutoIPLocIfaddrsReleaseRegistered(clone_b, free_original_chain) == 1);
    assert(AutoIPLocIfaddrsReleaseRegistered(clone_a, free_original_chain) == 1);
}

static void *concurrent_worker(void *unused) {
    (void)unused;
    for (int i = 0; i < ITERATIONS_PER_THREAD; ++i) {
        struct ifaddrs *original = make_chain(3);
        const struct ifaddrs *selected[] = {original, original->ifa_next->ifa_next};
        struct ifaddrs *clone =
            AutoIPLocIfaddrsCloneAndRegister(original, selected, 2);
        assert(clone != NULL);
        assert(AutoIPLocIfaddrsReleaseRegistered(clone, free_original_chain) == 1);
    }
    return NULL;
}

static void test_concurrent_registry_lifecycle(void) {
    pthread_t threads[THREAD_COUNT];
    for (size_t i = 0; i < THREAD_COUNT; ++i) {
        assert(pthread_create(&threads[i], NULL, concurrent_worker, NULL) == 0);
    }
    for (size_t i = 0; i < THREAD_COUNT; ++i) {
        assert(pthread_join(threads[i], NULL) == 0);
    }
}

int main(void) {
    atomic_store(&g_original_free_calls, 0);
    test_clone_preserves_original_and_links();
    test_invalid_inputs_and_unregistered_head();
    test_multiple_allocations_release_out_of_order();
    test_concurrent_registry_lifecycle();

    const int expected = 1 + 1 + 2 + (THREAD_COUNT * ITERATIONS_PER_THREAD);
    assert(atomic_load(&g_original_free_calls) == expected);
    puts("ifaddrs ownership tests: PASS");
    return 0;
}
