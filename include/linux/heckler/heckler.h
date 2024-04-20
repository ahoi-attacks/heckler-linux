#ifndef __HECKLER_H
#define __HECKLER_H

#include <linux/types.h>
#include <linux/spinlock_types.h>
#include <asm/atomic.h>
#include <linux/kvm_types.h>
#include <asm/kvm_page_track.h>
#include <asm/svm.h>

#include <uapi/linux/heckler/sev-step.h>
#include "userspace_page_track_api.h"


typedef struct {
    struct mutex config_mutex;
	struct kvm* main_vm;
    int destroyed;

    int do_tracing;
    int do_tracking;
    int track_all_pages;
    int untrack_all_pages;
    int track_all_pages_flush;
    int do_inject_vector;
    int inject_vector;
    int inject_do_ack;
    // usp_poll_api_ctx_t *uspt_ctx;
} heckler_config_t;

extern heckler_config_t heckler_config;

int heckler_on_page_fault(struct kvm_vcpu *, struct kvm_page_fault *);
int heckler_on_vcpu_create(struct kvm *kvm, struct kvm_vcpu* vcpu);
int heckler_on_vcpu_run(struct kvm_vcpu *);
int heckler_on_kvm_dev_ioctl(struct file *, unsigned int, unsigned long);
int heckler_can_handle_kvm_dev_ioctl(struct file *, unsigned int, unsigned long);
int heckler_on_create_vm(struct kvm*);
int heckler_on_kvm_destroy_vm(struct kvm*);
int heckler_on_kvm_init(void);
int heckler_on_svm_vcpu_enter_exit(struct kvm_vcpu *vcpu);


#endif