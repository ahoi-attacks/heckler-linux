#include <linux/smp.h>
#include <linux/vmalloc.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <asm/svm.h>
#include <linux/kvm.h>
#include <lapic.h>
#include <linux/kvm_host.h>
#include <linux/xarray.h>
#include "svm/svm.h"

#include <linux/heckler/sev-step.h>
#include <linux/heckler/heckler.h>
#include "../mmu/mmu_internal.h"

heckler_config_t heckler_config = {};

EXPORT_SYMBOL(heckler_config);

// XXX: Remove page from NX page_track tracking
// Call __clear_nx_on_page separately to clear NX bit
static bool __do_untrack_single_page(struct kvm_vcpu *vcpu, gfn_t gfn) {
    int idx;
    bool ret = 0;
    struct kvm_memory_slot *slot;
    enum kvm_page_track_mode mode = KVM_PAGE_TRACK_EXEC;

    idx = srcu_read_lock(&vcpu->kvm->srcu);
    slot = kvm_vcpu_gfn_to_memslot(vcpu, gfn);
    write_lock(&vcpu->kvm->mmu_lock);

    if (slot != NULL
        && kvm_slot_page_track_is_active(vcpu->kvm, slot, gfn, mode)) {
        kvm_slot_page_track_remove_page(vcpu->kvm, slot, gfn, mode);
        ret = true;
    } else {
        if (slot == NULL) {
            pr_info("Failed to untrack %016llx because slot null\n", gfn);
        } else if (!kvm_slot_page_track_is_active(vcpu->kvm, slot, gfn, mode)) {
            pr_info("Failed to untrack %016llx because not active \n", gfn);
        }
    }

    write_unlock(&vcpu->kvm->mmu_lock);
    srcu_read_unlock(&vcpu->kvm->srcu, idx);
    return ret;

}

// XXX: Add page to NX page_track tracking
static bool __do_track_single_page(struct kvm_vcpu *vcpu, gfn_t gfn) {
    bool ret;
    int idx;
    struct kvm_memory_slot *slot;
    enum kvm_page_track_mode mode = KVM_PAGE_TRACK_EXEC;

    ret = false;
    idx = srcu_read_lock(&vcpu->kvm->srcu);
    slot = kvm_vcpu_gfn_to_memslot(vcpu, gfn);
    write_lock(&vcpu->kvm->mmu_lock);

    if (slot != NULL &&
        !kvm_slot_page_track_is_active(vcpu->kvm, slot, gfn, mode)) {
        kvm_slot_page_track_add_page(vcpu->kvm, slot, gfn, mode);
        kvm_vcpu_exec_protect_gfn(vcpu, gfn, true);
        ret = true;

    } else {
        if (slot == NULL) {
            pr_info("Failed to track %016llx because slot null\n", gfn);
        } else if (kvm_slot_page_track_is_active(vcpu->kvm, slot, gfn, mode)) {
            pr_info("Failed to track %016llx because already active \n", gfn);
        }
        ret = false;
    }

    write_unlock(&vcpu->kvm->mmu_lock);
    srcu_read_unlock(&vcpu->kvm->srcu, idx);
    return ret;
}

bool __clear_nx_on_page(struct kvm_vcpu *vcpu, gfn_t gfn) {
    int idx;
    bool ret;
    struct kvm_memory_slot *slot;

    ret = false;
    idx = srcu_read_lock(&vcpu->kvm->srcu);
    slot = kvm_vcpu_gfn_to_memslot(vcpu, gfn);

    if (slot != NULL) {
        write_lock(&vcpu->kvm->mmu_lock);
        kvm_mmu_slot_gfn_protect(vcpu->kvm, slot, gfn, PG_LEVEL_4K,
                                 KVM_PAGE_TRACK_RESET_EXEC);
        write_unlock(&vcpu->kvm->mmu_lock);
        ret = true;
    }
    srcu_read_unlock(&vcpu->kvm->srcu, idx);
    return ret;
}

static int __track_all_pages_on_next_run(int flush) {
    mutex_lock(&heckler_config.config_mutex);

    heckler_config.track_all_pages = 1;
    heckler_config.track_all_pages_flush = !!flush;
    mutex_unlock(&heckler_config.config_mutex);

    pr_info("track_all_pages enabled for next vcpu run\n");
    return 0;
}

static int __init_poll_api(usp_init_poll_api_t param) {
    int ret = 0;

    uspt_ctx = kmalloc(sizeof(usp_poll_api_ctx_t), GFP_KERNEL);
    if (!uspt_ctx) {
        return -ENOMEM;
    }
    if (param.track_boot) {
        pr_info("__track_all_pages_on_next_run\n");
        ret = __track_all_pages_on_next_run(true);
        if (ret < 0) {
            goto error;
        }
    }
    pr_info("pid: %d, vaddr_shm: %p, ctx: %p\n",
            param.pid,
            (void *)param.user_vaddr_shared_mem,
            (void *)uspt_ctx);

    ret = usp_poll_init_user_vaddr(param.pid,
                                   param.user_vaddr_shared_mem,
                                   uspt_ctx);
    if (ret < 0) {
        pr_info("__track_all_pages_on_next_run failed: %d\n", ret);
        goto error;
    }
    return 0;
error:
    pr_info("_init_poll_api: failed\n");
    kfree(uspt_ctx);
    return ret;
}

static int __close_poll_api(void) {
    int ret = 0;
    struct page **pinned_pages;
    int pinned_pages_len;
    void *kernel_mapping;

    pr_info("KVM_USP_CLOSE_POLL_API\n");

    if (uspt_ctx == NULL) {
        pr_info("ctx already null");
        return 0;
    }

    pinned_pages = uspt_ctx->_pages_for_shared_mem;
    pinned_pages_len = uspt_ctx->_pages_for_shared_mem_len;
    kernel_mapping = uspt_ctx->shared_mem_region;

    ret = usp_poll_close_api(uspt_ctx);
    if (ret < 0) {
        pr_info("usp_poll_close_api: failed to close ctx\n");
        return -EINVAL;
    }
    kfree(uspt_ctx);
    uspt_ctx = NULL;

    if (kernel_mapping != NULL) {
        vunmap(kernel_mapping);
    }
    if (pinned_pages != NULL) {
        uint64_t idx;
        //sanity check refcount values
        for (idx = 0; idx < pinned_pages_len; idx++) {
            if (page_ref_count(pinned_pages[idx]) < 0) {
                pr_info("%s:%d [%s] unpinning pfn 0x%lx. refcount before: %d\n",
                        __FILE__, __LINE__, __FUNCTION__,
                        page_to_pfn(pinned_pages[idx]),
                        page_ref_count(pinned_pages[idx]));
            }
        }

        unpin_user_pages(pinned_pages, pinned_pages_len);

        //sanity check refcount values
        for (idx = 0; idx < pinned_pages_len; idx++) {
            if (page_ref_count(pinned_pages[idx]) < 0) {
                pr_info("%s:%d [%s] pfn 0x%lx. refcount after: %d\n",
                        __FILE__, __LINE__, __FUNCTION__,
                        page_to_pfn(pinned_pages[idx]),
                        page_ref_count(pinned_pages[idx]));
            }
        }
        kfree(pinned_pages);
    }

    if (heckler_config.destroyed) {
        return 0;
    }

    kvm_stop_tracking(xa_load(&heckler_config.main_vm->vcpu_array, 0),
                      KVM_PAGE_TRACK_EXEC);
    ret = 0;
    return ret;
}

int heckler_on_svm_vcpu_enter_exit(struct kvm_vcpu *vcpu) {
    struct vcpu_svm *svm = to_svm(vcpu);
    u64 fault_address = svm->vmcb->control.exit_info_2;

    mutex_lock(&heckler_config.config_mutex);

    if (heckler_config.do_inject_vector == 2) {
        heckler_config.do_inject_vector = 0;

        pr_info("apic clear isr: interrupt: %d\n",
            heckler_config.inject_vector);

        kvm_apic_clear_irr(vcpu, heckler_config.inject_vector);
    }

    if (svm->vmcb->control.exit_code == SVM_EXIT_NPF &&
        heckler_config.do_inject_vector == 1) {
        heckler_config.do_inject_vector = 2;

        pr_info("injecting: vector: %d, npf: %llx\n",
                heckler_config.inject_vector, fault_address);

        svm->vmcb->control.event_inj = heckler_config.inject_vector |
            SVM_EVTINJ_VALID |
            SVM_EVTINJ_TYPE_INTR;
    }

    mutex_unlock(&heckler_config.config_mutex);

    return 0;
}
EXPORT_SYMBOL(heckler_on_svm_vcpu_enter_exit);

int heckler_on_vcpu_run(struct kvm_vcpu *vcpu) {
    int do_tracking = 0;

    if (uspt_ctx == NULL) {
        return 0;
    }

    mutex_lock(&heckler_config.config_mutex);
    if (heckler_config.track_all_pages != 0) {
        pr_info("heckler: track_all_pages == 1\n");

        heckler_config.track_all_pages = 0;
        heckler_config.track_all_pages_flush = 0;
        do_tracking = 1;
    }
    mutex_unlock(&heckler_config.config_mutex);

    if (do_tracking) {
        kvm_start_tracking(vcpu, KVM_PAGE_TRACK_EXEC);
    }

    return 0;
}

int heckler_on_vcpu_create(struct kvm *kvm, struct kvm_vcpu *vcpu) {
    mutex_lock(&heckler_config.config_mutex);
    heckler_config.main_vm = kvm;
    mutex_unlock(&heckler_config.config_mutex);
    return 0;
}

int heckler_on_create_vm(struct kvm *) {
    pr_info("heckler_on_create_vm\n");
    heckler_config.destroyed = 0;
    return 0;
}

int heckler_setup_inject(struct kvm_vcpu *vcpu) {
    return 0;
}

int heckler_on_kvm_destroy_vm(struct kvm *) {
    pr_info("heckler_on_kvm_destroy_vm\n");
    mutex_lock(&heckler_config.config_mutex);
    
    heckler_config.destroyed = 1;
    heckler_config.main_vm = NULL;
    
    mutex_unlock(&heckler_config.config_mutex);
    return 0;
}

int heckler_on_kvm_init() {
    memset(&heckler_config, 0, sizeof(heckler_config_t));
    mutex_init(&heckler_config.config_mutex);
    return 0;
}

int heckler_on_page_fault(struct kvm_vcpu *vcpu, struct kvm_page_fault *fault) {
    int active = 0;
    struct kvm_memory_slot *slot;
    int ret = 0;

    slot = kvm_vcpu_gfn_to_memslot(vcpu, fault->gfn);
    if (slot != NULL) {
        active = kvm_slot_page_track_is_active(vcpu->kvm,
                                               slot,
                                               fault->gfn,
                                               KVM_PAGE_TRACK_EXEC);
        if (active) {
            __do_untrack_single_page(vcpu,
                                     fault->gfn);
#if 0
            kvm_vcpu_exec_unprotect_gfn(vcpu,
                                        fault->gfn,
                                        true);
            __clear_nx_on_page(vcpu,
                               fault->gfn);
#endif
        }
    }

    pr_info("c:%d active: %d pf: %llx x:%d p:%d w:%d u:%d "
            "rsvd %d pref:%d tdp:%d\n",
            uspt_ctx != NULL, active, fault->addr, fault->exec,
            fault->present, fault->write, fault->user, fault->rsvd,
            fault->prefetch, fault->is_tdp);

    if (uspt_ctx == NULL) {
        return 0;
    }

    if (active) {
        usp_page_fault_event_t pf_event = {
            .faulted_gpa = (uint64_t)(fault->addr),
            .is_decrypted_vmsa_data_valid = false,
            .has_vmsa_blob = 0,
        };

        ret = usp_send_and_block(uspt_ctx,
                                 PAGE_FAULT_EVENT,
                                 (void *)&pf_event);
        switch (ret) {
            case 2: {
                pr_info("usp_send_and_block aborted due to force_reset\n");
                break;
            }
            case 0:
                //no error
                break;
            default: {
                pr_info("usp_send_and_block: Failed in svm_vcpu_run with %d", ret);
                break;
            }
        }
    }
    return 0;
}

static int __ioctl_inj_interrupt(struct file *f, void *a) {
    inject_interrupt_t inj;
    if (copy_from_user(&inj, (void *)a, sizeof(inj))) {
        return -EINVAL;
    }
    pr_info("inject %x on next vcpu run\n", inj.vector);

    mutex_lock(&heckler_config.config_mutex);
    heckler_config.do_inject_vector = 1;
    heckler_config.inject_vector = inj.vector;
    mutex_unlock(&heckler_config.config_mutex);

    return 0;
}

static int __ioctl_track_page(struct file *f, void *a) {
    track_page_param_t p;
    struct kvm_vcpu *vcpu = NULL;

    if (copy_from_user(&p, (void *)a, sizeof(p))) {
        return -EINVAL;
    }
    pr_info("tracking page %llx\n", p.gpa >> PAGE_SHIFT);
    vcpu = xa_load(&heckler_config.main_vm->vcpu_array, 0);

    __do_track_single_page(
        vcpu,
        p.gpa >> PAGE_SHIFT);

    return 0;
}

static int __ioctl_untrack_page(struct file *f, void *a) {
    track_page_param_t p;
    unsigned long gfn;
    struct kvm_vcpu *vcpu = NULL;
    int r = 0;

    if (copy_from_user(&p, (void *)a, sizeof(p))) {
        return -EINVAL;
    }
    if (p.gpa == 0) {
        pr_info("invalid gpa\n");
        return -EINVAL;
    }

    gfn = p.gpa >> PAGE_SHIFT;
    vcpu = xa_load(&heckler_config.main_vm->vcpu_array, 0);

    r = __do_untrack_single_page(vcpu, gfn);

    if (r < 0) {
        pr_info("__do_untrack_single_page returned: %d\n", r);
    }

    __clear_nx_on_page(vcpu, gfn);

    #if 0
    kvm_vcpu_exec_unprotect_gfn(vcpu,
                                gfn,
                                true);
    #endif


    return 0;
}

static int __ioctl_track_all_pages(struct file *f, void *a) {
    struct kvm_vcpu *vcpu = NULL;

    if (heckler_config.main_vm != NULL) {
        vcpu = xa_load(&heckler_config.main_vm->vcpu_array, 0);
        kvm_start_tracking(
            vcpu,
            KVM_PAGE_TRACK_EXEC);
    } else {
        __track_all_pages_on_next_run(true);
    }

    return 0;
}

static int __ioctl_untrack_all_pages(struct file *f, void *a) {
    track_all_pages_t param;
    if (copy_from_user(&param, (void *)a, sizeof(param))) {
        return -EINVAL;
    }
    if (heckler_config.main_vm == NULL) {
        pr_info("main_vm is not initialized, aborting!\n");
        return -EINVAL;
    }
    if (heckler_config.destroyed == 1) {
        pr_info("main_vm already dead. destroyed = 1\n");
        return 0;
    }

    kvm_stop_tracking(xa_load(&heckler_config.main_vm->vcpu_array, 0),
                      KVM_PAGE_TRACK_EXEC);

    return 0;
}

__attribute__((unused))
static const char* __ioctl_to_char(unsigned int ioctl) {
    switch (ioctl) {
        case KVM_INJECT_INTERRUPT: return "KVM_INJECT_INTERRUPT";
        case KVM_TRACK_PAGE: return "KVM_TRACK_PAGE";
        case KVM_UNTRACK_PAGE: return "KVM_UNTRACK_PAGE";
        case KVM_TRACK_ALL_PAGES: return "KVM_TRACK_ALL_PAGES";
        case KVM_UNTRACK_ALL_PAGES: return "KVM_UNTRACK_ALL_PAGES";
        case KVM_USP_CLOSE_POLL_API: return "KVM_USP_CLOSE_POLL_API";
        case KVM_USP_INIT_POLL_API: return "KVM_USP_INIT_POLL_API";
        default: return "unknown";
    }
}

int heckler_can_handle_kvm_dev_ioctl(struct file *filp, unsigned int ioctl,
                                     unsigned long arg) {
    return ioctl == KVM_TRACK_PAGE
        || ioctl == KVM_UNTRACK_PAGE
        || ioctl == KVM_TRACK_ALL_PAGES
        || ioctl == KVM_UNTRACK_ALL_PAGES
        || ioctl == KVM_USP_INIT_POLL_API
        || ioctl == KVM_USP_CLOSE_POLL_API
        || ioctl == KVM_INJECT_INTERRUPT;
}

int heckler_on_kvm_dev_ioctl(struct file *f,
                             unsigned int ioctl,
                             unsigned long a) {
    long r = 0;

    #if 0
    pr_info("heckler ioctl %s\n", __ioctl_to_char(ioctl));
    #endif
    switch (ioctl) {
        case KVM_INJECT_INTERRUPT: return __ioctl_inj_interrupt(f, (void *)a);
        case KVM_TRACK_PAGE: return __ioctl_track_page(f, (void *)a);
        case KVM_UNTRACK_PAGE: return __ioctl_untrack_page(f, (void *)a);
        case KVM_TRACK_ALL_PAGES: return __ioctl_track_all_pages(f, (void *)a);
        case KVM_UNTRACK_ALL_PAGES: return __ioctl_untrack_all_pages(f, (void *)a);
        case KVM_USP_CLOSE_POLL_API: return __close_poll_api();
        case KVM_USP_INIT_POLL_API: {
            usp_init_poll_api_t param;
            if (copy_from_user(&param, (void *)a, sizeof(param))) {
                r = -EINVAL;
                break;
            }
            return __init_poll_api(param);
        }
        default: {
            r = -EINVAL;
        }
    }
    return r;
}
