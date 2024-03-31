#ifndef __UAPI_LINUX_HECKLER_H
#define __UAPI_LINUX_HECKLER_H

#include <linux/types.h>

#ifdef __KERNEL__
// #include <uapi/asm/kvm_page_track.h>
#else
// #include <asm/kvm_page_track.h>
#include <stdbool.h>
#include <stdint.h>
#endif


//
// SEV-STEP IOCTLs
//
#define KVM_TRACK_BOOT _IOWR(KVMIO, 0xa, track_boot_param_t)
#define KVM_TRACK_PAGE _IOWR(KVMIO, 0xb, track_page_param_t)
#define KVM_TRACK_ALL_PAGES _IOWR(KVMIO, 0xc, track_all_pages_t)
#define KVM_UNTRACK_ALL_PAGES _IOWR(KVMIO, 0xd, track_all_pages_t)
#define KVM_UNTRACK_PAGE _IOWR(KVMIO, 0xe, track_page_param_t)
#define KVM_USP_INIT_POLL_API _IOWR(KVMIO, 0xf, usp_init_poll_api_t)
#define KVM_USP_CLOSE_POLL_API _IO(KVMIO, 0x10)
#define KVM_SEV_STEP_ENABLE _IOWR(KVMIO, 0x11, sev_step_param_t)
#define KVM_SEV_STEP_DISABLE _IO(KVMIO, 0x12)
/**
 * @brief Injects an nmi into vm upon next vmrun.
 * Should only be called while vm is halted
 * 
 */
#define KVM_SEV_STEP_INJECT_NMI _IO(KVMIO, 0x13)

/**
 * @brief Build an L1D way predictor eviction set in kernel space
 * //TODO: probpably abandon in favor of KVM_SET_STEP_IMPORT_USER_EVS
 * 
 */
#define KVM_SEV_STEP_BUILD_EVS _IOWR(KVMIO, 0x15, build_eviction_set_param_t)
/**
 * @brief Free eviction set that has been allocated with either KVM_SEV_STEP_BUILD_EVS or
 * KVM_SET_STEP_IMPORT_USER_EVS
 * 
 */
#define KVM_SEV_STEP_FREE_EVS _IO(KVMIO, 0x16)

/**
 * @brief "Imports" an eviction set built in userspace by pinning the pages and creating mappings
 * to the underlying pages, so that we can use the eviction set anywhere in the kernel space.
 * Note: Does not work for way predictor based eviction sets, as these depend on the virtual address, which
 * changes when we create our kernel space mapping (in constrast to the underlying physical page, which stays the same)
 * 
 */
#define KVM_SET_STEP_IMPORT_USER_EVS _IOWR(KVMIO, 0x17, import_user_eviction_set_param_t)

/**
 * @brief Perform a cache attack on the next (single) step. Eviction set must already be loaded.
 * Result will be part of the step event
 * 
 */
#define KVM_SEV_STEP_DO_CACHE_ATTACK_NEXT_STEP _IOWR(KVMIO, 0x18, do_cache_attack_param_t)

/**
 * @brief Resolves the Guest Physical Adress to an Host Physical Adress.
 * This is e.g. required to build eviction sets that are based on the physical adress
 * 
 */
#define KVM_SEV_STEP_GPA_TO_HPA _IOWR(KVMIO, 0x19, gpa_to_hpa_param_t)

#define KVM_SEV_STEP_CACHE_ATTACK_TESTBED _IO(KVMIO, 0x20)

#define KVM_SEV_STEP_BUILD_ALIAS_EVS _IOWR(KVMIO, 0x21, build_eviction_set_param_t )



#define SEV_STEP_SHARED_MEM_BYTES (20 * 4096)
/**
 * @brief struct for storing the performance counter config values
 */
typedef struct {
	uint64_t HostGuestOnly;
	uint64_t CntMask;
	uint64_t Inv;
	uint64_t En;
	uint64_t Int;
	uint64_t Edge;
	uint64_t OsUserMode;
	uint64_t UintMask;
	uint64_t EventSelect; //12 bits in total split in [11:8] and [7:0]
	char* descriptive_name;
} perf_ctl_config_t;

typedef struct {
	uint64_t lookup_table_index;
	bool apic_timer_value_valid;
	uint32_t custom_apic_timer_value;
} do_cache_attack_param_t;

typedef struct {
	/// @brief Input Parameter. We want the HPA for this
	uint64_t in_gpa;
	/// @brief Result Parameter.
	uint64_t out_hpa;
} gpa_to_hpa_param_t;

/**
 * @brief Describe lookup table that can be targeted by a cache attack
 * 
 */
typedef struct {
	/// @brief guest vaddr where the lookup table starts
	uint64_t base_vaddr_table;
	/// @brief length of the lookup table in bytes
	uint64_t table_bytes;
} lookup_table_t;

typedef struct {
	/// @brief we build and l1d way predictor eviction for each target
	lookup_table_t *attack_targets;
	uint64_t attack_targets_len;
	/// @brief  configures the perf counter evaluated for the cache attack
	perf_ctl_config_t cache_attack_perf;
} build_eviction_set_param_t;

typedef struct {
	/// @brief flattened 2D array with the evictions sets.
	/// Every @import_user_eviction_set_param_t.way_count elements form one eviction set
	/// for each cache set covered by the lookup_table
	uint64_t *eviction_sets;
	/// @brief length of eviction_sets
	uint64_t eviction_sets_len;
} lookup_table_eviction_set_t;

typedef struct {
	/// @brief we build and l1d way predictor eviction for each target
	lookup_table_t *attack_targets;
	/// @brief eviction sets for the supplied attack_targets
	lookup_table_eviction_set_t *eviction_sets;
	/// @brief len of both attack_targets and eviction_sets
	uint64_t len;
	/// @brief ways of the attacked cache
	uint64_t way_count;
	/// @brief  configures the perf counter evaluated for the cache attack
	perf_ctl_config_t cache_attack_perf;
} import_user_eviction_set_param_t;

typedef enum {
	VRN_RFLAGS,
	VRN_RIP,
	VRN_RSP,
	VRN_R10,
	VRN_R11,
	VRN_R12,
	VRN_R13,
	VRN_R8,
	VRN_R9,
	VRN_RBX,
	VRN_RCX,
	VRN_RDX,
	VRN_RSI,
	VRN_CR3,
	VRN_MAX, //not a register; used to size sev_step_partial_vmcb_save_area_t.register_values
} vmsa_register_name_t;

typedef struct {
	/// @brief indexed by vmsa_register_name_t
	uint64_t register_values[VRN_MAX];
	bool failed_to_get_data;
} sev_step_partial_vmcb_save_area_t;

/**
 * @brief struct for storing tracking parameters 
 * which are sent from userspace
 */
typedef struct {
	//guest physical address of page
	uint64_t gpa;
	//one of the track modes defined in enum kvm_page_track_mode
	int track_mode;
} track_page_param_t;

typedef struct {
	int enabled;
} track_boot_param_t;

/**
 * @brief struct for storing tracking parameters 
 * for all pages which are sent from userspace
 */
typedef struct {
	//one of the track modes defined in enum kvm_page_track_mode
	int track_mode;
} track_all_pages_t;

/**
 * @brief enum for supported event types
 */
typedef enum {
	//used for page fault events
	PAGE_FAULT_EVENT,
	//used for single stepping events
	SEV_STEP_EVENT,
} usp_event_type_t;

/**
 * @brief Stores the structure of the shared memory 
 * region between kernelspace and userspace
 */
typedef struct {
	//lock for all of the other values in this struct
	int spinlock;
	//if true, we have a valid event stored
	int have_event;
	//if true, the receiver has acked the event
	int event_acked;
	//type of the stored event. Required to do the correct raw mem cast
	usp_event_type_t event_type;
	// buffer for the event
	uint8_t event_buffer[19 * 4096];
} shared_mem_region_t;

/**
 * @brief struct for storing parameters which are
 * needed for the initialization of the api
 */
typedef struct {
	//process id
	int pid;
	//the user defined shared memory address
	uint64_t user_vaddr_shared_mem;
	/// @brief if true, decrypt vmsa and send information with each event
	///only works if debug mode is active
	bool decrypt_vmsa;
	bool track_boot;
} usp_init_poll_api_t;


typedef struct {
	char cr3_cr0[16];
	char rflags_rip[16];
	char rsp[16];
	char rax[16];
	char cr2[16];
	char rcx[16];
	char rdx_rbx[16];
	char rbp[16];
	char rsi_rdi[16];
	char r8_r9[16];
	char r10_r11[16];
	char r12_r13[16];
	char r14_r15[16];
}  __packed vmcb_save_area_encrypt_blobs_t;



/**
 * @brief struct for storing page fault parameters 
 * which are sent to userspace
 */
typedef struct {
	// gpa of the page fault
	uint64_t faulted_gpa;
	sev_step_partial_vmcb_save_area_t decrypted_vmsa_data;
	/// @brief if true, decrypted_vmsa_data contains valid data
	bool is_decrypted_vmsa_data_valid;
	bool has_vmsa_blob;
	vmcb_save_area_encrypt_blobs_t vmsa_blob;
} usp_page_fault_event_t;

/**
 * @brief struct for storing sev-step event parameters
 * to send them to userspace
 */
typedef struct {
	uint32_t counted_instructions;
	sev_step_partial_vmcb_save_area_t decrypted_vmsa_data;
	/// @brief if true, decrypted_vmsa_data contains valid data
	bool is_decrypted_vmsa_data_valid;
	uint64_t *cache_attack_timings;
	uint64_t *cache_attack_perf_values;
	/// @brief length of both cache_attack_timings and
	/// cache_attack_perf_values
	uint64_t cache_attack_data_len;
	/************* NEMESIS ***************/
	uint64_t tsc_latency;
	/************************************/
} sev_step_event_t;

/**
 * @brief struct for storing sev-step config parameters
 * which are sent from userspace
 */
typedef struct {
	// apic timer value
	uint32_t tmict_value;
	/// @brief May be null. If set, we reset the ACCESS bits of these pages before vmentry
	/// which improves single stepping accuracy
	uint64_t *gpas_target_pages;
	uint64_t gpas_target_pages_len;
	bool do_tlb_flush_before_each_step;
} sev_step_param_t;




#endif
