/*
 * kallsyms_resolver.c — 运行时 /proc/kallsyms 动态符号查找
 *
 * 4.19 内核仍导出 kallsyms_lookup_name, 但 Android 的 kptr_restrict
 * 可能限制 /proc/kallsyms 读取。此模块提供降级策略:
 *   1. 首选: /proc/kallsyms 可读 -> 直接查找所有符号
 *   2. 降级: /proc/kallsyms 受限 -> 用硬编码偏移 + 指纹验证
 *
 * 集成在 robustness.c 中, 此文件仅提供辅助函数。
 */

#include "robustness.h"
#include "offset.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

#include "kernelsnitch/utils.h"

/*
 * 检查 /proc/kallsyms 是否可读 (非零地址)
 * 返回: 1=可读, 0=受限
 */
int kallsyms_is_readable(void) {
  int fd = open("/proc/kallsyms", O_RDONLY | O_CLOEXEC);
  if (fd < 0) {
    return 0;
  }

  char buf[256];
  ssize_t n = read(fd, buf, sizeof(buf) - 1);
  close(fd);

  if (n <= 0) {
    return 0;
  }
  buf[n] = '\0';

  /* 检查第一行是否有非零地址 */
  unsigned long long addr = 0;
  if (sscanf(buf, "%llx", &addr) == 1 && addr != 0) {
    return 1;
  }

  return 0;
}

/*
 * 批量查找关键符号
 * 返回找到的符号数量
 */
int kallsyms_resolve_batch(
    const char *const *names, uint64_t *addrs, int count) {
  int fd = open("/proc/kallsyms", O_RDONLY | O_CLOEXEC);
  if (fd < 0) {
    return 0;
  }

  FILE *fp = fdopen(fd, "r");
  if (!fp) {
    close(fd);
    return 0;
  }

  /* 初始化 */
  int found = 0;
  int remaining = count;
  for (int i = 0; i < count; i++) {
    addrs[i] = 0;
  }

  char buf[512];
  while (remaining > 0 && fgets(buf, sizeof(buf), fp)) {
    char sym_name[256];
    char sym_type;
    unsigned long long sym_addr;

    if (sscanf(buf, "%llx %c %255s", &sym_addr, &sym_type, sym_name) != 3) {
      continue;
    }
    if (sym_addr == 0) {
      /* kptr_restrict=2 */
      fclose(fp);
      return found;
    }

    /* 去除 $hash 后缀 */
    char *dollar = strchr(sym_name, '$');
    if (dollar) {
      *dollar = '\0';
    }

    for (int i = 0; i < count; i++) {
      if (addrs[i] == 0 && strcmp(sym_name, names[i]) == 0) {
        addrs[i] = (uint64_t)sym_addr;
        found++;
        remaining--;
        break;
      }
    }
  }

  fclose(fp);
  return found;
}

/*
 * 尝试用 kallsyms_lookup_name 函数指针查找单个符号
 * 4.19 内核仍导出此函数
 */
typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);

uint64_t kallsyms_resolve_via_func(const char *name) {
  /* 先从 /proc/kallsyms 找到 kallsyms_lookup_name 自身地址 */
  uint64_t func_addr = kallsyms_resolve("kallsyms_lookup_name");
  if (func_addr == 0) {
    return 0;
  }

  /* 将函数地址转为可调用指针
   * 注意: 这需要内核代码段可执行, 在用户态不可直接调用
   * 此函数仅在 pipe 原语可用后, 通过内核读原语间接调用
   * 当前实现返回 0, 保留接口供未来扩展
   */
  (void)func_addr;
  return 0;
}
