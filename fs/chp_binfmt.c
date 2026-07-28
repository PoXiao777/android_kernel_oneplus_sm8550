// SPDX-License-Identifier: GPL-2.0-only
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/binfmts.h>
#include <linux/elf.h>
#include <linux/fs.h>
#include <linux/mutex.h>
#include <linux/string.h>

#define EXA64_PATH "/exa64"
#define CHP_OPTIONS_LEN 256
#define CHP_MAX_OPTIONS 32

static char chp_options[CHP_OPTIONS_LEN] =
    "--use-binfmt-misc --smo-disable-libc-warn "
    "--enable-fast-interpreter";
static DEFINE_MUTEX(chp_options_lock);

static int chp_options_set(const char *val, const struct kernel_param *kp)
{
    char options[CHP_OPTIONS_LEN];

    if (strscpy(options, val, sizeof(options)) < 0)
        return -E2BIG;

    mutex_lock(&chp_options_lock);
    strscpy(chp_options, options, sizeof(chp_options));
    mutex_unlock(&chp_options_lock);
    return 0;
}

static int chp_options_get(char *buffer, const struct kernel_param *kp)
{
    int ret;

    mutex_lock(&chp_options_lock);
    ret = scnprintf(buffer, PAGE_SIZE, "%s", chp_options);
    mutex_unlock(&chp_options_lock);
    return ret;
}

static const struct kernel_param_ops chp_options_ops = {
    .set = chp_options_set,
    .get = chp_options_get,
};
module_param_cb(options, &chp_options_ops, &chp_options, 0644);
MODULE_PARM_DESC(options, "Space-separated ExaGear options (without /exa64 and --)");

static int is_x86_64_elf(struct linux_binprm *bprm)
{
    struct elfhdr *elf = (struct elfhdr *)bprm->buf;
    if (memcmp(elf->e_ident, ELFMAG, SELFMAG) != 0) return 0;
    if (elf->e_ident[EI_CLASS] != ELFCLASS64) return 0;
    if (elf->e_ident[EI_DATA] != ELFDATA2LSB) return 0;
    if (elf->e_machine != EM_X86_64) return 0;
    if (elf->e_type != ET_EXEC && elf->e_type != ET_DYN) return 0;
    return 1;
}

static int chp_load_binary(struct linux_binprm *bprm)
{
    int ret, i, option_count = 0;
    struct file *file;
    char options[CHP_OPTIONS_LEN];
    char *cursor, *option;
    const char *parsed[CHP_MAX_OPTIONS];

    if (!is_x86_64_elf(bprm))
        return -ENOEXEC;

    mutex_lock(&chp_options_lock);
    strscpy(options, chp_options, sizeof(options));
    mutex_unlock(&chp_options_lock);

    cursor = options;
    while ((option = strsep(&cursor, " \t\n")) != NULL) {
        if (!*option)
            continue;
        if (option_count == CHP_MAX_OPTIONS)
            return -E2BIG;
        parsed[option_count++] = option;
    }

    /* Preserve the original executable path, as binfmt_misc passes it as argv[1]. */
    ret = copy_string_kernel("--", bprm);
    if (ret)
        return ret;
    for (i = option_count - 1; i >= 0; i--) {
        ret = copy_string_kernel(parsed[i], bprm);
        if (ret)
            return ret;
    }
    ret = copy_string_kernel(EXA64_PATH, bprm);
    if (ret)
        return ret;

    bprm->argc += option_count + 2;

    /* Hand the rewritten argv to the actual /exa64 interpreter. */
    ret = bprm_change_interp(EXA64_PATH, bprm);
    if (ret)
        return ret;

    file = open_exec(EXA64_PATH);
    if (IS_ERR(file))
        return PTR_ERR(file);
    bprm->interpreter = file;

    return 0;
}

static struct linux_binfmt chp_binfmt = {
    .module = THIS_MODULE,
    .load_binary = chp_load_binary,
};

static int __init chp_binfmt_init(void)
{
    pr_info("CHP: x86_64 binfmt handler registered\n");
    insert_binfmt(&chp_binfmt);
    return 0;
}

static void __exit chp_binfmt_exit(void)
{
    unregister_binfmt(&chp_binfmt);
}

#ifdef MODULE
module_init(chp_binfmt_init);
module_exit(chp_binfmt_exit);
MODULE_LICENSE("GPL");
#else
fs_initcall(chp_binfmt_init);
#endif
