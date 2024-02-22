# ChCore 实验3 实验报告

## 练习1

```c++
cap_t sys_create_cap_group(unsigned long cap_group_args_p)
{
        struct cap_group *new_cap_group;
        struct vmspace *vmspace;
        cap_t cap;
        int r;
        struct cap_group_args args = {0};

        r = hook_sys_create_cap_group(cap_group_args_p);
        if (r != 0) return r;

        if (check_user_addr_range((vaddr_t)cap_group_args_p,
                sizeof(struct cap_group_args)) != 0)
                return -EINVAL;

        r = copy_from_user(&args, (void *)cap_group_args_p, sizeof(struct cap_group_args));
        if (r) {
                return -EINVAL;
        }

        if (check_user_addr_range((vaddr_t)args.name, (size_t)args.name_len) != 0)
                return -EINVAL;

        /* cap current cap_group */
        /* LAB 3 TODO BEGIN */
        // 分配新的 CAP_GROUP
        new_cap_group = obj_alloc(TYPE_CAP_GROUP, sizeof(struct cap_group));
        /* LAB 3 TODO END */
        if (!new_cap_group) {
                r = -ENOMEM;
                goto out_fail;
        }
        /* LAB 3 TODO BEGIN */
        /* initialize cap group */
        // 初始化
        cap_group_init(new_cap_group, BASE_OBJECT_NUM, args.badge);
        /* LAB 3 TODO END */

        cap = cap_alloc(current_cap_group, new_cap_group);
        if (cap < 0) {
                r = cap;
                goto out_free_obj_new_grp;
        }

        /* 1st cap is cap_group */
        if (cap_copy(current_thread->cap_group, new_cap_group, cap)
            != CAP_GROUP_OBJ_ID) {
                kwarn("%s: cap_copy fails or cap[0] is not cap_group\n", __func__);
                r = -ECAPBILITY;
                goto out_free_cap_grp_current;
        }

        /* 2st cap is vmspace */
        /* LAB 3 TODO BEGIN */
        // 分配 VMSPACE
        vmspace = obj_alloc(TYPE_VMSPACE, sizeof(struct vmspace));
        /* LAB 3 TODO END */

        if (!vmspace) {
                r = -ENOMEM;
                goto out_free_obj_vmspace;
        }

        vmspace_init(vmspace, args.pcid);

        r = cap_alloc(new_cap_group, vmspace);
        if (r != VMSPACE_OBJ_ID) {
                kwarn("%s: cap_copy fails or cap[1] is not vmspace\n", __func__);
                r = -ECAPBILITY;
                goto out_free_obj_vmspace;
        }

        new_cap_group->notify_recycler = 0;

        /* Set the cap_group_name (process_name) for easing debugging */
        memset(new_cap_group->cap_group_name, 0, MAX_GROUP_NAME_LEN + 1);
        if (args.name_len > MAX_GROUP_NAME_LEN)
                args.name_len = MAX_GROUP_NAME_LEN;
        
        r = copy_from_user(new_cap_group->cap_group_name,
                           (void *)args.name,
                           args.name_len);
        if (r) {
                r = -EINVAL;
                goto out_free_obj_vmspace;
        }

        return cap;
out_free_obj_vmspace:
        obj_free(vmspace);
out_free_cap_grp_current:
        cap_free(current_cap_group, cap);
        new_cap_group = NULL;
out_free_obj_new_grp:
        obj_free(new_cap_group);
out_fail:
        return r;
}
```

```C++
struct cap_group *create_root_cap_group(char *name, size_t name_len)
{
        struct cap_group *cap_group;
        struct vmspace *vmspace;
        cap_t slot_id;

        /* LAB 3 TODO BEGIN */
        // 分配 CAP_GROUP 内核对象
        cap_group = obj_alloc(TYPE_CAP_GROUP, sizeof(struct cap_group));
        /* LAB 3 TODO END */
        BUG_ON(!cap_group);

        /* LAB 3 TODO BEGIN */
        /* initialize cap group, use ROOT_CAP_GROUP_BADGE */
        // 初始化
        cap_group_init(cap_group, BASE_OBJECT_NUM, ROOT_CAP_GROUP_BADGE);
        /* LAB 3 TODO END */
        slot_id = cap_alloc(cap_group, cap_group);

        BUG_ON(slot_id != CAP_GROUP_OBJ_ID);

        /* LAB 3 TODO BEGIN */
        // 分配 VMSPACE 内核对象
        vmspace = obj_alloc(TYPE_VMSPACE, sizeof(struct vmspace));
        /* LAB 3 TODO END */
        BUG_ON(!vmspace);

        /* fixed PCID 1 for root process, PCID 0 is not used. */
        vmspace_init(vmspace, ROOT_PROCESS_PCID);

        /* LAB 3 TODO BEGIN */
        // 分配 slot
        slot_id = cap_alloc(cap_group, vmspace);
        /* LAB 3 TODO END */

        BUG_ON(slot_id != VMSPACE_OBJ_ID);

        /* Set the cap_group_name (process_name) for easing debugging */
        memset(cap_group->cap_group_name, 0, MAX_GROUP_NAME_LEN + 1);
        if (name_len > MAX_GROUP_NAME_LEN)
                name_len = MAX_GROUP_NAME_LEN;
        memcpy(cap_group->cap_group_name, name, name_len);

        root_cap_group = cap_group;
        return cap_group;
}
```



## 练习2

```C++
void create_root_thread(void)
{
//...
                /* LAB 3 TODO BEGIN */
                /* Get offset, vaddr, filesz, memsz from image*/
                // 获取 offset
                memcpy(data,
                       (void *)((unsigned long)&binary_procmgr_bin_start
                                + ROOT_PHDR_OFF + i * ROOT_PHENT_SIZE
                                + PHDR_OFFSET_OFF),
                       sizeof(data));
                offset = (unsigned int)le64_to_cpu(*(u64 *)data);
                // 获取 vaddr
                memcpy(data,
                       (void *)((unsigned long)&binary_procmgr_bin_start
                                + ROOT_PHDR_OFF + i * ROOT_PHENT_SIZE
                                + PHDR_VADDR_OFF),
                       sizeof(data));
                vaddr = (unsigned int)le64_to_cpu(*(u64 *)data);
                // 获取 filesz
                memcpy(data,
                       (void *)((unsigned long)&binary_procmgr_bin_start
                                + ROOT_PHDR_OFF + i * ROOT_PHENT_SIZE
                                + PHDR_FILESZ_OFF),
                       sizeof(data));
                filesz = (unsigned int)le64_to_cpu(*(u64 *)data);
                // 获取 memsz
                memcpy(data,
                       (void *)((unsigned long)&binary_procmgr_bin_start
                                + ROOT_PHDR_OFF + i * ROOT_PHENT_SIZE
                                + PHDR_MEMSZ_OFF),
                       sizeof(data));
                memsz = (unsigned int)le64_to_cpu(*(u64 *)data);
                /* LAB 3 TODO END */

                struct pmobject *segment_pmo;
                /* LAB 3 TODO BEGIN */
                // 创建 PMO
                ret = create_pmo(ROUND_UP(memsz, PAGE_SIZE),
                                 PMO_DATA,
                                 root_cap_group,
                                 0,
                                 &segment_pmo);
                /* LAB 3 TODO END */

                BUG_ON(ret < 0);

                /* LAB 3 TODO BEGIN */
                /* Copy elf file contents into memory*/
                // 将 elf 复制到内存中，先初始化这块内存，再复制进去
                memset((void *)phys_to_virt(segment_pmo->start), 0, segment_pmo->size);
                memcpy((void *)phys_to_virt(segment_pmo->start),
                       (void *)(((unsigned long)&binary_procmgr_bin_start)
                                + ROOT_BIN_HDR_SIZE + offset),
                       filesz);
                /* LAB 3 TODO END */
                
                unsigned vmr_flags = 0;    
                /* LAB 3 TODO BEGIN */
                /* Set flags*/
                // 根据 flags 值设置权限
                if (flags & PHDR_FLAGS_R)
                        vmr_flags |= VMR_READ;
                if (flags & PHDR_FLAGS_W)
                        vmr_flags |= VMR_WRITE;
                if (flags & PHDR_FLAGS_X)
                        vmr_flags |= VMR_EXEC;
                /* LAB 3 TODO END */
//...
}
```



## 练习3

```c++
void init_thread_ctx(struct thread *thread, vaddr_t stack, vaddr_t func,
                     u32 prio, u32 type, s32 aff)
{
        /* Fill the context of the thread */

        /* LAB 3 TODO BEGIN */
        /* SP_EL0, ELR_EL1, SPSR_EL1*/
        // 设置 thread 的三个值
        thread->thread_ctx->ec.reg[SP_EL0] = stack;
        thread->thread_ctx->ec.reg[ELR_EL1] = func;
        thread->thread_ctx->ec.reg[SPSR_EL1] = SPSR_EL1_EL0t;
        /* LAB 3 TODO END */

        /* Set the state of the thread */
        thread->thread_ctx->state = TS_INIT;

        /* Set thread type */
        thread->thread_ctx->type = type;

        /* Set the cpuid and affinity */
        thread->thread_ctx->affinity = aff;

        /* Set the budget and priority of the thread */
        if (thread->thread_ctx->sc != NULL) {
                thread->thread_ctx->sc->prio = prio;
                thread->thread_ctx->sc->budget = DEFAULT_BUDGET;
        }

        thread->thread_ctx->kernel_stack_state = KS_FREE;
        /* Set exiting state */
        thread->thread_ctx->thread_exit_state = TE_RUNNING;
        thread->thread_ctx->is_suspended = false;
}
```



## 思考题4

* 创建用户程序至少需要包括创建对应的 `cap_group`、加载用户程序镜像并且切换到程序
* 内核完成必要的初始化之后，调用 `create_root_thread` 函数，跳转到创建第一个用户程序的操作，完成第一个用户进程的创建
  * 从`procmgr`镜像中读取程序信息
  * 调用`create_root_cap_group`创建第一个 `cap_group` 进程
  * 在 `root_cap_group` 中创建第一个线程
* 调用`obj_alloc` 分配全新的 `cap_group` 和 `vmspace` 对象，以创建 `cap_group`
  * 对分配得到的 `cap_group` 对象，调用 `cap_group_init` 函数初始化并且设置必要的参数
  * 对分配得到的 `vmspace` 对象，调用 `cap_alloc` 分配对应的槽（slot）
* 调用`create_root_thread` 函数，进行线程的创建，将用户程序 ELF 的各程序段加载到内存中
* 调用 `init_thread_ctx` 函数，完成线程上下文的初始化，以做好从内核态切换到用户态线程的准备
* 接下来就可以从内核态向用户态进行跳转



## 练习5

```c++
EXPORT(el1_vector)

	/* LAB 3 TODO BEGIN */
	exception_entry sync_el1t
	exception_entry irq_el1t
	exception_entry fiq_el1t
	exception_entry error_el1t

	exception_entry sync_el1h
	exception_entry irq_el1h
	exception_entry fiq_el1h
	exception_entry error_el1h

	exception_entry sync_el0_64
	exception_entry irq_el0_64
	exception_entry fiq_el0_64
	exception_entry error_el0_64

	exception_entry sync_el0_32
	exception_entry irq_el0_32
	exception_entry fiq_el0_32
	exception_entry error_el0_32
	/* LAB 3 TODO END */
    
sync_el1t:
	/* LAB 3 TODO BEGIN */
	bl unexpected_handler
	/* LAB 3 TODO END */

sync_el1h:
	exception_enter
	mov	x0, #SYNC_EL1h
	mrs	x1, esr_el1
	mrs	x2, elr_el1

	/* LAB 3 TODO BEGIN */
	/* jump to handle_entry_c, store the return value as the ELR_EL1 */
	bl handle_entry_c
	str x0, [sp, #16 * 16]
	/* LAB 3 TODO END */
	exception_exit
```



## 练习6

```c++
.macro	exception_enter

	/* LAB 3 TODO BEGIN */
	sub sp, sp, #ARCH_EXEC_CONT_SIZE
	stp x0, x1, [sp, #16 * 0]
	stp x2, x3, [sp, #16 * 1]
	stp x4, x5, [sp, #16 * 2]
	stp x6, x7, [sp, #16 * 3]
	stp x8, x9, [sp, #16 * 4]
	stp x10, x11, [sp, #16 * 5]
	stp x12, x13, [sp, #16 * 6]
	stp x14, x15, [sp, #16 * 7]
	stp x16, x17, [sp, #16 * 8]
	stp x18, x19, [sp, #16 * 9]
	stp x20, x21, [sp, #16 * 10]
	stp x22, x23, [sp, #16 * 11]
	stp x24, x25, [sp, #16 * 12]
	stp x26, x27, [sp, #16 * 13]
	stp x28, x29, [sp, #16 * 14]
	/* LAB 3 TODO END */

	mrs	x21, sp_el0
	mrs	x22, elr_el1
	mrs	x23, spsr_el1

	/* LAB 3 TODO BEGIN */
	stp x30, x21, [sp, #16 * 15]
	stp x22, x23, [sp, #16 * 16]
	/* LAB 3 TODO END */

.endm

.macro	exception_exit

	/* LAB 3 TODO BEGIN */
	ldp x22, x23, [sp, #16 * 16]
	ldp x30, x21, [sp, #16 * 15]
	/* LAB 3 TODO END */

	msr	sp_el0, x21
	msr	elr_el1, x22
	msr	spsr_el1, x23

	/* LAB 3 TODO BEGIN */
	ldp x0, x1, [sp, #16 * 0]
	ldp x2, x3, [sp, #16 * 1]
	ldp x4, x5, [sp, #16 * 2]
	ldp x6, x7, [sp, #16 * 3]
	ldp x8, x9, [sp, #16 * 4]
	ldp x10, x11, [sp, #16 * 5]
	ldp x12, x13, [sp, #16 * 6]
	ldp x14, x15, [sp, #16 * 7]
	ldp x16, x17, [sp, #16 * 8]
	ldp x18, x19, [sp, #16 * 9]
	ldp x20, x21, [sp, #16 * 10]
	ldp x22, x23, [sp, #16 * 11]
	ldp x24, x25, [sp, #16 * 12]
	ldp x26, x27, [sp, #16 * 13]
	ldp x28, x29, [sp, #16 * 14]
	add sp, sp, #ARCH_EXEC_CONT_SIZE
	/* LAB 3 TODO END */

	eret
.endm

.macro switch_to_cpu_stack
	mrs     x24, TPIDR_EL1
	/* LAB 3 TODO BEGIN */
	add x24, x24, #OFFSET_LOCAL_CPU_STACK
	/* LAB 3 TODO END */
	ldr	x24, [x24]
	mov	sp, x24
.endm
```



## 思考题7

* `printf` 函数调用了 `vfprintf`，其中文件描述符参数为 `stdout`。这说明在 `vfprintf` 中将使用 `stdout` 的某些操作函数
* `vfprintf`函数中调用了`stdout`的`write`函数
* 在 `user/chcore-libc/musl-libc/src/stdio/stdout.c`中可以看到 `stdout` 的 `write` 操作被定义为 `__stdout_write`
* `__stdout_write`又调用了 `__stdio_write` 函数
* `__stdio_write`则以`stdout`为文件描述符，调用了系统指令`SYS_writev`，对应于函数`chcore_writev`
* `chcore_write`则通过`fd_dic[fd]->fd_op->write(fd, buf, count)`语句调用到函数`chcore_stdout_write`



## 练习8

```C++
static void put(char buffer[], unsigned size)
{
        /* LAB 3 TODO BEGIN */
        // 调用内核中的函数 sys_putstr
        chcore_syscall2(CHCORE_SYS_putstr, (vaddr_t)buffer, size);
        /* LAB 3 TODO END */
}
```



## 练习9

```C++
#include <stdio.h>

int main() {
    printf("Hello ChCore!\n");
    return 0;
}
```

