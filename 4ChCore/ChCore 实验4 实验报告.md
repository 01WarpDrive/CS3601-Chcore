# ChCore 实验4 实验报告

## 思考题1

1. 选定主CPU
   * `mrs x8, mpidr_el1`：将当前处理器的MPIDR寄存器的值加载到寄存器x8中，其中包含当前处理器的ID信息
   * `and x8, x8, #0xFF`：取处理器ID的最低字节
   * `cbz x8, primary`：如果x8寄存器的值为零（即判断是否为0号CPU），则跳转到标签"primary"，否则继续执行
   * 通过上述判断语句，ChCore选定id为0的主CPU引导初始化
2. 阻塞其它CPU
   * `wait_until_smp_enabled`：进入一个循环，等待SMP启用
   * `cbz x3, wait_until_smp_enabled`：如果x3寄存器的值为零（表示SMP未启用），则继续等待
   * 通过上述判断语句，其它CPU将进入等待SMP启用的循环，从而被阻塞；等待主核完成初始化并设置secondary-boot_flag标志后才继续执行secondary_init_c，进行其他CPU的初始化操作。



## 思考题2

1. `start.S`中的`secondary_boot_flag`是物理地址, 因为 MMU 未启动
2. `init_c.c`中调用`start_kernel(secondary_boot_flag)`传入参数；通过 `main` 函数的参数 `boot_flag` 传入`enable_smp_cores`
3. 在`main.c`中调用`enable_smp_cores(boot_flag)`，`boot_flag` 是smp的boot flag地址，是物理地址；函数`enable_smp_cores`调用`secondary_boot_flag = (long *)phys_to_virt(boot_flag)`转换为虚拟地址后进行赋值



## 练习题1

对每个CPU的就绪队列都进行初始化：queue_head和queue_len；并且进行锁的初始化。

```C++
for (int i = 0; i < PLAT_CPU_NUM; i++) {
        init_list_head(&(rr_ready_queue_meta[i].queue_head));
        rr_ready_queue_meta[i].queue_len = 0;
        lock_init(&rr_ready_queue_meta[i].queue_lock);
}
```



## 练习题2

* 将`thread`插入到`cpuid`对应的就绪队列
* 增加queue_len

```C++
list_append(&(thread->ready_queue_node), &(rr_ready_queue_meta[cpuid].queue_head));
++rr_ready_queue_meta[cpuid].queue_len;
```



## 练习题3

1. 使用 `for_each_in_list`遍历ready_queue_node并找到第一个满足条件的thread，然后终止遍历

   ```C++
   for_each_in_list (thread, struct thread, ready_queue_node, thread_list) {
           if (!thread->thread_ctx->is_suspended && 
           (thread->thread_ctx->kernel_stack_state == KS_FREE || 
           thread == current_thread)) {
                   break;
           }
   }
   ```

   

2. 使用`list_del`删除ready_queue_node并减小相应 `cpuid` 的就绪队列长度

   ```c++
   list_del(&(thread->ready_queue_node));
   --rr_ready_queue_meta[thread->thread_ctx->cpuid].queue_len;
   ```



## 练习题4

1. 在`sys_yield`中调用 sched() 函数

   ```C++
   sched();
   ```

   

2. 将当前正在运行的线程重新加入调度队列中

   ```C++
   rr_sched_enqueue(old);
   ```



## 练习题5

* 根据注释完成相应代码
* 参考上下文，通过类似`asm volatile("mrs %0, cntfrq_el0" : "=r"(cntp_freq));`的指令完成读取
* 参考上下文，通过类似`asm volatile("msr cntp_tval_el0, %0" ::"r"(cntp_tval));`的指令完成写入

```C++
/* LAB 4 TODO BEGIN (exercise 5) */
/* Note: you should add three lines of code. */
/* Read system register cntfrq_el0 to cntp_freq*/
asm volatile("mrs %0, cntfrq_el0" : "=r"(cntp_freq));
/* Calculate the cntp_tval based on TICK_MS and cntp_freq */
cntp_tval = (cntp_freq * TICK_MS / 1000);
/* Write cntp_tval to the system register cntp_tval_el0 */
asm volatile("msr cntp_tval_el0, %0" ::"r"(cntp_tval));
/* LAB 4 TODO END (exercise 5) */

/* LAB 4 TODO BEGIN (exercise 5) */
/* Note: you should add two lines of code. */
/* Calculate the value of timer_ctl */
timer_ctl = 0x1;
/* Write timer_ctl to the control register (cntp_ctl_el0) */
asm volatile("msr cntp_ctl_el0, %0" ::"r"(timer_ctl));
/* LAB 4 TODO END (exercise 5) */
```



## 练习题6

1. 当中断号irq为INT_SRC_TIMER1（代表中断源为物理时钟）时调用`handle_timer_irq`并返回

   ```c++
   switch (irq) {
   /* LAB 4 TODO BEGIN (exercise 6) */
   /* Call handle_timer_irq and return if irq equals INT_SRC_TIMER1 (physical timer) */
   case INT_SRC_TIMER1:
           handle_timer_irq();
           return;
   /* LAB 4 TODO END (exercise 6) */
   ```



2. 根据要求完成：

   ```C++
   // kernel/irq/timer.c
   
   /* LAB 4 TODO BEGIN (exercise 6) */
   /* Decrease the budget of current thread by 1 if current thread is not NULL */
   if (current_thread) {
           --current_thread->thread_ctx->sc->budget;
       	/* Then call sched to trigger scheduling */
   		sched();
   }
   /* LAB 4 TODO END (exercise 6) */
   ```

   

3. 恢复其调度时间片budget为DEFAULT_BUDGET

   ```c++
   old->thread_ctx->sc->budget = DEFAULT_BUDGET;
   ```

   



## 练习题7

1. 在 `connection.h` 中， `declared_ipc_routine_entry ` 和 ` register_cb_thread` 的定义：

   ```c++
   struct ipc_server_config {
   	/* Callback_thread for handling client registration */
   	struct thread *register_cb_thread;
   
   	/* Record the argument from the server thread */
   	unsigned long declared_ipc_routine_entry;
   };
   ```

   结合上下文代码填写：

   ```C++
   config->declared_ipc_routine_entry = ipc_routine;
   config->register_cb_thread = register_cb_thread;
   ```



2. shm字段会记录共享内存相关的信息（包括大小，分别在客户端进程和服务器进程当中的虚拟地址和capability)。结合上下文代码填写：

   ```C++
   conn->shm.client_shm_uaddr = shm_addr_client;
   conn->shm.shm_size = shm_size;
   conn->shm.shm_cap_in_client = shm_cap_client;
   conn->shm.shm_cap_in_server = shm_cap_server;
   ```

   

3. 在`sys_ipc_register_cb_return`函数中得知stack address 和 ip 赋值形式：

   ```c++
   handler_config->ipc_routine_entry =
           arch_get_thread_next_ip(ipc_server_handler_thread);
   handler_config->ipc_routine_stack =
           arch_get_thread_stack(ipc_server_handler_thread);
   ```

   又从`uapi/ipc.h`得知：

   ```C++
    * @param shm_ptr: pointer to start address of IPC shared memory. Use
    * SHM_PTR_TO_CUSTOM_DATA_PTR macro to convert it to concrete custom
    * data pointer.
    * @param max_data_len: length of IPC shared memory.
    * @param send_cap_num: number of capabilites sent by client in this request.
    * @param client_badge: badge of client.
    */
   ```

   因此根据提示填写：

   ```C++
   arch_set_thread_stack(target, handler_config->ipc_routine_stack);
   arch_set_thread_next_ip(target, handler_config->ipc_routine_entry);
   
   /* see server_handler type in uapi/ipc.h */
   arch_set_thread_arg0(target, shm_addr);
   arch_set_thread_arg1(target, shm_size);
   arch_set_thread_arg2(target, cap_num);
   arch_set_thread_arg3(target, conn->client_badge);
   ```

   

4. 同理，在`sys_register_server`函数中得知stack address 和 ip 赋值形式：

   ```C++
       register_cb_config->register_cb_entry =
               arch_get_thread_next_ip(register_cb_thread);
       register_cb_config->register_cb_stack =
               arch_get_thread_stack(register_cb_thread);
   ```

   又在`ipc.c`中理解 `register_cb` 参数的意义：

   ```c++
   void *register_cb(void *ipc_handler)
   {...}
   ```

   从而根据提示填写：

   ```C++
   arch_set_thread_stack(register_cb_thread, register_cb_config->register_cb_stack);
   arch_set_thread_next_ip(register_cb_thread, register_cb_config->register_cb_entry);
   
   arch_set_thread_arg0(register_cb_thread, server_config->declared_ipc_routine_entry);
   ```



5. 根据上下文填写：

   ```C++
   conn->shm.server_shm_uaddr = server_shm_addr;
   ```

