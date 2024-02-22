# ChCore 实验2 实验报告

## 练习题1

```C++
static struct page *split_chunk(struct phys_mem_pool *pool, int order,
                                struct page *chunk)
{
        /* LAB 2 TODO 1 BEGIN */
        /*
         * Hint: Recursively put the buddy of current chunk into
         * a suitable free list.
         */
        /* BLANK BEGIN */

        // 递归，直到分割出指定order的内存块
        if (chunk->order == order) {
                return chunk;
        }

        // 分割出伙伴块，加入空闲链表
        chunk->order -= 1;
        struct page *buddy_chunk = get_buddy_chunk(pool, chunk);
        if (buddy_chunk != NULL && buddy_chunk->allocated == 0) {
                buddy_chunk->order = chunk->order;
                list_add(&buddy_chunk->node, &(pool->free_lists[buddy_chunk->order].free_list));
                pool->free_lists[buddy_chunk->order].nr_free += 1;
        }

    	return split_chunk(pool, order, chunk);

        /* BLANK END */
        /* LAB 2 TODO 1 END */
}
```

```C++
static struct page *merge_chunk(struct phys_mem_pool *pool, struct page *chunk)
{
        /* LAB 2 TODO 1 BEGIN */
        /*
         * Hint: Recursively merge current chunk with its buddy
         * if possible.
         */
        /* BLANK BEGIN */

        struct page *buddy_chunk = NULL;

        // 合并到最大的order时停止
        if (chunk->order == (BUDDY_MAX_ORDER - 1)) {
                return chunk;
        }

        buddy_chunk = get_buddy_chunk(pool, chunk);
        // 三种无效情况：伙伴块不存在、被占用、层级错误；无法继续合并，退出递归
        if (buddy_chunk == NULL || buddy_chunk->allocated == 1 || buddy_chunk->order != chunk->order) {
                return chunk;
        }

        // 将伙伴块从空闲列表中移除，order增加，实现合并
        list_del(&buddy_chunk->node);
        pool->free_lists[buddy_chunk->order].nr_free -= 1;
        buddy_chunk->order += 1;
        chunk->order += 1;

        // 将chunk地址更新为两个内存块中的低地址
        if (chunk > buddy_chunk) {
                chunk = buddy_chunk;
        }
    
    	return merge_chunk(pool, chunk);

        /* BLANK END */
        /* LAB 2 TODO 1 END */
}
```

```C++
struct page *buddy_get_pages(struct phys_mem_pool *pool, int order)
{
    	// ...
        /* LAB 2 TODO 1 BEGIN */
        /*
         * Hint: Find a chunk that satisfies the order requirement
         * in the free lists, then split it if necessary.
         */
        /* BLANK BEGIN */

        // 找到可分割的空闲块
        cur_order = order;
        while(cur_order < BUDDY_MAX_ORDER && pool->free_lists[cur_order].nr_free == 0) {
                cur_order += 1;
        }

        // 当没有可用空闲块时，先unlock，再返回NULL
        if (cur_order >= BUDDY_MAX_ORDER) {
                unlock(&pool->buddy_lock);
                return NULL;
        }

        // 将空闲块从空闲列表中移除
        free_list = &(pool->free_lists[cur_order].free_list);
        page = list_entry(free_list->next, struct page, node);
        list_del(&page->node);
        pool->free_lists[cur_order].nr_free -= 1;

        // 将分割出的新空闲块标记为占用
        page = split_chunk(pool, order, page);
        page->allocated = 1;

        /* BLANK END */
        /* LAB 2 TODO 1 END */
out:
        unlock(&pool->buddy_lock);
        return page;
}
```

```C++
void buddy_free_pages(struct phys_mem_pool *pool, struct page *page)
{
        int order;
        struct list_head *free_list;

        lock(&pool->buddy_lock);

        /* LAB 2 TODO 1 BEGIN */
        /*
         * Hint: Merge the chunk with its buddy and put it into
         * a suitable free list.
         */
         /* BLANK BEGIN */

        // 标记为空闲
        page->allocated = 0;

        // 获取合并后的内存块，加入空闲链表
        page = merge_chunk(pool, page);
    	order = page->order;
    	free_list = &(pool->free_lists[order].free_list);
        list_add(&page->node, free_list);
        pool->free_lists[order].nr_free += 1;

        /* BLANK END */
        /* LAB 2 TODO 1 END */

        unlock(&pool->buddy_lock);
}
```



## 练习题2

```C++
static void choose_new_current_slab(struct slab_pointer *pool)
{
        /* LAB 2 TODO 2 BEGIN */
        /* Hint: Choose a partial slab to be a new current slab. */
        /* BLANK BEGIN */

        struct list_head *partial_slab_list;
        struct slab_header *partial_slab;

        // 获取partial_slab列表
        partial_slab_list = &(pool->partial_slab_list);
        if (list_empty(partial_slab_list)) {
                pool->current_slab = NULL;
        } else {
                // 选择新的current_slab，并从链表中删除
                partial_slab = (struct slab_header *)list_entry(partial_slab_list->next, struct slab_header, node); // 选择一个partial_slab
                pool->current_slab = partial_slab;
                list_del(partial_slab_list->next);
        }

        /* BLANK END */
        /* LAB 2 TODO 2 END */
}
```

```c++
static void *alloc_in_slab_impl(int order)
{
    	// ...
        /* LAB 2 TODO 2 BEGIN */
        /*
         * Hint: Find a free slot from the free list of current slab.
         * If current slab is full, choose a new slab as the current one.
         */
        /* BLANK BEGIN */

        // 找到第一个空闲slot
        free_list = (struct slab_slot_list *)current_slab->free_list_head;
        BUG_ON(free_list == NULL);
        // 移除该slot
        next_slot = free_list->next_free;
        current_slab->free_list_head = next_slot;
        current_slab->current_free_cnt -= 1;
        // 如果current slab为空，换一个slab
        if (unlikely(current_slab->current_free_cnt == 0)) {
                choose_new_current_slab(&slab_pool[order]);
        }

        /* BLANK END */
        /* LAB 2 TODO 2 END */

        unlock(&slabs_locks[order]);

        return (void *)free_list;
}
```

```c++
void free_in_slab(void *addr)
{
		// ...
        /* LAB 2 TODO 2 BEGIN */
        /*
         * Hint: Free an allocated slot and put it back to the free list.
         */
        /* BLANK BEGIN */

    	slot->next_free = slab->free_list_head; // 将slot插入链表头部
        slab->free_list_head = slot; // 将slot设为slat的空闲链表首部
        ++slab->current_free_cnt; // slab的空闲slot数量加一
    
        /* BLANK END */
        /* LAB 2 TODO 2 END */

        try_return_slab_to_buddy(slab, order);

        unlock(&slabs_locks[order]);
}
```



## 练习题3

```C++
void *_kmalloc(size_t size, bool is_record, size_t *real_size)
{
        void *addr;
        int order;

        if (unlikely(size == 0))
                return ZERO_SIZE_PTR;

        if (size <= SLAB_MAX_SIZE) {
                /* LAB 2 TODO 3 BEGIN */
                /* Step 1: Allocate in slab for small requests. */
                /* BLANK BEGIN */

                addr = alloc_in_slab(size, real_size); // slab分配

                /* BLANK END */
#if ENABLE_MEMORY_USAGE_COLLECTING == ON
                if(is_record && collecting_switch) {
                        record_mem_usage(*real_size, addr);
		}
#endif
        } else {
                /* Step 2: Allocate in buddy for large requests. */
                /* BLANK BEGIN */

                order = size_to_page_order(size); // 根据size计算order
                addr = get_pages(order); // 伙伴系统分配

                /* BLANK END */
                /* LAB 2 TODO 3 END */
        }

        BUG_ON(!addr);
        return addr;
}
```



## 练习题4

```C++
int query_in_pgtbl(void *pgtbl, vaddr_t va, paddr_t *pa, pte_t **entry)
{
        /* LAB 2 TODO 4 BEGIN */
        /*
         * Hint: Walk through each level of page table using `get_next_ptp`,
         * return the pa and pte until a L0/L1 block or page, return
         * `-ENOMAPPING` if the va is not mapped.
         */
        /* BLANK BEGIN */

        ptp_t *l0_ptp, *l1_ptp, *l2_ptp, *l3_ptp; // 各级页表页
        ptp_t *phys_page; // 物理页
        pte_t *pte;
        int ret; // get_next_ptp()返回值

        // 查询 L0 page table
        l0_ptp = (ptp_t *)pgtbl;
        ret = get_next_ptp(l0_ptp, L0, va, &l1_ptp, &pte, false, NULL);
        if (ret == -ENOMAPPING) { // va未建立映射，报错
                return ret;
        }

        // 查询 L1 page table
        ret = get_next_ptp(l1_ptp, L1, va, &l2_ptp, &pte, false, NULL);
        if (ret == -ENOMAPPING) {
                return ret;
        } 
        else if (ret == BLOCK_PTP) {
                if (entry != NULL) {
                        *entry = pte;
                }
                *pa = virt_to_phys(l2_ptp) + GET_VA_OFFSET_L1(va);
                return 0;
        }
        

        // 查询 L2 page table
        ret = get_next_ptp(l2_ptp, L2, va, &l3_ptp, &pte, false, NULL);
        if (ret == -ENOMAPPING) {
                return ret;
        }
        else if (ret == BLOCK_PTP) {
                if (entry != NULL) {
                        *entry = pte;
                }
                *pa = virt_to_phys(l3_ptp) + GET_VA_OFFSET_L2(va);
                return 0;
        }

        // 查询 L3 page table
        ret = get_next_ptp(l3_ptp, L3, va, &phys_page, &pte, false, NULL);
        if (ret == -ENOMAPPING) {
                return ret;
        }
        if (entry != NULL) {
                *entry = pte;
        }

        // 计算并返回pa、pte
        *pa = virt_to_phys((vaddr_t)phys_page) + GET_VA_OFFSET_L3(va);

        /* BLANK END */
        /* LAB 2 TODO 4 END */
        return 0;
}
```

```c++
static int map_range_in_pgtbl_common(void *pgtbl, vaddr_t va, paddr_t pa, size_t len,
                       vmr_prop_t flags, int kind, long *rss)
{
        /* LAB 2 TODO 4 BEGIN */
        /*
         * Hint: Walk through each level of page table using `get_next_ptp`,
         * create new page table page if necessary, fill in the final level
         * pte with the help of `set_pte_flags`. Iterate until all pages are
         * mapped.
         * Since we are adding new mappings, there is no need to flush TLBs.
         * Return 0 on success.
         */
        /* BLANK BEGIN */

        s64 total_page_cnt;
        ptp_t *l0_ptp, *l1_ptp, *l2_ptp, *l3_ptp; // 各级页表页
        pte_t *pte;
        int ret; // get_next_ptp()返回值
        int pte_index; // 最后一级页表的pte index
        int i;

        BUG_ON(pgtbl == NULL);
        BUG_ON(va % PAGE_SIZE);
        total_page_cnt = len / PAGE_SIZE + (((len % PAGE_SIZE) > 0) ? 1 : 0);

        l0_ptp = (ptp_t *)pgtbl;
        l1_ptp = NULL;
        l2_ptp = NULL;
        l3_ptp = NULL;

        while (total_page_cnt > 0)
        {       
                // 依次建立各级页表页（L3除外）中对应的映射，get_next_ptp自动分配
                // l0
                ret = get_next_ptp(l0_ptp, L0, va, &l1_ptp, &pte, true, rss);
                // l1
                ret = get_next_ptp(l1_ptp, L1, va, &l2_ptp, &pte, true, rss);
                // l2
                ret = get_next_ptp(l2_ptp, L2, va, &l3_ptp, &pte, true, rss);
                BUG_ON(ret != 0);
                // l3: 获取pte的index,设置属性
                pte_index = GET_L3_INDEX(va);
                for (i = pte_index; i < PTP_ENTRIES; ++i) {
                        pte_t new_pte_val;
                        new_pte_val.pte = 0;
                        new_pte_val.l3_page.is_valid = 1;
                        new_pte_val.l3_page.is_page = 1;
                        new_pte_val.l3_page.pfn = pa >> PAGE_SHIFT;
                        set_pte_flags(&new_pte_val, flags, kind);
                        l3_ptp->ent[i].pte = new_pte_val.pte;

                        va += PAGE_SIZE;
                        pa += PAGE_SIZE;
                        if (rss) {
                                *rss += PAGE_SIZE;
                        }
                        total_page_cnt--;
                        if (total_page_cnt == 0) {
                                break;
                        }
                }
        }       

        /* BLANK END */
        /* LAB 2 TODO 4 END */
        return 0;
}
```

```c++
int unmap_range_in_pgtbl(void *pgtbl, vaddr_t va, size_t len, long *rss)
{
        /* LAB 2 TODO 4 BEGIN */
        /*
         * Hint: Walk through each level of page table using `get_next_ptp`,
         * mark the final level pte as invalid. Iterate until all pages are
         * unmapped.
         * You don't need to flush tlb here since tlb is now flushed after
         * this function is called.
         * Return 0 on success.
         */
        /* BLANK BEGIN */

        s64 total_page_cnt;
        ptp_t *l0_ptp, *l1_ptp, *l2_ptp, *l3_ptp; // 各级页表页
        pte_t *pte;
        int ret; // get_next_ptp()返回值
        int pte_index; // 最后一级页表的pte index
        int i;

        BUG_ON(pgtbl == NULL);
        BUG_ON(va % PAGE_SIZE);
        total_page_cnt = len / PAGE_SIZE + (((len % PAGE_SIZE) > 0) ? 1 : 0);

        l0_ptp = (ptp_t *)pgtbl;
        l1_ptp = NULL;
        l2_ptp = NULL;
        l3_ptp = NULL;

        while (total_page_cnt > 0)
        {       
                // 依次查询各级页表页（L3除外）中对应的映射
                ret = get_next_ptp(l0_ptp, L0, va, &l1_ptp, &pte, false, rss);
                ret = get_next_ptp(l1_ptp, L1, va, &l2_ptp, &pte, false, rss);
                ret = get_next_ptp(l2_ptp, L2, va, &l3_ptp, &pte, false, rss);
				BUG_ON(ret != 0);
                // l3: 获取pte的index,设置为invalid
                pte_index = GET_L3_INDEX(va);
                for (i = pte_index; i < PTP_ENTRIES; ++i) {
                        l3_ptp->ent[i].l3_page.is_valid = 0;
                        va += PAGE_SIZE;
                        total_page_cnt--;
                        if (total_page_cnt == 0) {
                                break;
                        }
                }
        }

        /* BLANK END */
        /* LAB 2 TODO 4 END */

        dsb(ishst);
        isb();

        return 0;
}
```

```c++
int mprotect_in_pgtbl(void *pgtbl, vaddr_t va, size_t len, vmr_prop_t flags)
{
        /* LAB 2 TODO 4 BEGIN */
        /*
         * Hint: Walk through each level of page table using `get_next_ptp`,
         * modify the permission in the final level pte using `set_pte_flags`.
         * The `kind` argument of `set_pte_flags` should always be `USER_PTE`.
         * Return 0 on success.
         */
        /* BLANK BEGIN */

        s64 total_page_cnt;
        ptp_t *l0_ptp, *l1_ptp, *l2_ptp, *l3_ptp; // 各级页表页
        pte_t *pte;
        int ret; // get_next_ptp()返回值
        int pte_index; // 最后一级页表的pte index
        int i;

        BUG_ON(pgtbl == NULL);
        BUG_ON(va % PAGE_SIZE);
        total_page_cnt = len / PAGE_SIZE + (((len % PAGE_SIZE) > 0) ? 1 : 0);

        l0_ptp = (ptp_t *)pgtbl;
        l1_ptp = NULL;
        l2_ptp = NULL;
        l3_ptp = NULL;

        while (total_page_cnt > 0)
        {       
                // 依次查询各级页表页（L3除外）中对应的映射
                ret = get_next_ptp(l0_ptp, L0, va, &l1_ptp, &pte, false, NULL);
                ret = get_next_ptp(l1_ptp, L1, va, &l2_ptp, &pte, false, NULL);
                ret = get_next_ptp(l2_ptp, L2, va, &l3_ptp, &pte, false, NULL);
                BUG_ON(ret != 0);
                // l3: 获取pte的index，修改权限
                pte_index = GET_L3_INDEX(va);
                for (i = pte_index; i < PTP_ENTRIES; ++i) {
                        set_pte_flags(&(l3_ptp->ent[i]), flags, USER_PTE);
                        va += PAGE_SIZE;
                        total_page_cnt--;
                        if (total_page_cnt == 0) {
                                break;
                        }
                }
        }       

        /* BLANK END */
        /* LAB 2 TODO 4 END */
        return 0;
}
```



## 思考题5

* 需要配置页表描述符的哪个/哪些字段：
  * **访问权限位（Access Permissions）**：在写时拷贝中，需要将写权限设置为只读。当有写操作发生时，会触发一个页错误异常。
* 发生页错误时如何处理：
  * **捕获页错误异常**：发生写时拷贝时，会触发一个页错误异常，操作系统捕获这个异常。
  * **识别导致异常的地址**：处理页错误异常时，需要确定哪个地址触发了异常，以便后续的处理。
  * **检查页表项**：在页错误处理程序中，需要检查相应的页表项，确保它们被正确设置以支持写时拷贝。
  * **进行拷贝操作**：如果检测到写时拷贝的情况，需要在合适的时机进行页面的拷贝操作，以确保进程不会影响共享的页面。
  * **更新页表项**：在进行拷贝操作后，可能需要更新相应的页表项，确保它们正确地映射到新的页面。
  * **恢复原始权限**：一旦拷贝完成，可能需要将相应页面的访问权限恢复到原始状态，以允许进程继续写入。



## 思考题6

* **内存浪费**：粗粒度页表将大块物理内存映射到地址空间中，可能导致内存空间浪费。
* **性能低下**：粗粒度可能导致TLB命中率降低，增加页表查找开销，降低性能。
* **灵活性降低**：粗粒度页表可能会限制了对虚拟内存的高级管理策略的实施，如内存分页、页面置换等。



## 练习题8

```c++
/* LAB 2 TODO 5 BEGIN */
/* BLANK BEGIN */

ret = handle_trans_fault(current_thread->vmspace, fault_addr);

/* BLANK END */
/* LAB 2 TODO 5 END */
```



## 练习题9

```C++
struct vmregion *find_vmr_for_va(struct vmspace *vmspace, vaddr_t addr)
{
        /* LAB 2 TODO 6 BEGIN */
        /* Hint: Find the corresponding vmr for @addr in @vmspace */
        /* BLANK BEGIN */

        struct vmregion *vmr;
        struct rb_node *node;

        // 查找va所在的vmr
        node = rb_search(
                &vmspace->vmr_tree, (const void *)addr, cmp_vmr_and_va);

        if (node == NULL) { // 若没找到，返回NULL
                return NULL;
        } else { // 返回vmr
                vmr = rb_entry(node, struct vmregion, tree_node);
                return vmr;
        }

        /* BLANK END */
        /* LAB 2 TODO 6 END */
}
```



## 练习题10

```c++
/* LAB 2 TODO 7 BEGIN */
/* BLANK BEGIN */
/* Hint: Allocate a physical page and clear it to 0. */

// 分配物理页
vaddr_t kva = (vaddr_t)get_pages(0);
BUG_ON(kva == 0);
// 获取物理地址
pa = virt_to_phys((void *)kva);
// 清零
memset((void *)kva, 0, PAGE_SIZE);

/* BLANK END */
/*
 * Record the physical page in the radix tree:
 * the offset is used as index in the radix tree
 */
```

```c++
/* BLANK BEGIN */

// 添加映射
ret = map_range_in_pgtbl(vmspace->pgtbl, fault_addr, pa, PAGE_SIZE, perm, &rss);
BUG_ON(ret != 0);

/* BLANK END */
```

```c++
/* BLANK BEGIN */

// 增加映射
ret = map_range_in_pgtbl(vmspace->pgtbl, fault_addr, pa, PAGE_SIZE, perm, &rss);
BUG_ON(ret != 0);

/* BLANK END */
/* LAB 2 TODO 7 END */
```



