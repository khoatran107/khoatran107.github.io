---
layout: post
title: Cross-cache attacks against SLUB's new sheaf/barn mechanism in Linux 7.1
mermaid: true
date: 2026-06-27 00:51 +0700
categories: [Linux Kernel]
tags: [linux, kernel]
description: How Linux 7.1's SLUB sheaf/barn caching changes cross-cache attacks, with a working strategy to free the victim slab page.
---
## Introduction

The new sheaf/barn mechanism of the SLUB allocator is merged into the Linux Kernel in version 6.18, for performance reasons. And as a result, the strategy of doing cross-cache attack also changes. That means, CROSS-X[<sup>[1]</sup>](https://kaist-hacking.github.io/pubs/2025/kim:crossx.pdf) - the paper I had waited for 3 months, becomes irrelevant after just several months, so sad. Cross-cache exploiting the new mechanism requires less computations (due to the removal of per-CPU partial list), but is harder (possibly impossible) to stabilize based on a timing side-channel.

It's an obstacle I encountered when trying to exploit a 0-day on the 7.0.10 kernel (blog will be published after the patch is merged). Just as I was about to finish my exploit, something was off: `cpu_partial` of `TCP` cache being 0. I searched for a bit and realized the situation. In the exploit development process, I utilized kernel-hack-drill[<sup>[2]</sup>](https://github.com/a13xp0p0v/kernel-hack-drill) to isolate the primitive and really accelerate the process of finding an effective strategy.

I haven't seen any posts that's specifically about doing cross-cache on sheaf/barn, so I decided I have to write one myself. 

Before moving on, I recommend reading one Linternals post of sam4k[<sup>[3]</sup>](https://sam4k.com/linternals-memory-allocators-0x02/) to grab the basics on the old implementation of SLUB allocator first, as I only discuss the changes and will not explain old terms.

## Motivation & timeline
For a while, the SLUB allocator is fairly stable, and remains the main allocator used by almost every server and desktop distributions nowadays.

The main motivation for new caching mechanism is too much cross-CPU locking behaviors in the old SLUB allocator. Adding a new caching layer reduces the frequency of direct interaction with the complex slab data structure. It's also better from caching perspective, as the returned object is the "hottest" object in cache, so TLB or CPU data cache works pretty fast. The details can be found in the newsletter [<sup>[4]</sup>](https://lwn.net/Articles/1010667/).

For the development timeline, this thing dated back to November 2024, started by Babka from OpenSUSE[<sup>[5]</sup>](https://lore.kernel.org/all/20241112-slub-percpu-caches-v1-0-ddc0bdc27e05@suse.cz/). It is merged into Linux kernel version 6.18, on November 30th, 2025[<sup>[6]</sup>](https://www.kernel.org/pub/linux/kernel/v6.x/ChangeLog-6.18). And then the whole per-CPU partial slab is completely removed and merged into kernel 7.0, on April 12th, 2026[<sup>[7]</sup>](https://www.kernel.org/pub/linux/kernel/v7.x/ChangeLog-7.0).

## Mechanism
From this section, I will use the 7.1 source code[<sup>[8]</sup>](https://github.com/torvalds/linux/releases/tag/v7.1).

As of kernel 7.1, both the active slab and the per-CPU partial list are removed.

Instead, we have another layer of cache built on top of the slab layer: sheaves. Each CPU has one main sheaf.

```c
struct slab_sheaf {
	union {
		struct rcu_head rcu_head;
		struct list_head barn_list;
		/* only used for prefilled sheafs */
		struct {
			unsigned int capacity;
			bool pfmemalloc;
		};
	};
	struct kmem_cache *cache;
	unsigned int size;   // <--- important
	int node; /* only used for rcu_sheaf */
	void *objects[];     // <--- important
};
```
The two most important fields of a `slab_sheaf` are `size` and `objects`:
* `size` shows how many objects are available for allocating in this sheaf
* `objects` is an array of **raw** object pointers, allocated by `refill_sheaf`, which calls & takes objects from the partial slab list below. 
    * when allocating, just return `objects[size-1]; size--`, 
    * when freeing, assign `objects[size++] = obj`.

One more thing to note. There is a difference in managing freed object in sheaf versus in partial slab list:
* In sheaves: 
    * We manage objects as raw pointer in sheaves, there is no `next` pointer in the middle of a freed object. 
    * Freed object in sheaf is still marked as **used** in its slab, and it is only returned to the slab under some circumstances.
* In slab: still have the next pointer at offset `kmem_cache::offset` inside freed object.

Structures and relationships, tl;dr: the whole sheaf/barn is a layer above the slab layer.

```
A slab cache (kmem_cache)
  Per cpu (slub_percpu_sheaves): have these slab_sheaf
    - main: always non-null when unlocked, have [obj0, obj1... objN]
    - spare: nullable
    - rcu_free: nullable

  Per node (kmem_cache_per_node_ptrs):
    - node_barn
        + sheaves_full: linked list of sheaves having all freed objects, maximum MAX_FULL_SHEAVES elements
        + sheaves_empty: linked list of sheaves having no freed objects, maximum MAX_EMPTY_SHEAVES elements

    - kmem_cache_node
        + partial: partial list
```

Moving on is the allocation and deallocation paths. The core principle is trying the upper layer first, only move down when there's no other way.

A little revision of old version's paths, where we still have `c->freelist`, `c->slab`, `c->partial`

![i7pmg3](/assets/img/cross-cache-attacks-slub-sheaf-barn-mechanism-linux-7-1/i7pmg3.png)
*From CROSS-X: Allocation and deallocation paths of the SLUB allocator in kernel <= 6.6*

New version's allocation path:
![7.1 allocate](/assets/img/cross-cache-attacks-slub-sheaf-barn-mechanism-linux-7-1/7.1_allocate.svg)
*Allocation path in kernel 7.1 (`kmalloc()` → `slab_alloc_node()` → `alloc_from_pcs()`). Made by me; [draw.io source here](https://drive.google.com/file/d/1zrE03sKH3ymogBUoPdopc_NxkkYyWAr-/view?usp=sharing).*


New version's deallocation path:
![7.1 free](/assets/img/cross-cache-attacks-slub-sheaf-barn-mechanism-linux-7-1/7.1_free.svg)
*Deallocation path in kernel 7.1 (`kfree()` → `slab_free()` → `free_to_pcs()`); the `(**)` flush to the slab layer is the only way down. Made by me; [draw.io source here](https://drive.google.com/file/d/1fefgnzBkXc1xH0TQbMZOVbS689FJnnNM/view?usp=sharing).*

Essentially, we change the unit of caching from slab pages to objects, and reduce some state manipulation related to slabs. 

## Cross-cache strategy
The main point of "cross-cache" strategy boils down to two problems:
- how to free the slab page containing the UAF-object.
- how to starve the cache of the target object so it takes new page from page allocator.

The second one is easier than the first one.

So from there, naturally we want to know some values when looking at a cache:

| Attribute | Value | kmalloc-128 |
|---|---|---|
| Max number of objects per slab | `/sys/kernel/slab/<slab>/objs_per_slab` | 32 |
| Max number of objects per sheaf | `/sys/kernel/slab/<slab>/sheaf_capacity`  | 60 |
| Max number of sheaves per barn | `MAX_FULL_SHEAVES` = `MAX_EMPTY_SHEAVES` = 10 | 10 |
| min_partial | `/sys/kernel/slab/<slab>/min_partial` | 5 |
| page order | `/proc/slabinfo` | 0 |

### Freeing slab page

#### The invariant
A slab page returns to the page allocator at exactly one place - the discard condition in `__slab_free`[<sup>[9]</sup>](https://elixir.bootlin.com/linux/v7.1/source/mm/slub.c#L5587) (and the equivalent bulk path at L7168[<sup>[10]</sup>](https://elixir.bootlin.com/linux/v7.1/source/mm/slub.c#L7168)):

```c
if (unlikely(!slab->inuse && n->nr_partial >= s->min_partial))
    goto slab_empty; /* discard */
```

So at the moment the victim slab loses its last object, the following two must hold:
* **Condition 1**. `slab->inuse == 0`: the victim slab must be fully attacker-owned - all `objs_per_slab` slots are ours and we free them all.
* **Condition 2**. `n->nr_partial >= s->min_partial`: there are already at least `min_partial` other partial slabs.

Everything in this section is just the work of making those two conditions true at the same time.

#### Getting an object down to the slab layer

There's a catch before we even reach `__slab_free`: a freed object normally stops at the sheaf layer and never touches the slab. The *only* free path that pushes objects back down to the slab is the flush at (**)[<sup>[11]</sup>](https://elixir.bootlin.com/linux/v7.1/source/mm/slub.c#L5729), which fires when all three hold:

* main sheaf is full,
* spare sheaf is full,
* the node barn's `sheaves_full` is **saturated** (already holds `MAX_FULL_SHEAVES`, so it can't accept the full main being pushed down) - the `-E2BIG` case in `barn_replace_full_sheaf`.

(Here a sheaf being "full" means *full of freed objects*)

When (**) fires:
* slab-level free all objects in the spare sheaf (bulk free, per-sheaf granularity),
* main = the now-empty spare,
* spare = old full main,
* put the new object in the new main.

Flushing is therefore *per-sheaf*: a whole spare sheaf is bulk-freed at once, never a single object.

#### Fresh-boot worked example (ideal environment)

On a clean boot (empty barn, empty main/spare, `nr_partial == 0`) you can count exactly. 

Allocate a lot, drain the full sheaves so `sheaves_full` empties and `sheaves_empty` fills, then start freeing: each full sheaf you push down is `sheaf_capacity` objects, and you need `MAX_FULL_SHEAVES` of them plus main and spare to reach the flush - roughly `sheaf_capacity * (MAX_FULL_SHEAVES + 2)` freed objects. Build `min_partial` partial slabs for condition 2, free a fully-owned victim slab, and it discards.

This is the picture my first version used.

#### Live-kernel reality

On a non-fresh kernel, condition 1 is hard if we do exact count like before. Existing partial slabs have free slots owned by other subsystems, so a fresh allocation cluster can land in them and the victim slab ends up holding foreign objects. Defrag first to push onto fresh slabs. Also, the last flushing step have to be a little generous, over-flush it to make sure the victim's slab is completely free. 

#### Final strategy

Every "free" step below consumes objects we must have allocated first, so the plan splits into an allocate-first **prepare** phase and a **execute** (free) phase. Order matters: the defrag and the pools must all be allocated before the victim cluster, so that the pre-existing sheaf, barn, and partial-slab free slots are drained first and the victim lands on fresh, fully-owned slabs. The allocation order is: defrag → partial-seed pool → saturation pool → victim cluster → flush pool.

**Prepare (allocate):**
- Step 0 - Defrag: spray `GUESSED_NR_PARTIAL * objs_per_slab` allocations (kept allocated) to fill the free slots of existing partial slabs (be generous to cover all of them). On its own this isn't enough on a non-fresh kernel - allocations are served from the main sheaf, then the barn, then the partial list - but the large Step 1 saturation pool that follows drains that pre-existing sheaf and barn. Together, the defrag and that pool exhaust every old free slot before the victim cluster is allocated, so the victim lands on fresh, fully-owned slabs.
- Step 1 - Pools we free later: allocate the partial-seed pool and the saturation (barn) pool - at least `sheaf_capacity * (MAX_FULL_SHEAVES + 2)` (the `+2` for main and spare) - *before* the victim cluster, then allocate the flush pool *after* it (be generous to make sure we flush the sheaf containing our victim and its same-slab friends). Keep all allocated.
- Step 2 - Victim cluster: allocate `pre`, victim, `post` (each `objs_per_slab` wide) consecutively so the victim slab is entirely ours, sandwiched between the pools above. Keep them allocated for now - we only free them in the execute phase.

**Execute (free):**
- Step 3 - Seed partial list (conditional): if the target cache is rarely exercised - only hit by specific syscalls - `nr_partial` may sit below `min_partial`, so seed `min_partial` partial slabs. Skippable on a live kernel where the cache is used frequently and `nr_partial >= min_partial` already holds.
- Step 4 - Saturate: free from the pool past `sheaf_capacity * (MAX_FULL_SHEAVES + 2)` to fill `sheaves_full` + main + spare and enter the slab-flush mode (`-E2BIG`).
- Step 5 - Free the victim cluster: free `pre`, victim, `post`. Their objects enter the active sheaf, and since the barn is already saturated, each further free flushes a full spare sheaf down to the slab.
- Step 6 - Flush: keep freeing the rest of the pool generously to drive the sheaves holding victim objects through the flush, so the victim slab reaches `inuse == 0` and discards.


Note: the defrag allocations (Step 0) don't have to be dead weight. They are already allocated on attacker-owned slabs, so you can recycle them as the partial-list seed (Step 3) and/or the flush pool (Step 6) instead of allocating separate pools - just free them at the right moment. This trims the total allocation count.


### Starving target cache
This is easy, just make sure the target cache's slab page is the same order as the victim's, and spray a bunch of objects. If the primitive is read-after-free, maybe we can reclaim using Page Spray techniques[<sup>[15]</sup>](https://www.usenix.org/conference/usenixsecurity24/presentation/guo-ziyi).

## Simulation in kernel-hack-drill
To simulate my primitive, and to make it easier to demonstrate, I modify `kernel-hack-drill` a bit to use a dedicated cache, simulating a `TCP` cache I was exploiting. I also take representative `kmalloc-x` caches based on default values in `calculate_sheaf_capacity`: 4, 12, 26, 60; the corresponding caches are `kmalloc-4k`, `kmalloc-1k`, `kmalloc-256`, and `kmalloc-128`.

The strategy has been tested on those 5 caches and all succeed in freeing the victim page. The cache parameters (`SHEAF_CAPACITY`, `OBJS_PER_SLAB`, `MIN_PARTIAL`) live in `/sys/kernel/slab/<cache>/`, read them once from your debug VM. 

| Cache | ALLOC_SIZE | SHEAF_CAPACITY | OBJS_PER_SLAB | MIN_PARTIAL | Page order |
|---|---|---|---|---|---|
| kmalloc-128 | 128 | 60 | 32 | 5 | 0 |
| kmalloc-256 | 256 | 28 | 16 | 5 | 0 |
| kmalloc-1k | 1024 | 12 | 16 | 5 | 2 |
| kmalloc-4k | 4096 | 4 | 8 | 6 | 3 |
| drill_item | 0x940 | 12 | 13 | 5 | 3 |

The demo code and setup is available at khoatran107/sheaf-barn-exploit[<sup>[12]</sup>](https://github.com/khoatran107/sheaf-barn-exploit). Here I only verify the deallocation of slab page by attaching GDB and check page allocator. A better approach to collect data would be:
* develop a different kernel module mirroring the drill_mod, but with different cache.
* reclaim the freed page.
* use the write-after-free primitive of the UAF-object to write signature to the new object.
* scan the signature in the new object.
* run the above 1000 times and measure success rate.

Note that kernel version 7.1 moves the `node_barn` out of `kmem_cache_node`, compared to version 7.0.10, so the current `bata24/gef` doesn't work when scanning per-node's `sheaves_full`. I use Opus 4.8 to fix that and upload to gef.py[<sup>[13]</sup>](https://gitlab.com/-/snippets/6003422). Replace the file `~/.gef/gef.py` with my file for better debugging experience.

## Real-world exploits
I've tested this method on several 1-days and successfully escalated from an unprivileged user to root. The vulns are known and patched but not merged into the main kernel tree, so I'm not comfortable releasing them. This will make another part of this blog, where I measure success rate of the exploits and the simulation above.

## (Trying to) Stabilize exploits
For live machines, we don't have a clean cache when we run our exploit, and we don't know the current state of heap caches. `SLUBStick`[<sup>[14]</sup>](https://lukasmaar.github.io/publications/usenix24-slubstick.pdf) was a good candidate and I thought a great method for this new mechanism.

For quick note, the final goal of `SLUBStick` is to have a trusty list of `slabs[n_slabs][objs_per_slab]` to do slab list manip on. The real idea of it, is using a `measurement primitive` - a syscall that does both alloc + free, and measure its execution time. From that, we know iterations that take longer invoke allocating new slab, mark that as the `start`, for next long iteration, we check if `cur - start == objs_per_slab`. If that's incorrect, just mark start = cur, and continue. For example, if our cache's `objs_per_slab` is 28, but our timing side-channel tells us the distance between two bumps being 27, it's fair to say some IRQ has triggered and slip into our victim cache, and we can't fully free that slab page. If it's correct, add it to a list of slab we have complete control over.
```c
for (..) {
    alloc_object();
    start_time = get_time();
    call_probe() // do allocation + deallocation in our target cache in one call
    end_time = get_time();
}
```

However, it was developed on kernel 6.2, and in the new kernel 7.1, all measurement primitives were changed and became unusable.

I did try to modify a measurement primitive `add_key`, with a different config, and can use it on `kmalloc-256`. 

The breaking point is that: we can only detect new sheaf. Knowing a bunch of objects was on the same sheaf doesn't help anything with exploitation. Because now, despite how old was the object's original sheaf, the object is still put into active sheaf, not the original one. So I personally think the idea of timing side-channel for stabilizing cross-cache attack is doomed from now on. RIP `SLUBStick`. 

## Final words
One more thing: sheaves store raw pointers inside `struct slab_sheaf`. And depending on the size of the object, its sheaf can be in one of the following 4 caches:

| Served cache `s->size` | Initial capacity | Raw sheaf size | Rounded kmalloc cache | Final capacity |
|---|---:|---|---|---:|
| `< 256` | 60 | `32 + 60*8 = 512` | `kmalloc-512` | 60 |
| `>= 256 && < 1024` | 26 | `32 + 26*8 = 240` | `kmalloc-256` | 28 |
| `>= 1024 && < PAGE_SIZE` | 12 | `32 + 12*8 = 128` | `kmalloc-128` | 12 |
| `>= PAGE_SIZE` | 4 | `32 + 4*8 = 64` | `kmalloc-64` | 4 |

So if there was a write-after-free primitive at offset >= 32, this may be turned into some sort of "sheaf poisoning", or `Dirty Sheaf`. But, I don't think that can be used to spray, as `MAX_FULL_SHEAVES` is too small to do any spraying. But (again), maybe other people can think of better ideas. I haven't done experiments on this as it's out of scope in this post.

Since the mechanism is still new, I expect some paper about exploiting this in USENIX 2027 or ACM CCS 2027, from KAIST maybe.

## References

1. [CROSS-X: Generalized and Stable Cross-Cache Attack on the Linux Kernel](https://kaist-hacking.github.io/pubs/2025/kim:crossx.pdf)
2. [kernel-hack-drill](https://github.com/a13xp0p0v/kernel-hack-drill)
3. [Linternals: The Slab Allocator](https://sam4k.com/linternals-memory-allocators-0x02/)
4. [Slabs, sheaves, and barns](https://lwn.net/Articles/1010667/)
5. [[PATCH RFC 0/6] SLUB percpu sheaves](https://lore.kernel.org/all/20241112-slub-percpu-caches-v1-0-ddc0bdc27e05@suse.cz/)
6. [ChangeLog-6.18](https://www.kernel.org/pub/linux/kernel/v6.x/ChangeLog-6.18)
7. [ChangeLog-7.0](https://www.kernel.org/pub/linux/kernel/v7.x/ChangeLog-7.0)
8. [Linux v7.1 source release](https://github.com/torvalds/linux/releases/tag/v7.1)
9. [mm/slub.c#L5587 - __slab_free discard condition](https://elixir.bootlin.com/linux/v7.1/source/mm/slub.c#L5587)
10. [mm/slub.c#L7168 - bulk free path](https://elixir.bootlin.com/linux/v7.1/source/mm/slub.c#L7168)
11. [mm/slub.c#L5729 - sheaf flush path](https://elixir.bootlin.com/linux/v7.1/source/mm/slub.c#L5729)
12. [khoatran107/sheaf-barn-exploit](https://github.com/khoatran107/sheaf-barn-exploit)
13. [gef.py snippet](https://gitlab.com/-/snippets/6003422)
14. [SLUBStick: Arbitrary Memory Writing through Practical Software Cross-Cache Attacks within the Linux Kernel](https://lukasmaar.github.io/publications/usenix24-slubstick.pdf)
15. [Take a Step Further: Understanding Page Spray in Linux Kernel Exploitation](https://www.usenix.org/conference/usenixsecurity24/presentation/guo-ziyi)
