# DataStore1

## Overview

As name suggests, it is a simple data store program where data is saved in form
of a tree - each node can be one of the allowed types. Following is the
important type definitions from the source:

```c
typedef enum {
    TYPE_EMPTY = 0,
    TYPE_ARRAY = 0xfeed0001,
    TYPE_STRING,
    TYPE_UINT,
    TYPE_FLOAT,
} type_t;

typedef struct {
    type_t type;

    union {
        struct Array *p_arr;
        struct String *p_str;
        uint64_t v_uint;
        double v_float;
    };
} data_t;   // size = 0x10

typedef struct Array {
    size_t count;
    data_t data[];
} arr_t;    // size == sizeof(Array) + count * sizeof(data_t) == 8 + count * 0x10

typedef struct String {
    size_t size;
    char *content;
} str_t;
```

The program allows listing and editing the tree. List will recursively print
the entire tree and edit allows updating or freeing nodes. Root node however
cannot be freed.

Two other important things to know about is:
- Remove operation will not return error if the current type is
  invalid/unknown, and always reset type to `TYPE_EMPTY` at the end.
- Edit prints original value of the node it is currently operating on


## Bug

The `edit` operation does the array index check in the following way:

```c
static int edit(data_t *data){
    ...
                printf("index: ");
                unsigned idx = getint();
                if(idx > arr->count)        // [0]
                    return -1;
    ...
}
```

At `[0]`, there is an off-by-one error where the comparison will allow `idx ==
arr->count`, allowing OOB array access.


## Exploit

Overall idea for exploiting the bug is to get allocated chunk of
`String->content` immediately after the `Array` object. Because `Array` object
will always be of size `0x.8`, this means the `data.type` field for `index ==
count` will overlap with size of next chunk and the `data.p_str` will be
overlap with first 8 bytes of content buffer. This gives arbitrary read/write.


Exploitation steps:

1. Start by making a root node as an array
2. Make some string allocations and free them (mainly to avoid any random
   allocation to happen between step 3 and 4)
3. Allocate a new array node `A1` in root array.
4. Allocate a new string `S1` with content length such that it gets allocated
   right after `A1`
5. Remove `index : A1.count` in `A1`. This will fix the type (originally size
   of next chunk - unknown type) to `TYPE_EMPTY`.
6. Allocate new string object in `A1` at `index: A1.count` (overwrite first 8
   bytes of `S1`'s content)
7. Leak heap address
8. Now we can do arbitrary read by modifying `S1->content` to `<S1->content+8>
   <any_large_size> <address_to_read/write>` (craft and point to fake `String`
   object) followed by doing `edit+update` on `A1[A1.count]`.
   - We cannot do read via `list` here because `list` doesn't do OOB access of
     the array, and to preserve old value, we can update with the values we
     just read
9. Remaining exploit is simply to get libc unsorted bin address on heap,
   environ, and overwrite stack for ROP.

Please see [exploit.py](exploit.py) for detailed exploit.
