#include <stdio.h>

#include "disarm64.h"

int main(int argc, char** argv)
{
    DA64_Opcode opcode = { 0 };
    char buf[2048] = { 0 };

    const int instructions[] = {
        0xaa0003e2, //  orr		x2, xzr, x0
        0xf100403f, //  subs		xzr, x1, #0x10
        0x540000a8, //  b.hi 		0x1000008dc
        0xeb02003f, //  subs		xzr, x1, x2
        0x54000068, //  b.hi 		0x1000008dc
        0xaa0203e0, //  orr		x0, xzr, x2
        0x1407816f, //  b		0x1001e0e94
        0x52b00008, //  movz		w8, #0x8000, lsl #0x10
        0xeb08003f, //  subs		xzr, x1, x8
        0x54000069, //  b.ls 		0x1000008f0
        0xd2800000, //  movz		x0, #0x0, lsl #0x0
        0xd65f03c0, //  ret		x30
        0xd10083ff, //  sub		sp, sp, #0x20
        0xa9017bfd, //  stp		x29, x30, [sp, #16]
        0x910043fd, //  add		x29, sp, #0x10
        0xf90007ff, //  str		xzr, [sp, #0x8]
        0x52800108, //  movz		w8, #0x8, lsl #0x0
        0xf100203f, //  subs		xzr, x1, #0x8
        0x9a888021, //  csel		x1, x1, x8, hi
        0x910023e0, //  add		x0, sp, #0x8
        0x94078185, //  bl		0x1001e0f24
        0xf94007e8, //  ldr		x8, [sp, #0x8]
        0x7100001f, //  subs		wzr, w0, #0x0
        0x9a9f0100, //  csel		x0, x8, xzr, eq
        0xa9417bfd, //  ldp		x29, x30, [sp, #16]
        0x910083ff, //  add		sp, sp, #0x20
        0xd65f03c0, //  ret		x30
        0xf100405f, //  subs		xzr, x2, #0x10
        0x540000a8, //  b.hi 		0x100000944
        0xeb03005f, //  subs		xzr, x2, x3
        0x54000068, //  b.hi 		0x100000944
        0xaa0303e1, //  orr		x1, xzr, x3
        0x140781a9, //  b		0x1001e0fe4
        0x52b00008, //  movz		w8, #0x8000, lsl #0x10
        0xeb08005f, //  subs		xzr, x2, x8
        0x54000069, //  b.ls 		0x100000958
        0xd2800000, //  movz		x0, #0x0, lsl #0x0
        0xd65f03c0, //  ret		x30
        0xd10103ff, //  sub		sp, sp, #0x40
        0xa90157f6, //  stp		x22, x21, [sp, #16]
        0xa9024ff4, //  stp		x20, x19, [sp, #32]
        0xa9037bfd, //  stp		x29, x30, [sp, #48]
        0x9100c3fd, //  add		x29, sp, #0x30
        0xaa0103f5, //  orr		x21, xzr, x1
        0xaa0003f4, //  orr		x20, xzr, x0
        0xf90007ff, //  str		xzr, [sp, #0x8]
        0x52800108, //  movz		w8, #0x8, lsl #0x0
        0xf100205f, //  subs		xzr, x2, #0x8
        0x9a888041, //  csel		x1, x2, x8, hi
        0x910023e0, //  add		x0, sp, #0x8
        0xaa0303f6, //  orr		x22, xzr, x3
        0xaa0303e2, //  orr		x2, xzr, x3
        0x94078165, //  bl		0x1001e0f24
        0xaa0003e8, //  orr		x8, xzr, x0
        0xd2800000, //  movz		x0, #0x0, lsl #0x0
        0x35000168, //  cbnz		w8, 0x1000009c8
        0xf94007f3, //  ldr		x19, [sp, #0x8]
        0xb4000133, //  cbz		x19, 0x1000009c8
        0xeb1502df, //  subs		xzr, x22, x21
        0x9a9532c2, //  csel		x2, x22, x21, cc
        0xaa1303e0, //  orr		x0, xzr, x19
        0xaa1403e1, //  orr		x1, xzr, x20
        0x9407813d, //  bl		0x1001e0eac
        0xaa1403e0, //  orr		x0, xzr, x20
        0x94078126, //  bl		0x1001e0e58
        0xaa1303e0, //  orr		x0, xzr, x19
        0xa9437bfd, //  ldp		x29, x30, [sp, #48]
        0xa9424ff4, //  ldp		x20, x19, [sp, #32]
        0xa94157f6, //  ldp		x22, x21, [sp, #16]
        0x910103ff, //  add		sp, sp, #0x40
        0xd65f03c0, //  ret		x30
        0xf100403f, //  subs		xzr, x1, #0x10
        0x540000a8, //  b.hi 		0x1000009f4
        0xeb00003f, //  subs		xzr, x1, x0
        0x54000068, //  b.hi 		0x1000009f4
        0x52800021, //  movz		w1, #0x1, lsl #0x0
        0x140780f6, //  b		0x1001e0dc8
        0x52b00008, //  movz		w8, #0x8000, lsl #0x10
        0xeb08003f, //  subs		xzr, x1, x8
        0x54000069, //  b.ls 		0x100000a08
        0xd2800000, //  movz		x0, #0x0, lsl #0x0
        0xd65f03c0, //  ret		x30
        0xd100c3ff, //  sub		sp, sp, #0x30
        0xa9014ff4, //  stp		x20, x19, [sp, #16]
        0xa9027bfd, //  stp		x29, x30, [sp, #32]
        0x910083fd, //  add		x29, sp, #0x20
    };

    const int instruction_count = sizeof(instructions) / sizeof(*instructions);

    int pc = 0;
    for (int i = 0; i < instruction_count; i++) {
        opcode = da64_decode(instructions[i]);
        da64_fmt_insn_pc(pc, opcode, buf, sizeof(buf));
        printf("decoded: %s\n", buf);
        pc += sizeof(*instructions);
    }
}