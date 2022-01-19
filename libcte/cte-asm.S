.extern cte_restore

.section        .cte_essential,"ax",@progbits
.global cte_restore_entry
.p2align 4
.type   cte_restore_entry, @function
cte_restore_entry:
        // A propper callframe for perf
        pushq %rbp
        mov   %rsp, %rbp
        /////////////////////////////

        pushq %rdi
        pushq %rsi

        // rdi (first argument) is the current return pointer of this function
        movq 24(%rsp), %rdi
        // rsi (second argument) is the address of the next instruction
        // (after the call) in the caller
        movq 32(%rsp), %rsi

        // Modify the return ptr: Return to the original function start addr
        leaq -12(%rdi), %rdi
        movq %rdi, 24(%rsp)

        // Save the caller-saved registers
        // rax, rdi, rsi, rdx, rcx, r8, r9, r10, r11
        pushq %rax
        pushq %rdx
        pushq %rcx
        pushq %r8
        pushq %r9
        pushq %r10
        pushq %r11

        // The stack must be 16-byte aligned before the call
        // "leaq -8(%rsp), %rsp\n"

        // Save the %xmm0-%xmm7 -- they are used for fp arguments
        /* "subq $128, %rsp\n" */
        leaq -128(%rsp), %rsp
        movdqu %xmm0, 112(%rsp)
        movdqu %xmm1, 96(%rsp)
        movdqu %xmm2, 80(%rsp)
        movdqu %xmm3, 64(%rsp)
        movdqu %xmm4, 48(%rsp)
        movdqu %xmm5, 32(%rsp)
        movdqu %xmm6, 16(%rsp)
        movdqu %xmm7, (%rsp)

        call cte_restore

        // Restore %xmm0-%xmm7
        movdqu 112(%rsp), %xmm0
        movdqu 96(%rsp), %xmm1
        movdqu 80(%rsp), %xmm2
        movdqu 64(%rsp), %xmm3
        movdqu 48(%rsp), %xmm4
        movdqu 32(%rsp), %xmm5
        movdqu 16(%rsp), %xmm6
        movdqu (%rsp), %xmm7
        leaq 128(%rsp), %rsp

        // "leaq 8(%rsp), %rsp\n"

        // Restore the caller-saved registers
        popq %r11
        popq %r10
        popq %r9
        popq %r8
        popq %rcx
        popq %rdx
        popq %rax
        popq %rsi
        popq %rdi

        popq %rbp
        ret

.size   cte_restore_entry, .-cte_restore_entry
