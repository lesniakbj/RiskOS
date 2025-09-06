.intel_syntax noprefix

.global outb
outb:
    mov dx, di      # port is in rdi, so we use di for 16-bit port
    mov al, sil     # value is in rsi, so we use sil for 8-bit value
    out dx, al
    ret

.global inb
inb:
    mov dx, di      # port is in rdi, so we use di for 16-bit port
    in al, dx
    ret             # return value is already in al (which is part of rax)

.global inw
inw:
    mov dx, di      # port is in rdi (di)
    in ax, dx       # read a word into ax
    ret             # return value is in ax (part of rax)

.global outw
outw:
    mov dx, di      # port is in rdi (di)
    mov ax, si      # value is in rsi (si)
    out dx, ax
    ret

.global outl
outl:
    mov dx, di      # port is in rdi, so we use di for 16-bit port
    mov eax, esi    # value is in rsi, so we use esi for 32-bit value
    out dx, eax
    ret

.global inl
inl:
    mov dx, di      # port is in rdi, so we use di for 16-bit port
    in eax, dx
    ret             # return value is already in eax

.global io_wait
io_wait:
    # Port 0x80 is often used for I/O delays, why change...
    out 0x80, al
    ret