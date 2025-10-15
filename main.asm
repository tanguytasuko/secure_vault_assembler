; Secure Vault (Credentials manager)
; Linux x86-64, NASM, syscalls only
; Build: nasm -felf64 secure_vault.asm -o secure_vault.o && ld -o secure_vault secure_vault.o
; Run  : ./secure_vault
;
; F0: ask DB password (first 8 bytes form XOR key)
;     -> Immediate authentication: new DB initializes header; existing DB is verified/migrated; wrong key exits.
; F1: add credential (login[32], password[32])
; F2: decrypt and print DB
; Menu loops until you choose 3) Quit
;
BITS 64
default rel

; ---- Linux syscalls ----
%define SYS_read      0
%define SYS_write     1
%define SYS_close     3
%define SYS_openat  257
%define SYS_exit     60

%define AT_FDCWD    -100

; ---- flags / modes (decimal to avoid octal quirks) ----
%define O_RDONLY      0
%define O_WRONLY      1
%define O_CREAT      64
%define O_TRUNC     512
%define MODE_600    384   ; 0600

%define STDIN          0
%define STDOUT         1
%define STDERR         2

%define MAX_DB     65536
%define REC_SIZE       64
%define FIELD_SIZE     32
%define HEAD_LEN        8

section .data
    db_path:        db "vault.db", 0
    urand_path:     db "/dev/urandom", 0

    msg_welcome:    db "Secure Vault (XOR-ECB, key = first 8 bytes)", 10
    len_welcome     equ $-msg_welcome

            msg_pass:       db "Enter DB password: ", 0
    msg_pass_new:   db "New DB password: ", 0
    msg_short:      db "Password must be at least 8 characters.", 10
    len_short       equ $-msg_short
    msg_menu:       db 10, "Choose:", 10, "  1) Add credential", 10, "  2) Show DB", 10, "  3) Quit", 10, "Choice: ", 0
    msg_login:      db "Login (<=31 chars): ", 0
    msg_pwd:        db "Password (<=31 chars): ", 0
    msg_saved:      db "Saved.", 10
    len_saved       equ $-msg_saved

    msg_db_empty:   db "(DB empty or missing)", 10
    len_db_empty    equ $-msg_db_empty

    msg_bad_choice: db "Invalid choice.", 10
    len_bad_choice  equ $-msg_bad_choice

    msg_db_big:     db "DB too big for buffer.", 10
    len_db_big      equ $-msg_db_big

    msg_wrong:      db "Wrong password.", 10
    len_wrong       equ $-msg_wrong

    msg_corrupt:    db "Corrupted DB (size mismatch).", 10
    len_corrupt     equ $-msg_corrupt

    msg_init:       db "Initialized new vault.", 10
    len_init        equ $-msg_init

    msg_migrated:   db "Migrated: authentication enabled.", 10
    len_migrated    equ $-msg_migrated

    lbl_login:      db "Login: ", 0
    lbl_pass:       db "Password: ", 0
    sep_line:       db "----------------", 10
    len_sep_line    equ $-sep_line

    nl:             db 10

    ; 8-byte header magic (exactly HEAD_LEN bytes)
    head_magic:     db "SVDBv1", 0, 0   ; 6 + 2 zeros = 8 bytes

section .bss
    key8:       resb 8
    pass_in:    resb 64
    choice_in:  resb 8
    login_in:   resb FIELD_SIZE
    pwd_in:     resb FIELD_SIZE
    db_buf:     resb MAX_DB
    db_size:    resq 1
    first_run:  resb 1

section .text
    global _start

_start:
    ; banner
    mov rdi, STDOUT
    mov rsi, msg_welcome
    mov rdx, len_welcome
    call write_all

    ; Check if DB exists/has content to customize password prompt
    mov rdi, db_buf
    mov rsi, MAX_DB
    call load_db
    mov [db_size], rax
    cmp qword [db_size], 0
    jne .existing
    mov byte [first_run], 1
    jmp .prompt_pw
.existing:
    mov byte [first_run], 0

.prompt_pw:
.pass_loop:
    ; show "New DB password" on first run, otherwise normal prompt
    cmp byte [first_run], 1
    jne .prompt_existing
    mov rdi, msg_pass_new
    jmp .do_prompt
.prompt_existing:
    mov rdi, msg_pass
.do_prompt:
    call print_cstr
    mov rdi, pass_in
    mov rsi, 63
    call read_line            ; returns length in rax, pass_in NUL-terminated
    cmp rax, 8
    jae .have_pw
    ; too short -> warn and retry
    mov rdi, STDOUT
    mov rsi, msg_short
    mov rdx, len_short
    call write_all
    jmp .pass_loop
.have_pw:
    ; derive key (first 8 bytes, zero-padded)
    mov rdi, key8
    mov rsi, 8
    call memzero
    mov rdi, key8
    mov rsi, pass_in
    mov rdx, 8
    call memcpy

    ; authenticate or init/migrate immediately (may exit on wrong password)
    call auth_or_init

main_menu:
    mov rdi, msg_menu
    call print_cstr
    mov rdi, choice_in
    mov rsi, 7
    call read_line
    mov al, [choice_in]
    cmp al, 49              ; '1'
    je do_add
    cmp al, 50              ; '2'
    je do_show
    cmp al, 51              ; '3'
    je exit_ok
    mov rdi, STDOUT
    mov rsi, msg_bad_choice
    mov rdx, len_bad_choice
    call write_all
    jmp main_menu

; ---- F1: add credential ----

do_add:
    ; login
    mov rdi, msg_login
    call print_cstr
    mov rdi, login_in
    mov rsi, FIELD_SIZE
    call memzero
    mov rdi, login_in
    mov rsi, FIELD_SIZE-1
    call read_line

    ; password
    mov rdi, msg_pwd
    call print_cstr
    mov rdi, pwd_in
    mov rsi, FIELD_SIZE
    call memzero
    mov rdi, pwd_in
    mov rsi, FIELD_SIZE-1
    call read_line

    ; load DB
    mov rdi, db_buf
    mov rsi, MAX_DB
    call load_db
    mov [db_size], rax

    ; decrypt
    mov rdi, db_buf
    mov rsi, [db_size]
    mov rdx, key8
    call xor_buf

    ; ensure header exists (should be ok after auth_or_init); if legacy, migrate inline
    mov rax, [db_size]
    mov rcx, rax
    and rcx, 63
    cmp rcx, HEAD_LEN
    je .da_ready
    cmp rcx, 0
    jne .da_corrupt
    ; legacy -> make room for header
    mov rax, [db_size]
    add rax, HEAD_LEN
    cmp rax, MAX_DB
    ja .too_big
    mov rcx, [db_size]
    cmp rcx, 0
    je .put_head
.shift:
    dec rcx
    mov al, [db_buf + rcx]
    mov [db_buf + rcx + HEAD_LEN], al
    cmp rcx, 0
    jne .shift
.put_head:
    mov rdi, db_buf
    mov rsi, head_magic
    mov rdx, HEAD_LEN
    call memcpy
    mov rax, [db_size]
    add rax, HEAD_LEN
    mov [db_size], rax
    jmp .da_ready

.da_corrupt:
    mov rdi, STDOUT
    mov rsi, msg_corrupt
    mov rdx, len_corrupt
    call write_all
    jmp main_menu

.da_ready:
    ; capacity
    mov rax, [db_size]
    add rax, REC_SIZE
    cmp rax, MAX_DB
    ja  .too_big

    ; append record after header/entries
    mov rbx, [db_size]
    ; Fill login field with random bytes, then copy cstring into it
    lea rdi, [db_buf]
    add rdi, rbx                       ; dest_login
    mov rsi, FIELD_SIZE
    call fill_random
    ; copy input (login_in) as cstring into dest_login (NUL-terminated)
    lea rdi, [db_buf]
    add rdi, rbx
    mov rsi, login_in
    mov rdx, FIELD_SIZE
    call copy_cstr

    ; Fill password field with random bytes, then copy cstring
    lea rdi, [db_buf]
    add rdi, rbx
    add rdi, FIELD_SIZE               ; dest_pwd
    mov rsi, FIELD_SIZE
    call fill_random
    lea rdi, [db_buf]
    add rdi, rbx
    add rdi, FIELD_SIZE
    mov rsi, pwd_in
    mov rdx, FIELD_SIZE
    call copy_cstr

    add rbx, REC_SIZE
    mov [db_size], rbx

    ; re-encrypt and save
    mov rdi, db_buf
    mov rsi, [db_size]
    mov rdx, key8
    call xor_buf

    mov rdi, db_buf
    mov rsi, [db_size]
    call save_db

    mov rdi, STDOUT
    mov rsi, msg_saved
    mov rdx, len_saved
    call write_all
    jmp main_menu

.too_big:
    mov rdi, STDOUT
    mov rsi, msg_db_big
    mov rdx, len_db_big
    call write_all
    jmp main_menu

; ---- F2: show DB ----

do_show:
    mov rdi, db_buf
    mov rsi, MAX_DB
    call load_db
    mov [db_size], rax

    cmp qword [db_size], 0
    jne .have
    mov rdi, STDOUT
    mov rsi, msg_db_empty
    mov rdx, len_db_empty
    call write_all
    jmp main_menu

.have:
    mov rdi, db_buf
    mov rsi, [db_size]
    mov rdx, key8
    call xor_buf

    ; determine format
    mov rax, [db_size]
    mov rcx, rax
    and rcx, 63
    cmp rcx, HEAD_LEN
    je .sh_headered
    cmp rcx, 0
    je .sh_legacy
    mov rdi, STDOUT
    mov rsi, msg_corrupt
    mov rdx, len_corrupt
    call write_all
    jmp main_menu

.sh_headered:
    ; verify magic
    xor rcx, rcx
.hcmp:
    cmp rcx, HEAD_LEN
    jae .display
    mov al, [db_buf + rcx]
    cmp al, [head_magic + rcx]
    jne .wrong
    inc rcx
    jmp .hcmp
.wrong:
    mov rdi, STDOUT
    mov rsi, msg_wrong
    mov rdx, len_wrong
    call write_all
    jmp main_menu

.sh_legacy:
    ; legacy without header after auth? treat as empty
    mov rdi, STDOUT
    mov rsi, msg_db_empty
    mov rdx, len_db_empty
    call write_all
    jmp main_menu

.display:
    ; iterate records (start after header)
    mov rbx, HEAD_LEN
.loop:
    mov rax, [db_size]
    cmp rbx, rax
    jae .done

    mov rax, [db_size]
    sub rax, rbx
    cmp rax, REC_SIZE
    jb .done

    ; --- separator BEFORE each record ---
    mov rdi, STDOUT
    mov rsi, sep_line
    mov rdx, len_sep_line
    call write_all

    ; login
    mov rdi, lbl_login
    call print_cstr
    lea rdi, [db_buf]
    add rdi, rbx
    mov rsi, FIELD_SIZE
    call print_field32

    ; password
    mov rdi, lbl_pass
    call print_cstr
    lea rdi, [db_buf]
    add rdi, rbx
    add rdi, FIELD_SIZE
    mov rsi, FIELD_SIZE
    call print_field32

    ; no trailing bar after record

    add rbx, REC_SIZE
    jmp .loop

.done:
    jmp main_menu

; ---- authentication at startup ----
; auth_or_init: verifies password against header, migrates legacy DB, or initializes new DB
; On wrong password / corruption it prints a message and exits. On success it returns.
auth_or_init:
    ; load DB
    mov rdi, db_buf
    mov rsi, MAX_DB
    call load_db
    mov [db_size], rax

    cmp qword [db_size], 0
    jne .have
    ; new DB -> create header, encrypt, save
    mov rdi, db_buf
    mov rsi, head_magic
    mov rdx, HEAD_LEN
    call memcpy
    mov qword [db_size], HEAD_LEN

    mov rdi, db_buf
    mov rsi, [db_size]
    mov rdx, key8
    call xor_buf
    mov rdi, db_buf
    mov rsi, [db_size]
    call save_db

    ; notify
    mov rdi, STDOUT
    mov rsi, msg_init
    mov rdx, len_init
    call write_all
    ret

.have:
    ; decrypt existing DB
    mov rdi, db_buf
    mov rsi, [db_size]
    mov rdx, key8
    call xor_buf

    ; detect format by (size % 64)
    mov rax, [db_size]
    mov rcx, rax
    and rcx, 63
    cmp rcx, HEAD_LEN
    je .headered
    cmp rcx, 0
    je .legacy
    ; corrupted size
    mov rdi, STDOUT
    mov rsi, msg_corrupt
    mov rdx, len_corrupt
    call write_all
    jmp exit_ok

.headered:
    ; verify magic
    xor rcx, rcx
.hchk:
    cmp rcx, HEAD_LEN
    jae .ok
    mov al, [db_buf + rcx]
    cmp al, [head_magic + rcx]
    jne .wrong
    inc rcx
    jmp .hchk
.ok:
    ret
.wrong:
    mov rdi, STDOUT
    mov rsi, msg_wrong
    mov rdx, len_wrong
    call write_all
    jmp exit_ok

.legacy:
    ; migrate automatically (prepend header)
    mov rax, [db_size]
    add rax, HEAD_LEN
    cmp rax, MAX_DB
    ja .too_big

    mov rcx, [db_size]
    cmp rcx, 0
    je .ins_head
.shift:
    dec rcx
    mov al, [db_buf + rcx]
    mov [db_buf + rcx + HEAD_LEN], al
    cmp rcx, 0
    jne .shift

.ins_head:
    mov rdi, db_buf
    mov rsi, head_magic
    mov rdx, HEAD_LEN
    call memcpy

    mov rax, [db_size]
    add rax, HEAD_LEN
    mov [db_size], rax

    ; re-encrypt and save
    mov rdi, db_buf
    mov rsi, [db_size]
    mov rdx, key8
    call xor_buf
    mov rdi, db_buf
    mov rsi, [db_size]
    call save_db

    ; notify
    mov rdi, STDOUT
    mov rsi, msg_migrated
    mov rdx, len_migrated
    call write_all
    ret

.too_big:
    mov rdi, STDOUT
    mov rsi, msg_db_big
    mov rdx, len_db_big
    call write_all
    jmp exit_ok

; ---- helpers ----

; fill_random(rdi=buf, rsi=len) -> fills with bytes from /dev/urandom
fill_random:
    push rbx
    push r12
    mov r12, rdi          ; save buf
    mov rbx, rsi          ; save len
    ; openat(AT_FDCWD, "/dev/urandom", O_RDONLY, 0)
    mov rax, SYS_openat
    mov rdi, AT_FDCWD
    mov rsi, urand_path
    mov rdx, O_RDONLY
    xor r10, r10
    syscall
    cmp rax, 0
    jl .fr_zero           ; if failed, fall back to zeros
    mov r11, rax          ; fd
    ; read all
    mov rax, SYS_read
    mov rdi, r11
    mov rsi, r12
    mov rdx, rbx
    syscall
    ; close
    mov rax, SYS_close
    mov rdi, r11
    syscall
    pop r12
    pop rbx
    ret
.fr_zero:
    ; fallback to zeros
    mov rdi, r12
    mov rsi, rbx
    call memzero
    pop r12
    pop rbx
    ret

; copy_cstr(rdi=dst, rsi=src, rdx=maxlen) -> copies src until NUL or maxlen-1, ensures trailing NUL
copy_cstr:
    test rdx, rdx
    jz .cc_done
    mov rcx, rdx          ; rcx = max
    dec rcx               ; reserve space for NUL
    js .put_nul           ; if max was 0 -> nothing
.cc_loop:
    cmp rcx, 0
    je .put_nul
    mov al, [rsi]
    cmp al, 0
    je .put_nul
    mov [rdi], al
    inc rdi
    inc rsi
    dec rcx
    jmp .cc_loop
.put_nul:
    mov byte [rdi], 0
.cc_done:
    ret



write_all:                 ; rdi=fd, rsi=buf, rdx=len
.wloop:
    mov rax, SYS_write
    syscall
    cmp rax, 0
    jl .done_w
    cmp rax, rdx
    je .done_w
    sub rdx, rax
    add rsi, rax
    jmp .wloop
.done_w:
    ret

print_cstr:                ; rdi=cstr
    push rdi
    call strlen
    mov rdx, rax
    pop rsi
    mov rdi, STDOUT
    call write_all
    ret

strlen:                    ; rdi=ptr -> rax=len
    mov rax, rdi
.sloop:
    cmp byte [rax], 0
    je .sout
    inc rax
    jmp .sloop
.sout:
    sub rax, rdi
    ret

read_line:                 ; rdi=buf, rsi=max_no_nul -> rax=len, buf NUL-terminated
    mov r8, rsi
    mov rdx, rsi
    mov rsi, rdi
    mov rdi, STDIN
    mov rax, SYS_read
    syscall
    cmp rax, 0
    jle .zero
    mov rcx, rax
    mov r9, rsi
    xor rax, rax
.find:
    cmp rax, rcx
    jae .no_nl
    cmp byte [r9 + rax], 10
    je .nl
    inc rax
    jmp .find
.nl:
    mov byte [r9 + rax], 0
    ret
.no_nl:
    mov rax, rcx
    cmp rcx, r8
    jne .room
    dec rax
    mov byte [r9 + rax], 0
    ret
.room:
    mov byte [r9 + rax], 0
    ret
.zero:
    xor rax, rax
    ret

memzero:                   ; rdi=ptr, rsi=len
    test rsi, rsi
    jz .mz_done
.mz_loop:
    mov byte [rdi], 0
    inc rdi
    dec rsi
    jnz .mz_loop
.mz_done:
    ret

memcpy:                    ; rdi=dst, rsi=src, rdx=len
    test rdx, rdx
    jz .mc_done
.mc_loop:
    mov al, [rsi]
    mov [rdi], al
    inc rsi
    inc rdi
    dec rdx
    jnz .mc_loop
.mc_done:
    ret

xor_buf:                   ; rdi=buf, rsi=len, rdx=key8
    test rsi, rsi
    jz .xb_done
    xor rcx, rcx
.xb_loop:
    mov r8, rcx
    and r8, 7
    mov al, [rdx + r8]
    xor [rdi + rcx], al
    inc rcx
    cmp rcx, rsi
    jb .xb_loop
.xb_done:
    ret

load_db:                   ; rdi=buf, rsi=max -> rax=size
    mov r8, rdi           ; buf
    mov r9, rsi           ; max
    mov rax, SYS_openat
    mov rdi, AT_FDCWD
    mov rsi, db_path
    mov rdx, O_RDONLY
    xor r10, r10          ; mode=0
    syscall
    cmp rax, 0
    jl .ld_empty
    mov r11, rax          ; fd
    xor r10, r10          ; total=0
.ld_read:
    mov rdx, r9
    sub rdx, r10
    cmp rdx, 0
    je .ld_close
    mov rax, SYS_read
    mov rdi, r11
    lea rsi, [r8 + r10]
    syscall
    cmp rax, 0
    jl .ld_close
    cmp rax, 0
    je .ld_close
    add r10, rax
    jmp .ld_read
.ld_close:
    mov rax, SYS_close
    mov rdi, r11
    syscall
    mov rax, r10
    ret
.ld_empty:
    xor rax, rax
    ret

save_db:                   ; rdi=buf, rsi=size
    mov r8, rdi           ; buf
    mov r9, rsi           ; size
    mov rax, SYS_openat
    mov rdi, AT_FDCWD
    mov rsi, db_path
    mov rdx, O_WRONLY | O_CREAT | O_TRUNC
    mov r10, MODE_600
    syscall
    cmp rax, 0
    jl .sv_ret
    mov rdi, rax          ; fd
    mov rsi, r8           ; buf
    mov rdx, r9           ; size
    call write_all
    mov rax, SYS_close
    syscall
.sv_ret:
    ret

print_field32:             ; rdi=ptr, rsi=max=32
    xor rcx, rcx
.pf_loop:
    cmp rcx, rsi
    jae .pf_len
    cmp byte [rdi + rcx], 0
    je .pf_len
    inc rcx
    jmp .pf_loop
.pf_len:
    mov rdx, rcx
    mov rsi, rdi
    mov rdi, STDOUT
    call write_all
    mov rax, SYS_write
    mov rdi, STDOUT
    mov rsi, nl
    mov rdx, 1
    syscall
    ret

exit_ok:
    mov rax, SYS_exit
    xor rdi, rdi
    syscall

