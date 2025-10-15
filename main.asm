; Secure Vault (Credentials manager) — Security++
; Linux x86-64, NASM, syscalls only
; Build: nasm -felf64 secure_vault.asm -o secure_vault.o && ld -o secure_vault secure_vault.o
; Run  : ./secure_vault
;
; Crypto per spec: XOR with 8-byte repeating key (key = first 8 bytes of password)
; Hardening in this version:
;   - **No known-plaintext header** anymore. New header = 16 bytes: [nonce(8)][tag(8)]
;     where tag = FNV1a-64(key8 || nonce || "SV"), stored *encrypted* like the rest.
;   - **Immediate authentication** on startup: wrong password => exit right away.
;   - **Password input hidden** (ECHO off) for master password and entry password.
;   - **Random padding** for 32-byte fields (login/password) to avoid zero-padding leaks.
;   - **Memory wipe** (key/password buffers) before exit.
;   - Backward compatibility:
;       * Legacy (no header) -> auto-migrate to new 16-byte header.
;       * Old v1 header (8-byte "SVDBv1") -> auto-migrate to 16-byte header.
;
BITS 64
default rel

; ---- Linux syscalls ----
%define SYS_read      0
%define SYS_write     1
%define SYS_close     3
%define SYS_ioctl    16
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
%define HEAD1_LEN       8      ; old header length ("SVDBv1")
%define HEAD2_LEN      16      ; new header length: nonce(8) + tag(8)

; ioctl termios
%define TCGETS     0x5401
%define TCSETS     0x5402
%define ECHO_BIT       8       ; bit to clear in c_lflag

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

    ; old v1 magic (8 bytes) for backward detection
    head1_magic:    db "SVDBv1", 0, 0   ; 6 + 2 zeros = 8 bytes

    ; FNV-1a 64-bit constants
    FNV_OFFSET:     dq 0xcbf29ce484222325
    FNV_PRIME:      dq 0x00000100000001b3

section .bss
    key8:       resb 8
    pass_in:    resb 64
    choice_in:  resb 8
    login_in:   resb FIELD_SIZE
    pwd_in:     resb FIELD_SIZE
    db_buf:     resb MAX_DB
    db_size:    resq 1
    first_run:  resb 1

    nonce8:     resb 8

    term_old:   resb 64
    term_new:   resb 64
    echo_state: resb 1

section .text
    global _start

_start:
    ; banner
    mov rdi, STDOUT
    mov rsi, msg_welcome
    mov rdx, len_welcome
    call write_all

    ; Check if DB exists to choose prompt text
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
    ; prompt (hidden input)
    cmp byte [first_run], 1
    jne .prompt_existing
    mov rdi, msg_pass_new
    jmp .do_prompt
.prompt_existing:
    mov rdi, msg_pass
.do_prompt:
    call print_cstr
    call disable_echo
    mov rdi, pass_in
    mov rsi, 63
    call read_line            ; returns length in rax, pass_in NUL-terminated
    mov rbx, rax              ; SAVE length before printing newline
    call restore_echo
    ; add a manual newline after hidden input (does not clobber length check)
    mov rax, SYS_write
    mov rdi, STDOUT
    mov rsi, nl
    mov rdx, 1
    syscall

    cmp rbx, 8
    jae .have_pw
    mov rdi, STDOUT
    mov rsi, msg_short
    mov rdx, len_short
    call write_all
    jmp .pass_loop
.have_pw:
    ; derive key (first 8 bytes)
    mov rdi, key8
    mov rsi, 8
    call memzero
    mov rdi, key8
    mov rsi, pass_in
    mov rdx, 8
    call memcpy

    ; authenticate / init / migrate (may exit on wrong password)
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

    ; password (hidden)
    mov rdi, msg_pwd
    call print_cstr
    call disable_echo
    mov rdi, pwd_in
    mov rsi, FIELD_SIZE
    call memzero
    mov rdi, pwd_in
    mov rsi, FIELD_SIZE-1
    call read_line
    call restore_echo
    ; newline after hidden input
    mov rax, SYS_write
    mov rdi, STDOUT
    mov rsi, nl
    mov rdx, 1
    syscall

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

    ; expect HEAD2_LEN header (auth_or_init enforces it)
    mov rax, [db_size]
    mov rcx, rax
    and rcx, 63
    cmp rcx, HEAD2_LEN
    jne .da_corrupt

    ; capacity
    mov rax, [db_size]
    add rax, REC_SIZE
    cmp rax, MAX_DB
    ja  .too_big

    ; append record with random padding
    mov rbx, [db_size]

    ; login field
    lea rdi, [db_buf + rbx]
    mov rsi, FIELD_SIZE
    call fill_random
    lea rdi, [db_buf + rbx]
    mov rsi, login_in
    mov rdx, FIELD_SIZE
    call copy_cstr

    ; password field
    lea rdi, [db_buf + rbx + FIELD_SIZE]
    mov rsi, FIELD_SIZE
    call fill_random
    lea rdi, [db_buf + rbx + FIELD_SIZE]
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

.da_corrupt:
    mov rdi, STDOUT
    mov rsi, msg_corrupt
    mov rdx, len_corrupt
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

    ; verify HEAD2 header tag
    ; compute tag(key8, nonce)
    lea rsi, [db_buf]          ; nonce at start
    mov rdi, key8
    call compute_tag           ; RAX = tag
    mov r8, [db_buf + 8]       ; stored tag
    cmp rax, r8
    jne .wrong

    ; iterate records (start after 16-byte header)
    mov rbx, HEAD2_LEN
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
    lea rdi, [db_buf + rbx]
    mov rsi, FIELD_SIZE
    call print_field32

    ; password
    mov rdi, lbl_pass
    call print_cstr
    lea rdi, [db_buf + rbx + FIELD_SIZE]
    mov rsi, FIELD_SIZE
    call print_field32

    add rbx, REC_SIZE
    jmp .loop

.done:
    jmp main_menu

.wrong:
    mov rdi, STDOUT
    mov rsi, msg_wrong
    mov rdx, len_wrong
    call write_all
    jmp main_menu

; ---- authentication / initialization / migration ----
; New header format (v2): [nonce(8)][tag(8)] where tag = FNV1a64(key8 || nonce || "SV")
; All bytes stored encrypted by XOR just like the rest of the file.
; On wrong password => prints and exits.
auth_or_init:
    ; We already loaded db into db_buf and db_size in _start for prompt text, but reload to be safe
    mov rdi, db_buf
    mov rsi, MAX_DB
    call load_db
    mov [db_size], rax

    cmp qword [db_size], 0
    jne .have
    ; new DB -> create v2 header (nonce+tag), encrypt, save
    mov rdi, nonce8
    mov rsi, 8
    call fill_random                 ; nonce
    ; write header (plaintext in RAM)
    mov rdi, db_buf
    mov rsi, nonce8
    mov rdx, 8
    call memcpy                      ; nonce
    ; tag = compute_tag(key8, nonce)
    mov rdi, key8
    mov rsi, db_buf                  ; nonce just copied
    call compute_tag                 ; RAX = tag
    mov [db_buf + 8], rax

    mov qword [db_size], HEAD2_LEN

    ; encrypt + save
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

    ; Decide by size % 64
    mov rax, [db_size]
    mov rcx, rax
    and rcx, 63
    cmp rcx, HEAD2_LEN
    je .is_v2
    cmp rcx, HEAD1_LEN
    je .is_v1
    cmp rcx, 0
    je .legacy
    ; corrupted
    mov rdi, STDOUT
    mov rsi, msg_corrupt
    mov rdx, len_corrupt
    call write_all
    jmp exit_ok

.is_v2:
    ; verify tag
    lea rsi, [db_buf]       ; nonce
    mov rdi, key8
    call compute_tag        ; RAX = tag
    mov r8, [db_buf + 8]
    cmp rax, r8
    jne .bad
    ret
.bad:
    mov rdi, STDOUT
    mov rsi, msg_wrong
    mov rdx, len_wrong
    call write_all
    jmp exit_ok

.is_v1:
    ; verify old magic then migrate to v2 (grow by +8)
    xor rdx, rdx
.v1chk:
    cmp rdx, HEAD1_LEN
    jae .v1_ok
    mov al, [db_buf + rdx]
    cmp al, [head1_magic + rdx]
    jne .bad
    inc rdx
    jmp .v1chk
.v1_ok:
    ; ensure capacity
    mov rax, [db_size]
    add rax, 8
    cmp rax, MAX_DB
    ja .too_big
    ; shift content right by 8 (from end to start)
    mov rcx, [db_size]
.v1_shift:
    cmp rcx, 0
    je .v1_ins
    dec rcx
    mov al, [db_buf + rcx]
    mov [db_buf + rcx + 8], al
    jmp .v1_shift
.v1_ins:
    ; write new v2 header (nonce+tag)
    mov rdi, nonce8
    mov rsi, 8
    call fill_random
    mov rdi, db_buf
    mov rsi, nonce8
    mov rdx, 8
    call memcpy
    mov rdi, key8
    mov rsi, db_buf
    call compute_tag
    mov [db_buf + 8], rax
    ; update size
    mov rax, [db_size]
    add rax, 8
    mov [db_size], rax
    ; re-encrypt + save
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

.legacy:
    ; grow by +16 and add v2 header
    mov rax, [db_size]
    add rax, HEAD2_LEN
    cmp rax, MAX_DB
    ja .too_big
    mov rcx, [db_size]
.leg_shift:
    cmp rcx, 0
    je .leg_ins
    dec rcx
    mov al, [db_buf + rcx]
    mov [db_buf + rcx + HEAD2_LEN], al
    jmp .leg_shift
.leg_ins:
    mov rdi, nonce8
    mov rsi, 8
    call fill_random
    mov rdi, db_buf
    mov rsi, nonce8
    mov rdx, 8
    call memcpy
    mov rdi, key8
    mov rsi, db_buf
    call compute_tag
    mov [db_buf + 8], rax
    mov rax, [db_size]
    add rax, HEAD2_LEN
    mov [db_size], rax
    ; re-encrypt + save
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

; write_all(fd=STDOUT/...) with rsi=buf, rdx=len
write_all:
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

; print_cstr(rdi=ptr to zero-terminated string)
print_cstr:
    push rdi
    call strlen
    mov rdx, rax
    pop rsi
    mov rdi, STDOUT
    call write_all
    ret

; strlen(rdi=ptr) -> rax=len (up to first zero)
strlen:
    mov rax, rdi
.sloop:
    cmp byte [rax], 0
    je .sout
    inc rax
    jmp .sloop
.sout:
    sub rax, rdi
    ret

; read_line(rdi=buf, rsi=maxlen_without_nul) -> rax=len, stores 0-terminated
read_line:
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

; memzero(rdi=ptr, rsi=len)
memzero:
    test rsi, rsi
    jz .mz_done
.mz_loop:
    mov byte [rdi], 0
    inc rdi
    dec rsi
    jnz .mz_loop
.mz_done:
    ret

; memcpy(rdi=dst, rsi=src, rdx=len)
memcpy:
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

; copy_cstr(rdi=dst, rsi=src, rdx=maxlen) -> copies src until NUL or maxlen-1, ensures trailing NUL
copy_cstr:
    test rdx, rdx
    jz .cc_done
    mov rcx, rdx
    dec rcx
    js .put_nul
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

; xor_buf(rdi=buf, rsi=len, rdx=key8) — XOR with repeating 8-byte key
xor_buf:
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

; fill_random(rdi=buf, rsi=len) -> bytes from /dev/urandom (falls back to zeros)
fill_random:
    push rbx
    push r12
    mov r12, rdi
    mov rbx, rsi
    mov rax, SYS_openat
    mov rdi, AT_FDCWD
    mov rsi, urand_path
    mov rdx, O_RDONLY
    xor r10, r10
    syscall
    cmp rax, 0
    jl .fr_zero
    mov r11, rax
    mov rax, SYS_read
    mov rdi, r11
    mov rsi, r12
    mov rdx, rbx
    syscall
    mov rax, SYS_close
    mov rdi, r11
    syscall
    pop r12
    pop rbx
    ret
.fr_zero:
    mov rdi, r12
    mov rsi, rbx
    call memzero
    pop r12
    pop rbx
    ret

; compute_tag(rdi=key8, rsi=nonce8) -> rax = FNV1a64(key8 || nonce8 || "SV")
compute_tag:
    ; rax = offset
    mov rax, [rel FNV_OFFSET]
    ; fold key8
    xor rcx, rcx
.ct_k:
    cmp rcx, 8
    jae .ct_n
    mov bl, [rdi + rcx]
    xor al, bl
    mov rdx, [rel FNV_PRIME]
    mul rdx
    inc rcx
    jmp .ct_k
.ct_n:
    xor rcx, rcx
.ct_n_loop:
    cmp rcx, 8
    jae .ct_c
    mov bl, [rsi + rcx]
    xor al, bl
    mov rdx, [rel FNV_PRIME]
    mul rdx
    inc rcx
    jmp .ct_n_loop
.ct_c:
    mov bl, 'S'
    xor al, bl
    mov rdx, [rel FNV_PRIME]
    mul rdx
    mov bl, 'V'
    xor al, bl
    mov rdx, [rel FNV_PRIME]
    mul rdx
    ret

; disable_echo / restore_echo for terminal
disable_echo:
    mov rax, SYS_ioctl
    mov rdi, STDIN
    mov rsi, TCGETS
    mov rdx, term_old
    syscall
    cmp rax, 0
    jl .de_ret
    ; copy
    mov rdi, term_new
    mov rsi, term_old
    mov rdx, 64
    call memcpy
    ; clear ECHO bit in c_lflag (offset 12)
    mov eax, [term_new + 12]
    and eax, ~ECHO_BIT
    mov [term_new + 12], eax
    ; apply
    mov rax, SYS_ioctl
    mov rdi, STDIN
    mov rsi, TCSETS
    mov rdx, term_new
    syscall
    mov byte [echo_state], 1
.de_ret:
    ret

restore_echo:
    cmp byte [echo_state], 1
    jne .re_ret
    mov rax, SYS_ioctl
    mov rdi, STDIN
    mov rsi, TCSETS
    mov rdx, term_old
    syscall
    mov byte [echo_state], 0
.re_ret:
    ret

; load_db(rdi=buf, rsi=max) -> rax=size
load_db:
    mov r8, rdi
    mov r9, rsi
    mov rax, SYS_openat
    mov rdi, AT_FDCWD
    mov rsi, db_path
    mov rdx, O_RDONLY
    xor r10, r10
    syscall
    cmp rax, 0
    jl .ld_empty
    mov r11, rax
    xor r10, r10
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

; save_db(rdi=buf, rsi=size)
save_db:
    mov r8, rdi
    mov r9, rsi
    mov rax, SYS_openat
    mov rdi, AT_FDCWD
    mov rsi, db_path
    mov rdx, O_WRONLY | O_CREAT | O_TRUNC
    mov r10, MODE_600
    syscall
    cmp rax, 0
    jl .sv_ret
    mov rdi, rax
    mov rsi, r8
    mov rdx, r9
    call write_all
    mov rax, SYS_close
    syscall
.sv_ret:
    ret

; print_field32(rdi=ptr, rsi=max=32) -> prints bytes until NUL or max, then newline
print_field32:
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

; zero sensitive memory and exit
exit_ok:
    ; restore echo if needed
    call restore_echo
    ; wipe secrets
    mov rdi, pass_in
    mov rsi, 64
    call memzero
    mov rdi, key8
    mov rsi, 8
    call memzero
    mov rdi, login_in
    mov rsi, FIELD_SIZE
    call memzero
    mov rdi, pwd_in
    mov rsi, FIELD_SIZE
    call memzero

    mov rax, SYS_exit
    xor rdi, rdi
    syscall
