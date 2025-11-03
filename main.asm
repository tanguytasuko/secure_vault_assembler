; ============================================================================
; Secure Vault - Gestionnaire d’identifiants (XOR-ECB, clé 8 octets)
; Linux x86-64, NASM, appels systèmes uniquement
;
; Renforcements sécurité (v3) :
;   - En-tête chiffré 16 octets : [nonce(8)][tag(8)]
;       * tag_v3 = FNV1a64( pw_tagkey8 || nonce || "SV3" )
;         (pw_tagkey8 = FNV1a64(mot_de_passe_complet))
;       * rétro-compatibilité : v2 utilisait "SV" avec key8 (8 premiers octets du mot de passe)
;   - Sous-clé PAR ENREGISTREMENT (64 o) :
;       subkey_i = FNV1a64( key8 || nonce || uint64_le(i) )
;       -> Chaque record (64 o) est XOR avec sa sous-clé (répétée sur 8 qwords)
;   - Authentification immédiate au démarrage ; migration auto v1/v2 -> v3
;   - Saisie de mot de passe masquée ; bourrage aléatoire des champs (32 o)
;   - Nettoyage mémoire des secrets avant la sortie (key8, pw_tagkey8, etc.)
;
; Construction :
;   nasm -felf64 main.asm -o main.o && ld -o secure_vault main.o
; Exécution :
;   ./secure_vault
; ============================================================================

BITS 64
default rel

; ---- Appels systèmes Linux ----
%define SYS_read      0
%define SYS_write     1
%define SYS_close     3
%define SYS_ioctl    16
%define SYS_openat  257
%define SYS_exit     60

%define AT_FDCWD    -100

; ---- Flags / modes (décimaux) ----
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
%define HEAD1_LEN       8      ; ancien en-tête ("SVDBv1\0")
%define HEAD2_LEN      16      ; en-tête v2/v3 : nonce(8) + tag(8)

; ioctl termios
%define TCGETS     0x5401
%define TCSETS     0x5402
%define ECHO_BIT       8       ; bit ECHO dans c_lflag

section .data
    db_path:        db "vault.db", 0
    urand_path:     db "/dev/urandom", 0

    msg_welcome:    db "Secure Vault", 10
    len_welcome     equ $-msg_welcome

    msg_pass:       db "Mot de passe de la base : ", 0
    msg_pass_new:   db "Nouveau mot de passe de la base : ", 0
    msg_short:      db "Le mot de passe doit faire au moins 8 caracteres.", 10
    len_short       equ $-msg_short

    msg_menu:       db 10, "Choisir :", 10, "  1) Ajouter un identifiant", 10, "  2) Afficher la base", 10, "  3) Quitter", 10, "Choix : ", 0
    msg_login:      db "Identifiant (<=31 caracteres) : ", 0
    msg_pwd:        db "Mot de passe (<=31 caracteres) : ", 0
    msg_saved:      db "Enregistre.", 10
    len_saved       equ $-msg_saved

    msg_db_empty:   db "(Base vide ou absente)", 10
    len_db_empty    equ $-msg_db_empty

    msg_bad_choice: db "Choix invalide.", 10
    len_bad_choice  equ $-msg_bad_choice

    msg_db_big:     db "Base trop grande", 10
    len_db_big      equ $-msg_db_big

    msg_wrong:      db "Mauvais mot de passe.", 10
    len_wrong       equ $-msg_wrong

    msg_corrupt:    db "Base corrompue (taille incoherente).", 10
    len_corrupt     equ $-msg_corrupt

    msg_init:       db "Base init.", 10
    len_init        equ $-msg_init

    msg_migrated:   db "Migration effectuee : authentification activee.", 10
    len_migrated    equ $-msg_migrated

    lbl_login:      db "Identifiant : ", 0
    lbl_pass:       db "Mot de passe : ", 0
    sep_line:       db "----------------", 10
    len_sep_line    equ $-sep_line

    nl:             db 10

    ; ancien magic v1 (8 octets) pour detection
    head1_magic:    db "SVDBv1", 0, 0

    ; Constantes FNV-1a 64 bits
    FNV_OFFSET:     dq 0xcbf29ce484222325
    FNV_PRIME:      dq 0x00000100000001b3

section .bss
    key8:       resb 8
    pw_tagkey8: resb 8          ; FNV1a64(pass_in[0..len-1]) pour AUTH v3
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

; ----------------------------------------------------------------------------
; Point d’entrée
; ----------------------------------------------------------------------------
_start:
    ; bannière
    mov rdi, STDOUT
    mov rsi, msg_welcome
    mov rdx, len_welcome
    call write_all

    ; Charger la base pour savoir si première exécution
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

; ----------------------------------------------------------------------------
; Demande du mot de passe de base (masqué)
; ----------------------------------------------------------------------------
.prompt_pw:
.pass_loop:
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
    call read_line            ; rax = longueur
    mov rbx, rax              ; sauver longueur
    call restore_echo
    ; retour ligne manuel après saisie masquée
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
    ; clé = 8 premiers octets du mot de passe (pour CHIFFREMENT)
    mov rdi, key8
    mov rsi, 8
    call memzero
    mov rdi, key8
    mov rsi, pass_in
    mov rdx, 8
    call memcpy

    ; pw_tagkey8 = FNV1a64(mot_de_passe_complet) (pour AUTH)
    mov rdi, pass_in          ; ptr
    mov rsi, rbx              ; len
    call compute_fnv64_buf
    mov [pw_tagkey8], rax

    ; authentifier / initialiser / migrer (sort si mauvais mot de passe)
    call auth_or_init

; ----------------------------------------------------------------------------
; Menu principal
; ----------------------------------------------------------------------------
main_menu:
    mov rdi, msg_menu
    call print_cstr
    mov rdi, choice_in
    mov rsi, 7
    call read_line
    mov al, [choice_in]
    cmp al, '1'
    je do_add
    cmp al, '2'
    je do_show
    cmp al, '3'
    je exit_ok
    mov rdi, STDOUT
    mov rsi, msg_bad_choice
    mov rdx, len_bad_choice
    call write_all
    jmp main_menu

; ----------------------------------------------------------------------------
; F1 : Ajouter un identifiant
; ----------------------------------------------------------------------------
do_add:
    ; identifiant
    mov rdi, msg_login
    call print_cstr
    mov rdi, login_in
    mov rsi, FIELD_SIZE
    call memzero
    mov rdi, login_in
    mov rsi, FIELD_SIZE-1
    call read_line

    ; mot de passe (masque)
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
    ; retour ligne manuel
    mov rax, SYS_write
    mov rdi, STDOUT
    mov rsi, nl
    mov rdx, 1
    syscall

    ; charger la base
    mov rdi, db_buf
    mov rsi, MAX_DB
    call load_db
    mov [db_size], rax

    ; taille minimale pour en-tete
    cmp qword [db_size], HEAD2_LEN
    jb .da_small

    ; dechiffrer en-tete uniquement
    mov rdi, db_buf
    mov rsi, HEAD2_LEN
    mov rdx, key8
    call xor_buf

    ; verifier tag v3 (avec pw_tagkey8)
    mov rdi, pw_tagkey8
    mov rsi, db_buf          ; ptr nonce
    call compute_tag3
    mov r8, [db_buf + 8]
    cmp rax, r8
    jne .maybe_v2
    jmp .ok_hdr

.da_small:
    mov rdi, STDOUT
    mov rsi, msg_corrupt
    mov rdx, len_corrupt
    call write_all
    jmp main_menu

.maybe_v2:
    ; essayer tag v2 puis migrer v2 -> v3
    mov rdi, key8
    mov rsi, db_buf
    call compute_tag2
    mov r8, [db_buf + 8]
    cmp rax, r8
    jne .bad_pw

    ; dechiffrer le corps legacy (si >16)
    mov rax, [db_size]
    cmp rax, HEAD2_LEN
    jbe .no_legacy_body
    sub rax, HEAD2_LEN
    mov rsi, rax
    mov rdi, db_buf + HEAD2_LEN
    mov rdx, key8
    call xor_buf
.no_legacy_body:

    ; re-chiffrer en v3 par enregistrement (borne end_ptr en r8)
    mov rax, [db_size]
    cmp rax, HEAD2_LEN
    jbe .count_zero_mig
    sub rax, HEAD2_LEN
    shr rax, 6
    jmp .count_set_mig
.count_zero_mig:
    xor rax, rax
.count_set_mig:
    mov rsi, rax                ; nb records
    mov rdi, db_buf + HEAD2_LEN ; debut records
    mov rdx, key8
    mov rcx, db_buf             ; ptr nonce
    mov rax, [db_size]
    lea r8,  [db_buf + rax]     ; end_ptr
    call records_xor_v3

    ; nouveau tag v3 (avec pw_tagkey8) + re-chiffrer en-tete + sauver
    mov rdi, pw_tagkey8
    mov rsi, db_buf
    call compute_tag3
    mov [db_buf + 8], rax

    mov rdi, db_buf
    mov rsi, HEAD2_LEN
    mov rdx, key8
    call xor_buf

    mov rdi, db_buf
    mov rsi, [db_size]
    call save_db
    jmp .hdr_reloaded

.bad_pw:
    mov rdi, STDOUT
    mov rsi, msg_wrong
    mov rdx, len_wrong
    call write_all
    jmp main_menu

.hdr_reloaded:
    ; recharger + dechiffrer l’en-tete (v3)
    mov rdi, db_buf
    mov rsi, MAX_DB
    call load_db
    mov [db_size], rax
    mov rdi, db_buf
    mov rsi, HEAD2_LEN
    mov rdx, key8
    call xor_buf

.ok_hdr:
    ; dechiffrer les records (v3) avec end_ptr
    mov rax, [db_size]
    cmp rax, HEAD2_LEN
    jbe .count_zero_ok
    sub rax, HEAD2_LEN
    shr rax, 6
    jmp .count_set_ok
.count_zero_ok:
    xor rax, rax
.count_set_ok:
    mov rsi, rax                ; nb records
    mov rdi, db_buf + HEAD2_LEN
    mov rdx, key8
    mov rcx, db_buf
    mov rax, [db_size]
    lea r8,  [db_buf + rax]     ; end_ptr
    call records_xor_v3         ; dechiffre en place

    ; place disponible ?
    mov rax, [db_size]
    add rax, REC_SIZE
    cmp rax, MAX_DB
    ja  .too_big

    ; ajouter un enregistrement (clair + bourrage aleatoire)
    mov rbx, [db_size]

    ; champ identifiant (32)
    lea rdi, [db_buf + rbx]
    mov rsi, FIELD_SIZE
    call fill_random
    lea rdi, [db_buf + rbx]
    mov rsi, login_in
    mov rdx, FIELD_SIZE
    call copy_cstr

    ; champ mot de passe (32)
    lea rdi, [db_buf + rbx + FIELD_SIZE]
    mov rsi, FIELD_SIZE
    call fill_random
    lea rdi, [db_buf + rbx + FIELD_SIZE]
    mov rsi, pwd_in
    mov rdx, FIELD_SIZE
    call copy_cstr

    add rbx, REC_SIZE
    mov [db_size], rbx

    ; re-chiffrer les records (v3) avec end_ptr mis a jour
    mov rax, [db_size]
    cmp rax, HEAD2_LEN
    jbe .count_zero_end
    sub rax, HEAD2_LEN
    shr rax, 6
    jmp .count_set_end
.count_zero_end:
    xor rax, rax
.count_set_end:
    mov rsi, rax
    mov rdi, db_buf + HEAD2_LEN
    mov rdx, key8
    mov rcx, db_buf
    mov rax, [db_size]
    lea r8,  [db_buf + rax]     ; end_ptr
    call records_xor_v3

    ; tag v3 (avec pw_tagkey8) + (re)chiffrer en-tete + sauvegarde
    mov rdi, pw_tagkey8
    mov rsi, db_buf
    call compute_tag3
    mov [db_buf + 8], rax

    mov rdi, db_buf
    mov rsi, HEAD2_LEN
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


; ----------------------------------------------------------------------------
; F2 : Afficher la base
; ----------------------------------------------------------------------------
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
    ; taille min en-tete
    cmp qword [db_size], HEAD2_LEN
    jb .wrong

    ; dechiffrer l’en-tete
    mov rdi, db_buf
    mov rsi, HEAD2_LEN
    mov rdx, key8
    call xor_buf

    ; verifier tag v3 (avec pw_tagkey8)
    mov rdi, pw_tagkey8
    mov rsi, db_buf
    call compute_tag3
    mov r8, [db_buf + 8]
    cmp rax, r8
    jne .wrong

    ; dechiffrer les records (v3) avec end_ptr
    mov rax, [db_size]
    cmp rax, HEAD2_LEN
    jbe .sh_count_zero
    sub rax, HEAD2_LEN
    shr rax, 6
    jmp .sh_count_set
.sh_count_zero:
    xor rax, rax
.sh_count_set:
    mov rsi, rax
    mov rdi, db_buf + HEAD2_LEN
    mov rdx, key8
    mov rcx, db_buf
    mov rax, [db_size]
    lea r8,  [db_buf + rax]     ; end_ptr
    call records_xor_v3

    ; iterer les enregistrements en clair
    mov rbx, HEAD2_LEN
.loop:
    mov rax, [db_size]
    cmp rbx, rax
    jae .done

    mov rax, [db_size]
    sub rax, rbx
    cmp rax, REC_SIZE
    jb .done

    ; separateur AVANT chaque entree
    mov rdi, STDOUT
    mov rsi, sep_line
    mov rdx, len_sep_line
    call write_all

    ; identifiant
    mov rdi, lbl_login
    call print_cstr
    lea rdi, [db_buf + rbx]
    mov rsi, FIELD_SIZE
    call print_field32

    ; mot de passe
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


; ----------------------------------------------------------------------------
; Authentification / initialisation / migration
; ----------------------------------------------------------------------------
auth_or_init:
    ; recharger par prudence
    mov rdi, db_buf
    mov rsi, MAX_DB
    call load_db
    mov [db_size], rax

    cmp qword [db_size], 0
    jne .have
    ; nouvelle base -> créer en-tête v3
    mov rdi, nonce8
    mov rsi, 8
    call fill_random

    mov rdi, db_buf
    mov rsi, nonce8
    mov rdx, 8
    call memcpy

    ; tag v3 avec pw_tagkey8
    mov rdi, pw_tagkey8
    mov rsi, db_buf
    call compute_tag3
    mov [db_buf + 8], rax
    mov qword [db_size], HEAD2_LEN

    ; chiffrer l’en-tête et sauver
    mov rdi, db_buf
    mov rsi, HEAD2_LEN
    mov rdx, key8
    call xor_buf
    mov rdi, db_buf
    mov rsi, [db_size]
    call save_db

    mov rdi, STDOUT
    mov rsi, msg_init
    mov rdx, len_init
    call write_all
    ret

.have:
    ; taille minimale
    cmp qword [db_size], HEAD2_LEN
    jb .bad

    ; déchiffrer en-tête
    mov rdi, db_buf
    mov rsi, HEAD2_LEN
    mov rdx, key8
    call xor_buf

    ; tenter v3 (avec pw_tagkey8)
    mov rdi, pw_tagkey8
    mov rsi, db_buf
    call compute_tag3
    mov r8, [db_buf + 8]
    cmp rax, r8
    je .ok

    ; tenter v2 (sinon mot de passe faux)
    mov rdi, key8
    mov rsi, db_buf
    call compute_tag2
    mov r8, [db_buf + 8]
    cmp rax, r8
    jne .bad

    ; déchiffrer corps legacy
    mov rax, [db_size]
    cmp rax, HEAD2_LEN
    jbe .no_legacy_body2
    sub rax, HEAD2_LEN
    mov rsi, rax
    mov rdi, db_buf + HEAD2_LEN
    mov rdx, key8
    call xor_buf
.no_legacy_body2:

    ; re-chiffrer v3
    mov rax, [db_size]
    cmp rax, HEAD2_LEN
    jbe .ac_count_zero
    sub rax, HEAD2_LEN
    shr rax, 6
    jmp .ac_count_set
.ac_count_zero:
    xor rax, rax
.ac_count_set:
    mov rsi, rax
    mov rdi, db_buf + HEAD2_LEN
    mov rdx, key8
    mov rcx, db_buf
    call records_xor_v3

    ; nouveau tag v3 (pw_tagkey8) + re-chiffrer en-tête + sauver
    mov rdi, pw_tagkey8
    mov rsi, db_buf
    call compute_tag3
    mov [db_buf + 8], rax

    mov rdi, db_buf
    mov rsi, HEAD2_LEN
    mov rdx, key8
    call xor_buf

    mov rdi, db_buf
    mov rsi, [db_size]
    call save_db

    mov rdi, STDOUT
    mov rsi, msg_migrated
    mov rdx, len_migrated
    call write_all
    ret

.ok:
    ret
.bad:
    mov rdi, STDOUT
    mov rsi, msg_wrong
    mov rdx, len_wrong
    call write_all
    jmp exit_ok

; ----------------------------------------------------------------------------
; Helpers I/O et mémoire
; ----------------------------------------------------------------------------
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

print_cstr:
    push rdi
    call strlen
    mov rdx, rax
    pop rsi
    mov rdi, STDOUT
    call write_all
    ret

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

; lit une ligne (jusqu’à '\n') dans [rdi], max rsi (sans le NUL)
; renvoie rax = longueur ; écrit un NUL final
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

; copie une c-string dans dst (max rdx), garantit NUL final
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

; XOR buffer avec clé 8 octets répétée
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

; Remplit [rdi..rdi+rsi[ avec /dev/urandom (sinon zéros)
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

; ----------------------------------------------------------------------------
; Hash FNV-1a 64 bits d'un buffer (pour pw_tagkey8)
; compute_fnv64_buf(rdi=ptr, rsi=len) -> rax
; ----------------------------------------------------------------------------
compute_fnv64_buf:
    mov rax, [rel FNV_OFFSET]
    test rsi, rsi
    jz .cf_done
.cf_loop:
    mov dl, [rdi]
    xor al, dl
    mov r8, [rel FNV_PRIME]
    mul r8
    inc rdi
    dec rsi
    jnz .cf_loop
.cf_done:
    ret

; ----------------------------------------------------------------------------
; Tags et sous-clés (FNV-1a 64)
; ----------------------------------------------------------------------------
; tag v2 = FNV1a64(key8 || nonce || "SV")
compute_tag2:
    mov rax, [rel FNV_OFFSET]
    xor rcx, rcx
.ct2_k:
    cmp rcx, 8
    jae .ct2_n
    mov dl, [rdi + rcx]
    xor al, dl
    mov r9, [rel FNV_PRIME]
    mul r9
    inc rcx
    jmp .ct2_k
.ct2_n:
    xor rcx, rcx
.ct2_nl:
    cmp rcx, 8
    jae .ct2_c
    mov dl, [rsi + rcx]
    xor al, dl
    mov r9, [rel FNV_PRIME]
    mul r9
    inc rcx
    jmp .ct2_nl
.ct2_c:
    mov dl, 'S'
    xor al, dl
    mov r9, [rel FNV_PRIME]
    mul r9
    mov dl, 'V'
    xor al, dl
    mov r9, [rel FNV_PRIME]
    mul r9
    ret

; tag v3 = FNV1a64(tagkey8 || nonce || "SV3")
; (tagkey8 = pw_tagkey8 = FNV1a64(mot_de_passe_complet))
compute_tag3:
    mov rax, [rel FNV_OFFSET]
    xor rcx, rcx
.ct3_k:
    cmp rcx, 8
    jae .ct3_n
    mov dl, [rdi + rcx]
    xor al, dl
    mov r9, [rel FNV_PRIME]
    mul r9
    inc rcx
    jmp .ct3_k
.ct3_n:
    xor rcx, rcx
.ct3_nl:
    cmp rcx, 8
    jae .ct3_c
    mov dl, [rsi + rcx]
    xor al, dl
    mov r9, [rel FNV_PRIME]
    mul r9
    inc rcx
    jmp .ct3_nl
.ct3_c:
    mov dl, 'S'
    xor al, dl
    mov r9, [rel FNV_PRIME]
    mul r9
    mov dl, 'V'
    xor al, dl
    mov r9, [rel FNV_PRIME]
    mul r9
    mov dl, '3'
    xor al, dl
    mov r9, [rel FNV_PRIME]
    mul r9
    ret

; sous-clé 8 o = FNV1a64(key8 || nonce || index_u64_le)
compute_subkey:
    mov rax, [rel FNV_OFFSET]
    ; key8
    xor rcx, rcx
.cs_k:
    cmp rcx, 8
    jae .cs_n
    mov dl, [rdi + rcx]
    xor al, dl
    mov r8, [rel FNV_PRIME]
    mul r8
    inc rcx
    jmp .cs_k
.cs_n:
    xor rcx, rcx
.cs_nl:
    cmp rcx, 8
    jae .cs_i
    mov dl, [rsi + rcx]
    xor al, dl
    mov r8, [rel FNV_PRIME]
    mul r8
    inc rcx
    jmp .cs_nl
.cs_i:
    mov r9, rdx           ; index
    mov rcx, 8
.cs_il:
    mov dl, r9b
    xor al, dl
    mov r8, [rel FNV_PRIME]
    mul r8
    shr r9, 8
    dec rcx
    jnz .cs_il
    ret

; ----------------------------------------------------------------------------
; Chiffrement/Dechiffrement des enregistrements (v3)
; ----------------------------------------------------------------------------
; records_xor_v3(rdi=ptr_records, rsi=nb_records, rdx=key8_ptr, rcx=nonce_ptr, r8=end_ptr)
; -> XOR chaque record de 64 octets avec sa sous-clé (répétée 8x), avec contrôle de bornes
records_xor_v3:
    push r12
    push r13
    push r11
    push r10
    push r15

    mov  r12, rdx              ; key8 ptr
    mov  r13, rcx              ; nonce ptr
    mov  r11, rdi              ; base records (db_buf + 16)
    mov  r15, r8               ; fin valide (db_buf + db_size)
    xor  r10, r10              ; i = 0

.rx_loop:
    ; stop si i >= nb_records
    cmp  r10, rsi
    jae  .rx_done

    ; 1) Calculer la sous-clé d'abord (compute_subkey clobber r9)
    mov  rdi, r12              ; key8
    mov  rsi, r13              ; nonce
    mov  rdx, r10              ; index i
    call compute_subkey        ; rax = subkey
    mov  r8, rax               ; r8 = sous-clé 8 o

    ; 2) Puis calculer l'adresse du record i
    mov  r9, r10
    shl  r9, 6                 ; i*64
    add  r9, r11               ; ptr_record

    ; 3) Contrôle de bornes : (ptr_record + 64) <= end_ptr ?
    lea  rax, [r9 + 64]
    cmp  rax, r15
    ja   .rx_done              ; on arrête si dépasserait

    ; 4) XOR des 8 qwords du record avec la sous-clé
    mov  rax, [r9 +  0]
    xor  rax, r8
    mov  [r9 +  0], rax

    mov  rax, [r9 +  8]
    xor  rax, r8
    mov  [r9 +  8], rax

    mov  rax, [r9 + 16]
    xor  rax, r8
    mov  [r9 + 16], rax

    mov  rax, [r9 + 24]
    xor  rax, r8
    mov  [r9 + 24], rax

    mov  rax, [r9 + 32]
    xor  rax, r8
    mov  [r9 + 32], rax

    mov  rax, [r9 + 40]
    xor  rax, r8
    mov  [r9 + 40], rax

    mov  rax, [r9 + 48]
    xor  rax, r8
    mov  [r9 + 48], rax

    mov  rax, [r9 + 56]
    xor  rax, r8
    mov  [r9 + 56], rax

    inc  r10
    jmp  .rx_loop

.rx_done:
    pop  r15
    pop  r10
    pop  r11
    pop  r13
    pop  r12
    ret

; ----------------------------------------------------------------------------
; Terminal : masquer / restaurer l’echo
; ----------------------------------------------------------------------------
disable_echo:
    mov rax, SYS_ioctl
    mov rdi, STDIN
    mov rsi, TCGETS
    mov rdx, term_old
    syscall
    cmp rax, 0
    jl .de_ret
    ; copie
    mov rdi, term_new
    mov rsi, term_old
    mov rdx, 64
    call memcpy
    ; clear ECHO dans c_lflag (offset 12)
    mov eax, [term_new + 12]
    and eax, ~ECHO_BIT
    mov [term_new + 12], eax
    ; appliquer
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

; ----------------------------------------------------------------------------
; Fichiers : charger / sauver la base
; ----------------------------------------------------------------------------
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

; ----------------------------------------------------------------------------
; Affichage d’un champ 32 octets (jusqu’au NUL), plus saut de ligne
; ----------------------------------------------------------------------------
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

; ----------------------------------------------------------------------------
; Sortie propre (restaure l’echo, nettoie les secrets)
; ----------------------------------------------------------------------------
exit_ok:
    call restore_echo
    mov rdi, pass_in
    mov rsi, 64
    call memzero
    mov rdi, key8
    mov rsi, 8
    call memzero
    mov rdi, pw_tagkey8
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
