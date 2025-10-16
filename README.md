# secure_vault_assembler

Petite database en **assembleur x86-64 (NASM)** pour Linux, basé sur un chiffrement XOR (clé 8 octets) avec un tag d’authent. Interface en ligne de commande, sans dépendances (appels systèmes uniquement).

## Ce que ça fait

* Protège une base (`vault.db`) par mot de passe.
  * **Chiffrement**: XOR-ECB avec une clé de **8 octets** (les 8 premiers octets du mot de passe).
  * **Authentification**: vérifie **tout le mot de passe** via `pw_tagkey8 = FNV1a-64(pass_entier)`.
* Ajoute des paires **Identifiant / Mot de passe** (32 octets max chacun, bourrage aléatoire).
* Affiche le contenu après authentification.
* Nettoie la mémoire sensible à la sortie.
* Gère la **migration auto v1/v2 → v3** du format de base.

## Comment faire fonctionner

### Prérequis

* Linux x86-64, `nasm`, `ld`.

### Compilation

```bash
nasm -felf64 main.asm -o main.o && ld -o secure_vault main.o
# (option debug) :
# nasm -felf64 -g -F dwarf main.asm -o main.o && ld -o secure_vault main.o
```

### Exécution

```bash
./secure_vault
```

* Au premier lancement : saisir un **mot de passe de base** (≥ 8 caractères).
* Menu :

  1. Ajouter un identifiant
  2. Afficher la base
  3. Quitter

Le fichier chiffré est créé/lu à côté de l’exécutable : **`vault.db`**.

## Ce qu’il se passe derrière en bref

* **En-tête (16 o)** : `[nonce(8)][tag(8)]`, chiffré XOR avec la **clé 8 o** (les 8 premiers octets du mot de passe).

  * **v3** :
    `tag_v3 = FNV1a-64( pw_tagkey8 || nonce || "SV3" )`
    avec `pw_tagkey8 = FNV1a-64(mot_de_passe_complet)`.
    → L’authent dépend **de tout le mot de passe**, pas uniquement des 8 premiers octets.
  * **Compat v2** (lecture/migration) :
    `tag_v2 = FNV1a-64( key8 || nonce || "SV" )` (où `key8` = 8 premiers octets).
* **Données** : enregistrements de **64 o** = `login(32)` + `password(32)`.
  Chaque enregistrement est XOR avec une **sous-clé dédiée** :

  ```
  subkey_i = FNV1a-64( key8 || nonce || uint64_le(i) )
  ```

  (la sous-clé 8 o est répétée sur 8 qwords).
* **Aléa** : les champs sont bourrés avec `/dev/urandom`.
* **Sécurité pratique** : écho du terminal coupé pour la saisie, et **effacement** des buffers secrets avant `exit`.
* **Compat** : si une ancienne base (v1/v2) est détectée, elle est lue, vérifiée, puis **re-chiffrée en v3** automatiquement.
