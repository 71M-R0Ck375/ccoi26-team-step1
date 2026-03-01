# Transmission Final

- Type: Forensics
- Difficulté: Moyen
- Auteur: 0sh4w077
- Team: 71M_R0CK373

## Déscription:

L'agent avant sa compromission. L'image a été récupérée sur un
serveur chiffré à La Réunion. Les métadonnées EXIF indiquent Port-Louis, Maurice. Mais
l'agent ne se trouvait pas là-bas. **Le vrai message attend ceux qui savent chercher au-delà
de l'évident.**
https://drive.google.com/file/d/10OQrVHuckwJoBl2NZWv6A6MDfe4ncZPv/view?usp=sharing


## Phase d'investigation:
### file

```bash
$ file transmission_finale.jpg
```

Résultat:

```text
transmission_finale.jpg: JPEG image data, JFIF standard 1.01, resolution (DPI), density 96x96, segment length 16, Exif Standard: [TIFF image data, big-endian, direntries=4], baseline, precision 8, 512x512, components 3
```

C'est un fichier d'image JPEG. De ce côté, tout est normal.

### strings

```bash
$ strings transmission_finale.jpg | head -n 20
```

Résultat:

```text
JFIF
+CCOI26{n0t_th3_f1n4l_fl4g_th1s_1s_4_tr4p}
Exif
OCOI_LAGON
key=XOR(MD5(challenge2_codename),MD5(challenge1_author))
payload=x9Gmy8/cQ7kmcfp3GV67+PbN2fLOmAyhIyakRiUA5rnooZ2xot5f5nxilXp2Xfu7tP/Y8YA=
```

Hummm... intéressant!

Il me semble qu'on a découvert quelque chose d'utile !

```text
CCOI26{n0t_th3_f1n4l_fl4g_th1s_1s_4_tr4p}   ← FAUX FLAG (piège !)
key=XOR(MD5(challenge2_codename),MD5(challenge1_author))
payload=x9Gmy8/cQ7kmcfp3GV67+PbN2fLOmAyhIyakRiUA5rnooZ2xot5f5nxilXp2Xfu7tP/Y8YA=
```

Le premier flag visible est un **piège** — il est même nommé `th1s_1s_4_tr4p` !
Il faut donc analyser le `payload` chiffré avec la formule donnée par `key`.

La formule indique :
```text
key = XOR(MD5(challenge2_codename), MD5(challenge1_author))
```

Pour obtenir les deux secrets, il faut revenir aux challenges précédents.


### Calcul des MD5

```bash
$ echo -n "SPECTRE_NODE" | md5sum
```

Résultat:

```text
0db06b0ebdff12df63a9c2371c849648  -
```

```bash
$ echo -n "OCOI2026" | md5sum
```

Résultat:

```text
8922828c40152a0a71bf082e5ab41d81  -
```

La clé finale est le XOR de ces deux empreintes :
```text
key = XOR( 0db06b0ebdff12df63a9c2371c849648,
           8922828c40152a0a71bf082e5ab41d81 )
    = 8492e982fdea38d51216ca1946308bc9
```

Créons un script python !

```python3
import hashlib
import base64

challenge1_author   = 'OCOI2026'
challenge2_codename = 'SPECTRE_NODE'

payload_b64 = 'x9Gmy8/cQ7kmcfp3GV67+PbN2fLOmAyhIyakRiUA5rnooZ2xot5f5nxilXp2Xfu7tP/Y8YA='

md5_codename = hashlib.md5(challenge2_codename.encode()).hexdigest()
md5_author   = hashlib.md5(challenge1_author.encode()).hexdigest()

key_bytes = bytes(a ^ b for a, b in zip(bytes.fromhex(md5_codename), bytes.fromhex(md5_author)))

payload_bytes = base64.b64decode(payload_b64)

result = ""
for i in range(len(payload_bytes)):
    char_xor = payload_bytes[i] ^ key_bytes[i % len(key_bytes)]
    result += chr(char_xor)

print(f"Le Flag est : {result}")
```

> Lancer le script:
---

```bash
$ python3 lagon_noir.py
```

Résultat:
---
`Le Flag est : CCOI26{l4g0n_n01r_0p3r4t10n_c0mpl3t3_4g3nt_c0mpr0m1s}`

Voilà! C'est ce qui conclut ce challenge !