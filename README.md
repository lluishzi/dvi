# Magatzem privat (bdpub)

Magatzem estàtic d'arxius xifrats servit des de **GitHub Pages**.
Tots els documents es protegeixen amb **AES-256-GCM** sota una sola contrasenya.
No cal cap servidor ni cap dependència externa al navegador.

## Com funciona

```
Màquina local                       GitHub Pages (públic)
─────────────                       ────────────────────
source/passaport.pdf  ─┐
source/reserva.pdf   ─┤
                       ├─► encrypt.js ──► data/*.enc ──► navegador
VAULT_PW=la-mevapwd  ─┘                  data/salt.bin    │
                                            │             │
                                            ▼             ▼
                                    ┌─────────────────────────┐
                                    │  index.html + app.js    │
                                    │  (demana contrasenya)   │
                                    └─────────────────────────┘
```

1. L'script `encrypt.js` llegeix els fitxers de `source/`, els xifra amb
   **AES-256-GCM** (clau derivada via **PBKDF2-HMAC-SHA256** amb
   **600.000 iteracions**) i els escriu a `data/`.
2. GitHub Pages serveix `index.html` + `app.js` + `crypto.js` + `data/`.
3. Al navegador, l'usuari escriu la contrasenya. La pàgina:
   - Descarrega `data/salt.bin` (públic, 16 bytes).
   - Deriva la clau AES amb PBKDF2.
   - Descarrega i desxifra `data/index.json.enc` → llista de fitxers.
   - En clicar un, descarrega `data/<id>.enc`, el desxifra a memòria i
     llança una descàrrega `Blob` al navegador.

**Cap arxiu pla viatja pel servidor.** GitHub Pages només serveix blobs xifrats.

## Ús

### 1. Afegeix els teus documents privats

```bash
mkdir -p source
cp ~/Documents/passaport.pdf source/
cp ~/Documents/reserva.pdf source/
```

### 2. Xifra'ls

```bash
VAULT_PW='la-meva-contrasenya' node encrypt.js all
```

Si no passes `VAULT_PW`, l'script et la demanarà amagant l'entrada (només en
TTY). **No usis `PWD`**: és una variable estàndard del shell (el directori
actual) i xifraria amb el path del directori com a contrasenya sense avisar.
També pots fer-ho pas a pas:

```bash
node encrypt.js init                # crea data/salt.bin
node encrypt.js add passaport.pdf   # xifra un fitxer
node encrypt.js rebuild-index       # regenera l'índex
```

### 3. Prova-ho en local

```bash
python3 -m http.server 8000
# obre http://localhost:8000
```

> Per què cal un servidor? `file://` no permet `fetch()` a altres
> fitxers per seguretat del navegador. `localhost` és considerat
> "context segur" per la Web Crypto API.

### 4. Publica

```bash
git add index.html app.js crypto.js style.css data/ README.md .gitignore
git commit -m "actualitza magatzem"
git push
```

A la configuració del repo a GitHub, activa **Settings → Pages → Source:
Deploy from a branch → main / (root)**. La teva web quedarà servida a
`https://<usuari>.github.io/<repo>/`.

## Canviar la contrasenya

```bash
node encrypt.js password 'contrasenya-nova'
```

Et demanarà la contrasenya actual, verificarà que és correcta
(desxifrant l'índex), i re-xifrarà TOTS els fitxers amb un salt nou.
Cal tornar a fer `git push`.

## Estructura del projecte

```
bdpub/
├── index.html         # Pàgina única (entrada password + llistat)
├── app.js             # Lògica de la interfície
├── crypto.js          # Wrap de Web Crypto API (PBKDF2 + AES-GCM)
├── style.css          # Estils (mode clar/fosc automàtic)
├── encrypt.js         # Script local d'encriptació (Node.js, zero deps)
├── README.md          # Aquest fitxer
├── .gitignore         # Ignora source/ i node_modules
├── data/              # Es pujarà a GitHub
│   ├── salt.bin       # 16 bytes, NO secret
│   ├── index.json.enc # Llista de fitxers xifrada
│   └── <id-opac>.enc  # Documents xifrats; nom = HMAC (no revela res)
└── source/            # PRIVAT — mai al git
    └── ...
```

## Format dels fitxers `.enc`

```
[ 12 bytes IV  ] [ ciphertext + 16 bytes tag GCM ]
└─ per arxiu ──┘ └──────── dades xifrades ──────────┘
```

- **IV**: 12 bytes aleatoris, **únic per a cada xifrat** (crític per GCM).
- **Tag GCM**: 16 bytes, autentica el ciphertext — si algú modifica
  un byte del `.enc` al servidor o en trànsit, la desencriptació falla.
- El `salt` (16 bytes) és a `data/salt.bin` separat. No és secret,
  només garanteix que la mateixa contrasenya no produeixi la mateixa
  clau si mai es rota.

## Notes de seguretat

- **Els noms dels `.enc` són opacs** (HMAC-SHA256 de la clau derivada).
  El nom real de cada document només existeix dins de `index.json.enc`,
  que està xifrat. Ningú que navegui pel repo públic pot deduir què
  conté cap fitxer a partir del seu nom.
- **Les mides dels `.enc` són ~iguals a l'original** (+28 bytes). Si
  vols amagar també la mida, afegeix *padding* als fitxers font.
- **La contrasenya és l'única cosa secreta.** Si l'oblides, no hi ha
  recuperació — els fitxers són irrecuperables per disseny. Com que el
  salt i tots els blobs són públics, un atacant pot fer força bruta
  offline sense límit: usa una passphrase llarga i única.
- Usa una contrasenya llarga i única. Un gestor de contrasyes
  (Bitwarden, KeePass, etc.) és recomanable.
- **AES-GCM autentica cada fitxer.** Un `.enc` modificat al servidor
  o en trànsit fallarà la desencriptació i veuràs un error.
- La clau derivada viu només a la memòria del navegador mentre la
  pestanya és oberta. Mai es desa la contrasenya en clar ni en
  `localStorage`.
- 600.000 iteracions PBKDF2 (~1–2 s al navegador). És el valor
  recomanat per OWASP per a PBKDF2-HMAC-SHA256. Es defineix a la
  constant `ITER` de `encrypt.js` i `PBKDF2_ITER` de `crypto.js`;
  els dos valors **han de coincidir sempre**.
- HTTPS és obligatori: GitHub Pages el serveix per defecte. La Web
  Crypto API rebutja contextos no segurs.
- GitHub Pages és **públicament accessible** — qualsevol que endevini
  la URL pot baixar blobs xifrats. La seguretat recau 100% en la
  contrasenya.

## Llicència

El codi és teu. Fes-ne el que vulguis.
