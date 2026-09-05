# CVELab pentru Linux

Acest bundle instaleaza CVELab nativ pe Linux. Docker Desktop si WSL nu sunt necesare.

## Cerinte

- distributie Linux suportata de Python si Docker Engine;
- Python 3.11 sau mai nou, cu modulul `venv`;
- Git;
- Docker Engine activ;
- pluginul Docker Compose;
- accesul utilizatorului curent la socketul Docker.

## Instalare

Extrage arhiva si ruleaza:

```bash
tar -xzf cvelab-*-linux.tar.gz
cd cvelab-*-linux
./install.sh
```

Daca `~/.local/bin` nu este in `PATH`:

```bash
export PATH="$HOME/.local/bin:$PATH"
```

## Rulare

```bash
cvelab --output-root "$HOME/cvelab-labs" \
  auto CVE-YYYY-NNNNN \
  --ai on \
  --key \
  --model gpt-5.6-sol
```

La promptul `OpenAI API key:` introdu numai cheia API. Cheia nu este salvata de installer.

## CVE fara fix public

Daca repository-ul si revizia vulnerabila sunt verificabile, dar nu exista un fix public exact, CVELab poate genera `VULNERABLE_ONLY_REPRODUCTION`. Raportul trebuie sa indice:

```json
{
  "real_poc_verified": true,
  "fix_status": "PUBLIC_FIX_NOT_IDENTIFIED",
  "patched_tested": false,
  "differential_confirmed": false
}
```

## Dezinstalare

Installerul nu modifica pachetele sistemului. Pentru dezinstalare elimina mediul virtual si symlink-ul create in:

```text
~/.local/share/cvelab/venv
~/.local/bin/cvelab
```

Datele din directoarele de laboratoare nu sunt sterse automat.

Pentru configurare, utilizare, interpretarea rezultatelor si depanare consulta
`GUIDE.md` din repository.
