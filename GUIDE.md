# Ghid CVELab

Acest ghid descrie instalarea, rularea si interpretarea rezultatelor CVELab.
Platforma recomandata este Linux nativ cu Docker Engine si pluginul Compose.

## 1. Ce face CVELab

CVELab porneste de la un identificator CVE si incearca sa:

1. colecteze metadate si referinte publice;
2. identifice repository-ul si revizia vulnerabila;
3. identifice fixul public, daca acesta exista;
4. construiasca un laborator Docker local;
5. execute un validator specific vulnerabilitatii;
6. confirme un efect de securitate observabil;
7. produca dovezi, un walkthrough si un raport.

CVELab nu considera un marker reflectat sau un camp hardcodat drept PoC. Un
rezultat este acceptat numai daca validatorul executa testul si observa efectul
definit in contractul PoC.

## 2. Rezultatele posibile

### SOURCE_REPRODUCTION

Exista revizii publice vulnerabila si reparata. Acelasi test demonstreaza
vulnerabilitatea pe prima revizie si respingerea pe revizia patched.

Semnale asteptate:

```json
{
  "ok": true,
  "real_poc_verified": true,
  "patched_tested": true,
  "differential_confirmed": true
}
```

### VULNERABLE_ONLY_REPRODUCTION

Revizia vulnerabila este publica si verificabila, dar nu exista un commit de fix
public identificat cu suficienta incredere. CVELab nu inventeaza un serviciu
patched.

Semnale asteptate:

```json
{
  "ok": true,
  "real_poc_verified": true,
  "fix_status": "PUBLIC_FIX_NOT_IDENTIFIED",
  "patched_tested": false,
  "differential_confirmed": false
}
```

Acest rezultat demonstreaza vulnerabilitatea, dar nu valideaza remedierea.

### ARTIFACT_REQUIRED

Produsul vulnerabil nu este disponibil public sau necesita autentificare,
entitlement, licenta, firmware ori mediu hardware specific. CVELab nu ocoleste
aceste cerinte si nu inlocuieste produsul cu o simulare.

### POC_NOT_GENERATED

Datele publice nu sustin o reproducere fidela. Acest rezultat este preferabil
unui PoC fabricat sau atribuit unei revizii neverificate.

## 3. Instalare recomandata pe Linux

### Cerinte

- Python 3.11 sau mai nou;
- modulul Python `venv`;
- Git;
- Docker Engine activ;
- pluginul Docker Compose;
- acces la internet pentru surse publice, imagini si API;
- accesul utilizatorului la socketul Docker.

Pe Debian, Ubuntu sau Kali, numele uzuale ale pachetelor de baza sunt:

```bash
sudo apt update
sudo apt install -y git python3 python3-venv
```

Instaleaza Docker Engine din repository-ul oficial potrivit distributiei:
[Docker Engine installation](https://docs.docker.com/engine/install/).

Verifica mediul:

```bash
python3 --version
git --version
docker version
docker compose version
```

Apartenenta la grupul `docker` acorda privilegii echivalente accesului root.
Foloseste aceasta configuratie numai pe un sistem de laborator controlat.

### Instalare din Git

```bash
git clone https://github.com/AndreiIonascu17/cvelab.git
cd cvelab
python3 -m venv .venv
source .venv/bin/activate
python -m pip install .
cvelab --help
```

Pastreaza repository-ul si laboratoarele pe filesystem-ul Linux. Evita rularea
dintr-o partitie NTFS montata daca performanta build-urilor este importanta.

### Instalare din bundle

Construieste bundle-ul:

```bash
bash scripts/build-linux.sh
```

Instaleaza bundle-ul rezultat:

```bash
cd dist-linux
sha256sum --check cvelab-0.5.0-linux.tar.gz.sha256
tar -xzf cvelab-0.5.0-linux.tar.gz
cd cvelab-0.5.0-linux
./install.sh
```

Installerul verifica SHA-256 pentru wheel si instaleaza fara `sudo` in:

```text
~/.local/share/cvelab/venv
~/.local/bin/cvelab
```

## 4. API key

Varianta recomandata foloseste promptul mascat:

```bash
cvelab auto CVE-YYYY-NNNNN --ai on --key --model gpt-5.6-sol
```

Cand apare:

```text
OpenAI API key:
```

introdu numai cheia API. Nu introduce din nou comanda `cvelab`.

Alternativ:

```bash
export OPENAI_API_KEY="cheia-ta"
export CVELAB_MODEL="gpt-5.6-sol"
cvelab auto CVE-YYYY-NNNNN --ai on
```

Nu publica cheia in Git, capturi de ecran, shell history sau rapoarte. Revoca
imediat orice cheie expusa.

## 5. Rulare end-to-end

Comanda principala:

```bash
cvelab --output-root "$HOME/cvelab-labs" \
  auto CVE-YYYY-NNNNN \
  --ai on \
  --key \
  --model gpt-5.6-sol
```

Aceasta comanda face discovery, generare, build, pornire, validare si raportare.

Daca referintele sunt deja cunoscute:

```bash
cvelab --output-root "$HOME/cvelab-labs" \
  auto CVE-YYYY-NNNNN \
  --repo https://github.com/owner/project.git \
  --vulnerable-ref COMMIT_VULNERABIL \
  --fixed-ref COMMIT_FIX \
  --ai on \
  --key \
  --model gpt-5.6-sol
```

Fara fix public, omite `--fixed-ref`:

```bash
cvelab --output-root "$HOME/cvelab-labs" \
  auto CVE-YYYY-NNNNN \
  --repo https://github.com/owner/project.git \
  --vulnerable-ref COMMIT_VULNERABIL \
  --ai on \
  --key \
  --model gpt-5.6-sol
```

## 6. Rularea unui laborator existent

```bash
cvelab --output-root "$HOME/cvelab-labs" run CVE-YYYY-NNNNN
```

Foloseste `--keep` numai cand vrei sa inspectezi containerele dupa validare:

```bash
cvelab --output-root "$HOME/cvelab-labs" run CVE-YYYY-NNNNN --keep
```

Cleanup-ul normal este limitat la proiectul Compose al laboratorului. Nu trebuie
folosit `docker system prune --volumes` pentru acest flux.

## 7. Livrabile

Rezultatele sunt scrise in:

```text
$HOME/cvelab-labs/CVE-YYYY-NNNNN/
```

Fisiere importante:

- `report.json`: verdictul automat si verificarile PoC;
- `e2e/result.json`: rezultatul profilului E2E, daca acesta exista;
- `validator/validator.py`: validatorul executabil generat;
- `artifacts/EVIDENCE.json`: dovezi structurate si provenienta;
- `artifacts/WALKTHROUGH.md`: reproducerea manuala;
- `artifacts/REPORT.md`: raportul tehnic si limitarile;
- `plan.json`: tipul laboratorului, reviziile si contractul exploit;
- `docker-compose.yml`: serviciile laboratorului;
- `source/`: snapshot-urile de cod folosite.

Verdictul principal este `real_poc_verified`. Pentru un test cu fix trebuie sa
fie adevarat si `differential_confirmed`. Pentru un test fara fix, raportul
trebuie sa pastreze `patched_tested: false`.

## 8. Reproducere manuala

Deschide `artifacts/WALKTHROUGH.md` si urmeaza comenzile documentate acolo.
Walkthrough-ul trebuie sa indice:

- cum se porneste versiunea vulnerabila;
- cererea sau actiunea exacta a PoC-ului;
- efectul de securitate asteptat;
- locul in care este inspectata dovada;
- cum se face cleanup;
- pasii patched, numai daca un fix public a fost validat.

Daca walkthrough-ul nu permite repetarea manuala a efectului, rezultatul nu este
un livrabil PoC complet.

## 9. Closed source

```bash
cvelab closed-auto CVE-YYYY-NNNNN --key --model gpt-5.6-sol
```

Pentru un produs proprietar, CVELab continua numai cand artefactul obtinut legal
este disponibil local si inregistrat in `closed-catalog.json`. VirtualBox poate
gazdui produsul, dar kitul de instalare, licenta si configurarea vendorului nu pot
fi inventate ori descarcate prin ocolirea controalelor de acces.

## 10. Depanare

### Docker nu raspunde

```bash
systemctl status docker
docker info
docker compose version
```

Pe Linux nativ, remediaza Docker Engine la nivelul sistemului. CVELab nu modifica
automat daemonul si nu executa factory reset.

### Permission denied pentru Docker

Verifica permisiunile socketului si politica sistemului:

```bash
ls -l /var/run/docker.sock
id
```

### Adaptor AI incomplet

Generatorul face preflight pentru `docker-compose.yml`, Dockerfile-uri si
validator. Un adaptor incomplet este respins inainte de build.

### Lipseste fixul public

Lipsa fixului nu este o eroare daca revizia vulnerabila este verificata.
Rezultatul corect este `VULNERABLE_ONLY_REPRODUCTION`.

### Lipseste artefactul vulnerabil

Rezultatul corect este `ARTIFACT_REQUIRED` sau `POC_NOT_GENERATED`. Furnizeaza
un repository/revision verificabil ori artefactul legal cerut; nu folosi o
simulare ca substitut.

## 11. Siguranta si limite

- Ruleaza numai pe sisteme proprii sau autorizate explicit.
- Pastreaza serviciile pe loopback si retele Docker interne.
- Foloseste payload-uri nedistructive.
- Nu indrepta validatorul catre tinte externe.
- Nu confunda laboratoarele sintetice CWE cu PoC-uri ale produsului real.
- Nu considera absenta unui rezultat dupa timeout drept dovada unica a unui fix.
- Niciun generator nu poate reproduce fidel orice CVE doar din identificator.

## 12. Dezvoltare

Build Linux:

```bash
bash scripts/build-linux.sh
```

Verificari rapide:

```bash
python3 -m compileall -q cvelab
bash -n linux/install.sh
bash -n scripts/build-linux.sh
```

Artefactele de build sunt create in `dist-linux/` si nu sunt versionate.
