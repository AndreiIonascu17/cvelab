# CVELab

`cvelab` genereaza si ruleaza laboratoare locale pentru validarea reproductibila a vulnerabilitatilor descrise de un CVE. Utilizatorul furnizeaza CVE-ul, iar aplicatia incearca sa rezolve sursele publice, sa construiasca mediul, sa execute un PoC sigur si sa produca dovezi, un walkthrough si un raport.

Generatorul nu considera simpla reflectare a unui marker drept dovada. Un rezultat reusit trebuie sa demonstreze efectul vulnerabilitatii asupra artefactului real vulnerabil.

## Rezultate posibile

- `SOURCE_REPRODUCTION`: versiunea vulnerabila si versiunea reparata sunt reproduse; testul reuseste pe vulnerabil si este respins pe patched.
- `VULNERABLE_ONLY_REPRODUCTION`: versiunea vulnerabila este validata, dar nu exista un fix public identificabil. Nu este inventata o versiune patched.
- `CLOSED_SOURCE_REPRODUCTION`: foloseste numai un artefact proprietar obtinut legal si inregistrat local.
- `ARTIFACT_REQUIRED`: lipsesc codul, imaginea sau binarul necesar unei reproduceri fidele.
- `POC_NOT_GENERATED`: informatiile disponibile nu sunt suficiente pentru o dovada reala si verificabila.

## Cerinte

- Linux sau Windows 10/11.
- Python 3.11 sau mai nou.
- Docker Engine pe Linux sau Docker Desktop pe Windows.
- Git disponibil in `PATH`.
- Bash, Make si curl pentru profilele E2E care folosesc Shipyard/Kind.
- WSL cu o distributie Kali este necesar pentru Shipyard numai pe Windows.
- Un API key OpenAI si un model compatibil pentru generarea automata a adaptoarelor.
- Acces legal la produs si licenta necesara pentru software closed source.

## Instalare

Pe Kali/Debian:

```bash
sudo apt update
sudo apt install -y docker.io docker-compose python3-venv git make curl
sudo systemctl enable --now docker
sudo usermod -aG docker "$USER"
newgrp docker

cd cvelab
python3 -m venv .venv
source .venv/bin/activate
python -m pip install .
cvelab --help
```

Pe Windows, din PowerShell:

```powershell
cd "C:\OffSec Lab\cvelab"
py -m pip install .
cvelab --help
```

Daca folderul de scripturi Python nu este in `PATH`:

```powershell
& "$env:LOCALAPPDATA\Programs\Python\Python313\Scripts\cvelab.exe" --help
```

## Pornire rapida

Comanda recomandata pentru un CVE open source pe Linux este:

```bash
cvelab --output-root "$PWD/generated-labs" auto CVE-YYYY-NNNNN --ai on --key --model gpt-5.6-sol
```

Pe Windows:

```powershell
cvelab --output-root "C:\OffSec Lab\cvelab\generated-labs" auto CVE-YYYY-NNNNN --ai on --key --model gpt-5.6-sol
```

Optiunea `--key` fara o valoare dupa ea deschide promptul mascat `OpenAI API key:`. Cheia nu este scrisa in proiect si nu apare in linia de comanda.

Exemplu:

```powershell
cvelab --output-root "C:\OffSec Lab\cvelab\generated-labs" auto CVE-2026-47342 --ai on --key --model gpt-5.6-sol
```

Fluxul `auto`:

1. Colecteaza metadatele publice despre CVE.
2. Identifica repository-ul si referinta vulnerabila.
3. Identifica fixul public, daca exista.
4. Obtine snapshot-urile de cod necesare.
5. Genereaza un adaptor specific produsului.
6. Valideaza structura adaptorului inainte de Docker.
7. Construieste si porneste laboratorul local.
8. Executa PoC-ul si verifica efectul autentic.
9. Ruleaza automat si forma manuala a PoC-ului (`exploit` si `verify`) pe fiecare varianta.
10. Daca build-ul, pornirea sau dovada esueaza, captureaza logurile, regenereaza adaptorul pe baza
    cauzei observate si repeta validarea (maximum 4 incercari implicit).
11. Scrie dovezile, walkthrough-ul si raportul final numai dupa validare.

Nu este necesara interventie intre incercari. Numarul maxim poate fi schimbat, de exemplu:

```bash
cvelab --output-root "$PWD/generated-labs" auto CVE-YYYY-NNNNN \
  --key --model gpt-5.6-sol --max-attempts 6
```

Istoricul generarii, erorilor, reparatiilor si validarilor este pastrat in
`generated-labs/CVE-YYYY-NNNNN/automation.json`.

## CVE cu fix public

Cand sunt disponibile versiunea vulnerabila si fixul, rezultatul asteptat este diferential:

```json
{
  "ok": true,
  "real_poc_verified": true,
  "patched_tested": true,
  "differential_confirmed": true
}
```

Aceasta inseamna ca acelasi caz de test a demonstrat efectul pe versiunea vulnerabila si absenta efectului pe versiunea reparata.

Referintele pot fi furnizate explicit:

```powershell
cvelab --output-root "C:\OffSec Lab\cvelab\generated-labs" auto CVE-YYYY-NNNNN `
  --repo https://github.com/owner/project.git `
  --vulnerable-ref <commit-vulnerabil> `
  --fixed-ref <commit-fix> `
  --ai on --key --model gpt-5.6-sol
```

## CVE fara fix public

Aceeasi comanda `auto` poate produce un PoC real numai pe versiunea vulnerabila atunci cand sursa vulnerabila este disponibila, dar nu a fost publicat sau identificat un fix. Generatorul nu cere artificial `--fixed-ref` si nu creeaza un serviciu patched sintetic.

```powershell
cvelab --output-root "C:\OffSec Lab\cvelab\generated-labs" auto CVE-YYYY-NNNNN `
  --repo https://github.com/owner/project.git `
  --vulnerable-ref <commit-vulnerabil> `
  --ai on --key --model gpt-5.6-sol
```

Un rezultat reusit fara fix indica:

```json
{
  "ok": true,
  "real_poc_verified": true,
  "fix_status": "PUBLIC_FIX_NOT_IDENTIFIED",
  "patched_tested": false,
  "differential_confirmed": false
}
```

Acesta este un PoC al vulnerabilitatii, dar nu este o validare a remedierii. Raportul pastreaza aceasta limitare si nu afirma ca exista o versiune reparata.

## Comenzi principale

| Comanda | Rol |
| --- | --- |
| `auto` | Rezolva informatiile, construieste laboratorul, ruleaza PoC-ul si produce livrabilele. |
| `run` | Ruleaza din nou un laborator deja generat. |
| `source` | Genereaza un laborator source-level folosind referinte Git explicite. |
| `source-all` | Genereaza si ruleaza laboratorul source-level. |
| `build` | Genereaza un laborator de clasa CWE; nu este un PoC real al produsului. |
| `all` | Genereaza si ruleaza laboratorul de clasa CWE. |
| `closed-auto` | Rezolva cerintele unui produs closed source si foloseste un artefact local inregistrat. |
| `closed` | Construieste reproducerea closed source din catalog. |

Rularea din nou a unui laborator:

```powershell
cvelab --output-root "C:\OffSec Lab\cvelab\generated-labs" run CVE-YYYY-NNNNN
```

Generare source-level explicita:

```powershell
cvelab source CVE-YYYY-NNNNN `
  --repo https://github.com/owner/project.git `
  --vulnerable-ref <commit-vulnerabil> `
  --fixed-ref <commit-fix> `
  --ai on --key --model gpt-5.6-sol
```

Generare si rulare intr-o singura comanda:

```powershell
cvelab source-all CVE-YYYY-NNNNN `
  --repo https://github.com/owner/project.git `
  --vulnerable-ref <commit-vulnerabil> `
  --fixed-ref <commit-fix> `
  --ai on --key --model gpt-5.6-sol
```

## Livrabile

Un laborator validat este creat in:

```text
generated-labs/<CVE>/
```

Fisiere importante:

- `e2e/result.json`: rezultatul verificabil si statusurile reproducerii.
- `e2e/`: runnerul si probele E2E specifice produsului, daca profilul le foloseste.
- `validator/validator.py`: PoC-ul/validatorul executabil pentru adaptorul generat.
- `artifacts/PoC.py` (sau payload-ul specific profilului): PoC-ul local inspectabil.
- `artifacts/manual.sh`: runnerul Linux cu actiuni separate `setup`, `exploit`, `verify`, `cleanup`.
- `artifacts/MANUAL-POC.md`: instructiunile reproducerii manuale.
- `artifacts/EVIDENCE.json`: dovezi structurate si provenienta.
- `artifacts/WALKTHROUGH.md`: pasii pentru reproducere manuala.
- `artifacts/REPORT.md`: raportul tehnic, limitele si concluzia.
- `docker-compose.yml`: topologia locala a laboratorului Docker.
- `source/`: snapshot-urile Git folosite de laborator.

Pentru reproducerea manuala se urmeaza `artifacts/WALKTHROUGH.md`. Un PoC acceptat trebuie sa contina comanda sau cererea exacta, efectul observabil si metoda de verificare. Simplul camp `ok: true` nu este suficient fara dovezile din rezultat.

Pe Kali/Linux, dupa o rulare `auto` reusita:

```bash
cd generated-labs/CVE-YYYY-NNNNN/artifacts
bash manual.sh setup vulnerable
bash manual.sh exploit vulnerable
bash manual.sh verify vulnerable
bash manual.sh cleanup
```

Pentru un CVE cu fix public, aceiasi pasi se repeta cu `patched`; verdictul asteptat este
`BLOCKED`. Pentru `VULNERABLE_ONLY_REPRODUCTION`, varianta `patched` nu este oferita.

Fiecare raport foloseste acelasi contract si include nivelul de fidelitate, componentele vendor
executate, componentele simulate, dovada bruta pentru vulnerable/patched, contractul probei si
provenienta. `source_component` nu inseamna E2E al produsului; numai
`product_end_to_end` impreuna cu `product_e2e_verified: true` confirma acel nivel.

## Software closed source

```powershell
cvelab closed-auto CVE-YYYY-NNNNN --key --model gpt-5.6-sol
```

Daca produsul necesita autentificare, entitlement sau licenta, aplicatia se opreste cu `ARTIFACT_REQUIRED`. Dupa obtinerea legala a imaginii sau a kitului de instalare, artefactul este inregistrat o singura data in `closed-catalog.json`, apoi comanda poate continua.

Generatorul nu ocoleste autentificarea vendorului, nu descarca software piratat si nu substituie produsul real cu o simulare sintetica.

## API key si model

Varianta recomandata:

```powershell
cvelab auto CVE-YYYY-NNNNN --ai on --key --model gpt-5.6-sol
```

Alternativ:

```powershell
$env:OPENAI_API_KEY = "cheia-ta"
$env:CVELAB_MODEL = "gpt-5.6-sol"
cvelab auto CVE-YYYY-NNNNN --ai on
```

Nu se introduce cheia in fisiere, commit-uri, capturi de ecran sau exemple publice. Daca o cheie a fost expusa, ea trebuie revocata si regenerata.

## Docker Desktop pe Windows

Inainte de `auto` sau `run`, Docker trebuie sa raspunda:

```powershell
docker version
docker context show
docker info
```

Daca Shipyard esueaza la push catre `localhost:5000` cu `EOF` sau `connection reset`,
verifica temporar fara VPN. Unele politici VPN blocheaza accesul daemonului Docker la
porturile publicate si la subretelele bridge, chiar daca registry-ul este sanatos intre
containere. Testul trebuie reluat numai dupa ce `curl http://127.0.0.1:5000/v2/` poate
ajunge la un registry local publicat de Docker.

Runnerul trateaza erorile tranzitorii cunoscute ale contextului Docker si ale socket-urilor Docker Desktop. Daca backend-ul Docker Desktop se inchide complet, laboratorul nu poate continua pana cand engine-ul este din nou disponibil.

Erori precum `Dockerfile.vulnerable: no such file or directory` trebuie detectate in preflight. Un adaptor AI incomplet este respins, nu lansat partial.

Cleanup-ul elimina numai resursele laboratorului curent. Proiectul nu foloseste `docker system prune --volumes` pentru curatarea normala.

## Docker Engine pe Linux

Runnerul Shipyard este lansat direct prin Bash si foloseste Docker Engine-ul utilizatorului
curent. Nu sunt necesare WSL, Docker Desktop, `kubectl`, Kind sau Helm instalate separat pe
host; uneltele Kubernetes ale profilului sunt furnizate de mediul Shipyard. Verificare:

```bash
docker version
docker compose version
docker info
```

## Limite

- Niciun generator nu poate produce fidel fiecare CVE doar din identificator.
- Un CVE fara cod vulnerabil public sau artefact legal disponibil ramane `ARTIFACT_REQUIRED` ori `POC_NOT_GENERATED`.
- Lipsa unui fix public nu impiedica PoC-ul pe versiunea vulnerabila, dar impiedica validarea diferentiala a remedierii.
- Un repository sau un commit ghicit nu este acceptat ca provenienta.
- AI-ul genereaza adaptorul, dar rezultatul este acceptat numai dupa verificarea executabila a efectului.
- Laboratoarele sintetice de clasa CWE sunt demonstrative, nu PoC-uri ale produsului mentionat de CVE.

## Siguranta

- Laboratoarele sunt destinate cercetarii autorizate.
- Serviciile generate sunt limitate la loopback si la reteaua Docker interna.
- Payload-urile trebuie sa fie nedistructive.
- Nu se scaneaza si nu se ataca tinte externe.
- Orice test pe un sistem care nu iti apartine necesita autorizatie explicita.
