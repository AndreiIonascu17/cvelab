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

- Windows 10 sau Windows 11.
- Python 3.11 sau mai nou.
- Docker Desktop functional pentru laboratoarele Docker.
- Git disponibil in `PATH`.
- WSL si Kali Linux pentru profilele E2E care folosesc Shipyard/Kind.
- Un API key OpenAI si un model compatibil pentru generarea automata a adaptoarelor.
- Acces legal la produs si licenta necesara pentru software closed source.

## Instalare

Din PowerShell:

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

Comanda recomandata pentru un CVE open source este:

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
9. Scrie dovezile, walkthrough-ul si raportul final.

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
- `artifacts/EVIDENCE.json`: dovezi structurate si provenienta.
- `artifacts/WALKTHROUGH.md`: pasii pentru reproducere manuala.
- `artifacts/REPORT.md`: raportul tehnic, limitele si concluzia.
- `docker-compose.yml`: topologia locala a laboratorului Docker.
- `source/`: snapshot-urile Git folosite de laborator.

Pentru reproducerea manuala se urmeaza `artifacts/WALKTHROUGH.md`. Un PoC acceptat trebuie sa contina comanda sau cererea exacta, efectul observabil si metoda de verificare. Simplul camp `ok: true` nu este suficient fara dovezile din rezultat.

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

Runnerul trateaza erorile tranzitorii cunoscute ale contextului Docker si ale socket-urilor Docker Desktop. Daca backend-ul Docker Desktop se inchide complet, laboratorul nu poate continua pana cand engine-ul este din nou disponibil.

Erori precum `Dockerfile.vulnerable: no such file or directory` trebuie detectate in preflight. Un adaptor AI incomplet este respins, nu lansat partial.

Cleanup-ul elimina numai resursele laboratorului curent. Proiectul nu foloseste `docker system prune --volumes` pentru curatarea normala.

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
