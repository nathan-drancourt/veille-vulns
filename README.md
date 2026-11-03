# Veille vulnérabilités

Site de veille autonome hébergé sur GitHub Pages. Toutes les 4 heures, une GitHub Action collecte :

| Source | Ce qu'elle apporte |
|---|---|
| **CERT-FR** (alertes et avis) | La référence française. Une *alerte* signale une menace grave et active |
| **CISA KEV** | Vulnérabilités **exploitées dans la nature**, avec l'usage par des rançongiciels |
| **NVD** | Toutes les CVE publiées, avec leur score CVSS et les produits concernés |
| **EPSS** (FIRST) | Probabilité d'exploitation dans les 30 jours |

Le site classe chaque élément de P1 (urgent) à P4 (pour information) selon **votre parc**.

## Pourquoi votre parc n'est pas dans le dépôt

Le dépôt et le site sont publics. Publier la liste de vos équipements (marques de pare-feu, VPN, hyperviseurs…)
donnerait à un attaquant une carte de la collectivité. Le site publie donc toutes les vulnérabilités récentes,
et le croisement avec vos mots-clés se fait **dans votre navigateur**, depuis le panneau « Mon parc ».
La liste reste dans ce navigateur et n'est jamais envoyée.

## Mise en ligne (une seule fois, environ 10 minutes)

Tout se fait depuis le site github.com, sans rien installer.

1. **Créer le dépôt** : connectez-vous à GitHub, puis cliquez sur **New repository**.
   Nommez-le par exemple `veille-vulns`, choisissez **Public** et ne cochez rien d'autre.
   Avec un compte gratuit, GitHub Pages exige un dépôt public.
2. **Envoyer les fichiers** : sur la page du dépôt vide, cliquez sur *uploading an existing file*.
   Glissez-déposez **tout le contenu** du dossier `Veille` : `.github`, `collecteur`, `docs`, `config.json`, `README.md` et `.gitignore`.
   Cliquez ensuite sur **Commit changes**.
   - Vérifiez que le fichier `.github/workflows/veille.yml` apparaît bien dans le dépôt.
     Sinon, créez-le avec **Add file → Create new file** : tapez `.github/workflows/veille.yml` comme nom, puis collez son contenu.
3. **Activer Pages** : allez dans **Settings → Pages → Build and deployment → Source** et choisissez **GitHub Actions**.
4. **Lancer la première collecte** : dans l'onglet **Actions**, ouvrez **Veille vulnérabilités** puis cliquez sur **Run workflow**.
   Comptez 2 à 3 minutes.
5. **Ouvrir le site** à l'adresse `https://<votre-compte>.github.io/veille-vulns/`.
   Elle est aussi affichée dans **Settings → Pages**. Ajoutez-la à vos favoris.
6. Dans le site, ouvrez **Mon parc**, remplacez la liste d'exemple par vos équipements réels, puis cliquez sur **Enregistrer**.

Ensuite, tout est automatique : les données se mettent à jour toutes les 4 heures, même quand votre PC est éteint.

## Si quelque chose bloque

- **L'étape « Enregistrer les premières vues » échoue (erreur 403)** : allez dans **Settings → Actions → General → Workflow permissions**
  et choisissez **Read and write permissions**.
- **Le site affiche « données de plus de 12 h »** : ouvrez l'onglet **Actions** pour voir l'erreur de la dernière exécution.
  Si une seule source est en panne, le site reste à jour avec les autres et affiche un bandeau.
- **La collecte NVD est lente ou refusée** : demandez une clé gratuite sur <https://nvd.nist.gov/developers/request-an-api-key>.
  Ajoutez-la ensuite dans **Settings → Secrets and variables → Actions → New repository secret**, sous le nom `NVD_API_KEY`.
- GitHub retarde parfois les tâches planifiées de quelques dizaines de minutes aux heures chargées. C'est normal.

## Réglages

`config.json` contient les fenêtres de collecte. Après modification sur GitHub, la collecte se relance automatiquement.

| Clé | Défaut | Rôle |
|---|---|---|
| `JoursNvd` | 7 | CVE publiées sur cette période (maximum 120) |
| `JoursKev` | 30 | Ajouts récents au catalogue des failles exploitées |
| `JoursCertFr` | 30 | Alertes et avis CERT-FR |

Pour changer la fréquence de collecte, modifiez la ligne `cron` de `.github/workflows/veille.yml`. L'heure est en UTC.

## Fonctionnement

```
GitHub Actions (toutes les 4 h)
  └─ collecteur/Veille.ps1 ─► docs/donnees.json ─► GitHub Pages ─► docs/index.html
                           └─► etat/premieres-vues.json (date de première apparition, pour « Nouveau »)
```

Le collecteur fonctionne aussi sur un poste Windows, pour tester :
`powershell -ExecutionPolicy Bypass -File .\collecteur\Veille.ps1`

## Limites

- La correspondance avec votre parc se fait par mots-clés : il peut y avoir des faux positifs ou des oublis.
  Vérifiez toujours les versions concernées dans l'avis de l'éditeur.
- Les CVE très récentes n'ont souvent pas encore de score CVSS ni de produit identifié par la NVD.
  Elles remontent quand même si leur description cite un de vos mots-clés.
- En complément, abonnez-vous aux bulletins de sécurité de vos éditeurs : Cisco PSIRT, Fortinet PSIRT,
  Microsoft Patch Tuesday (2ᵉ mardi du mois), Stormshield…
