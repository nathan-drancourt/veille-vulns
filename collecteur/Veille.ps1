<#
.SYNOPSIS
    Collecteur de la veille cyber : vulnérabilités (CERT-FR, CISA KEV, NVD, EPSS) et actualités (flux RSS).

.DESCRIPTION
    Exécuté par GitHub Actions (PowerShell 7, Linux) ou en local (PowerShell 5.1+).
    Écrit docs/donnees.json, lu par le site docs/index.html.

    Volontairement, ce script ne connaît PAS votre parc : le dépôt et le site sont publics,
    le croisement avec vos équipements se fait dans le navigateur de chaque lecteur.

    etat/premieres-vues.json garde la date à laquelle chaque élément a été vu pour la première
    fois, pour que le site puisse signaler les nouveautés.
#>
$ErrorActionPreference = 'Stop'
$Racine = Split-Path $PSScriptRoot -Parent
$FichierSortie = Join-Path $Racine 'docs/donnees.json'
$FichierEtat = Join-Path $Racine 'etat/premieres-vues.json'
New-Item -ItemType Directory -Force (Split-Path $FichierEtat), (Split-Path $FichierSortie) | Out-Null

# PowerShell 5.1 : forcer TLS 1.2 et utiliser le proxy système avec l'identité Windows
#             (sans effet ou indisponible sous Linux, d'où le try)
try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    [System.Net.WebRequest]::DefaultWebProxy.Credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials
} catch { }

$Config = Get-Content (Join-Path $Racine 'config.json') -Raw -Encoding UTF8 | ConvertFrom-Json
$Maintenant = (Get-Date).ToUniversalTime()
# L'API NVD refuse plus de 120 jours
$JoursNvd = [Math]::Min([Math]::Max([int]$Config.JoursNvd, 1), 120)
$DepuisNvd = $Maintenant.AddDays(-$JoursNvd)
$DepuisKev = $Maintenant.AddDays(-[int]$Config.JoursKev)
$DepuisCertFr = $Maintenant.AddDays(-[int]$Config.JoursCertFr)
$DepuisActualites = $Maintenant.AddDays(-[int]$Config.JoursActualites)
$CleNvd = $env:NVD_API_KEY
# Certains sites refusent les clients sans navigateur déclaré
$AgentHttp = 'Mozilla/5.0 (compatible; veille-cyber; +https://github.com/nathan-drancourt/veille-vulns)'

function Write-Etape([string]$Message) {
    Write-Host "[$(Get-Date -Format HH:mm:ss)] $Message"
}

# Appel HTTP avec quelques tentatives (NVD renvoie parfois 403/503 sous charge)
function Invoke-Api([string]$Url, [hashtable]$Entetes = @{}, [int]$Tentatives = 4) {
    for ($i = 1; $i -le $Tentatives; $i++) {
        try {
            return Invoke-RestMethod -Uri $Url -Headers $Entetes -TimeoutSec 120 -UseBasicParsing
        } catch {
            if ($i -eq $Tentatives) { throw }
            Write-Warning "Échec ($($_.Exception.Message)), nouvelle tentative dans $(15 * $i) s..."
            Start-Sleep -Seconds (15 * $i)
        }
    }
}

# PowerShell 7 convertit déjà les dates JSON en [datetime], PowerShell 5.1 non : on normalise
function Format-Jour($Valeur) {
    if (-not $Valeur) { return '' }
    ([datetime]$Valeur).ToString('yyyy-MM-dd', [Globalization.CultureInfo]::InvariantCulture)
}

function Get-TexteXml($Noeud) {
    if ($null -eq $Noeud) { return '' }
    if ($Noeud -is [string]) { return $Noeud }
    $Noeud.InnerText
}

function Limit-Texte([string]$Texte, [int]$Max) {
    if (-not $Texte) { return '' }
    $Texte = $Texte -replace '\s+', ' '
    if ($Texte.Length -le $Max) { return $Texte.Trim() }
    $Texte.Substring(0, $Max).Trim() + '…'
}

function New-Element {
    [ordered]@{
        id       = ''
        sources  = @()
        titre    = ''
        desc     = ''
        lien     = ''
        date     = ''
        cvss     = $null
        sev      = ''
        epss     = $null
        kev      = $false
        rancon   = $false
        echeance = ''
        produits = ''
        vu       = ''
    }
}

# --- Sources ---------------------------------------------------------------------------------

function Get-Nvd {
    $format = 'yyyy-MM-ddTHH:mm:ss.fff'
    $debut = $DepuisNvd.ToString($format, [Globalization.CultureInfo]::InvariantCulture)
    $fin = $Maintenant.ToString($format, [Globalization.CultureInfo]::InvariantCulture)
    $entetes = @{}
    if ($CleNvd) { $entetes['apiKey'] = $CleNvd }
    # Sans clé : 5 requêtes / 30 s maximum
    $pause = if ($CleNvd) { 1 } else { 7 }

    $toutes = @()
    $index = 0
    $total = 1
    while ($index -lt $total) {
        Write-Etape "NVD : CVE publiées depuis $JoursNvd jour(s), à partir de $index"
        $url = "https://services.nvd.nist.gov/rest/json/cves/2.0?pubStartDate=$debut&pubEndDate=$fin&resultsPerPage=1000&startIndex=$index"
        $r = Invoke-Api $url $entetes
        $total = [int]$r.totalResults
        $toutes += $r.vulnerabilities
        if ([int]$r.resultsPerPage -le 0) { break }
        $index += [int]$r.resultsPerPage
        if ($index -lt $total) { Start-Sleep -Seconds $pause }
    }
    Write-Etape "NVD : $($toutes.Count) CVE"
    $toutes
}

function ConvertFrom-Nvd($Vuln) {
    $c = $Vuln.cve
    $e = New-Element
    $e.id = $c.id
    $e.sources = @('NVD')
    $e.desc = Limit-Texte ($c.descriptions | Where-Object { $_.lang -eq 'en' } | Select-Object -First 1).value 700
    $e.lien = "https://nvd.nist.gov/vuln/detail/$($c.id)"
    $e.date = Format-Jour $c.published

    # Meilleur score CVSS disponible (v4 > v3.1 > v3.0, NVD ou éditeur)
    foreach ($version in 'cvssMetricV40', 'cvssMetricV31', 'cvssMetricV30') {
        foreach ($m in @($c.metrics.$version)) {
            if ($null -eq $m) { continue }
            $score = [double]$m.cvssData.baseScore
            if ($null -eq $e.cvss -or $score -gt $e.cvss) {
                $e.cvss = $score
                $e.sev = [string]$m.cvssData.baseSeverity
            }
        }
    }

    # Produits concernés, extraits des CPE (cpe:2.3:a:editeur:produit:...)
    $produits = [ordered]@{}
    try {
        foreach ($cpe in @($c.configurations.nodes.cpeMatch.criteria)) {
            $p = "$cpe" -split ':'
            if ($p.Count -gt 4) { $produits[("$($p[3]) $($p[4])" -replace '_', ' ')] = $true }
        }
    } catch { }
    $e.produits = (@($produits.Keys) | Select-Object -First 8) -join ', '
    # Beaucoup de CVE récentes n'ont pas encore de CPE : on prend alors le début de la description
    $e.titre = if ($e.produits) { $e.produits } else { Limit-Texte $e.desc 90 }
    $e
}

function Get-Kev {
    Write-Etape 'CISA KEV : catalogue des vulnérabilités activement exploitées'
    (Invoke-Api 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json').vulnerabilities
}

function Get-CertFr {
    foreach ($type in 'alerte', 'avis') {
        Write-Etape "CERT-FR : flux $type"
        foreach ($it in (Invoke-Api "https://www.cert.cyber.gouv.fr/$type/feed/")) {
            try { $date = [DateTimeOffset]::Parse((Get-TexteXml $it.pubDate), [Globalization.CultureInfo]::InvariantCulture).UtcDateTime }
            catch { $date = $Maintenant }
            if ($date -lt $DepuisCertFr) { continue }

            $lien = Get-TexteXml $it.link
            $e = New-Element
            $e.id = ($lien.TrimEnd('/') -split '/')[-1]
            $e.sources = @("CERT-FR $type")
            $e.titre = Limit-Texte (Get-TexteXml $it.title) 200
            $e.desc = Limit-Texte ((Get-TexteXml $it.description) -replace '<[^>]+>', ' ') 700
            $e.lien = $lien
            $e.date = $date.ToString('yyyy-MM-dd')
            $e
        }
    }
}

# --- Actualités ------------------------------------------------------------------------------

# Thèmes repérés dans le titre et le résumé, pour filtrer et signaler ce qui presse
$Themes = [ordered]@{
    'exploitee'  = 'actively exploited|exploited in the wild|under active exploitation|exploitée? activement|activement exploitée?'
    'zero-day'   = 'zero[- ]?day|0[- ]?day|jour z[ée]ro'
    'rancon'     = 'ransomware|rançongiciel|ransom'
    'fuite'      = 'data breach|data leak|fuite de donn[ée]es|leaked'
    'hameconnage' = 'phishing|hameçonnage|smishing'
}

function ConvertTo-Date([string]$Texte) {
    if (-not $Texte) { return $null }
    $culture = [Globalization.CultureInfo]::InvariantCulture
    $style = [Globalization.DateTimeStyles]::AssumeUniversal
    $d = [DateTimeOffset]::MinValue
    if ([DateTimeOffset]::TryParse($Texte.Trim(), $culture, $style, [ref]$d)) { return $d.UtcDateTime }
    # RFC 822 avec fuseau en lettres (EST, PDT...) ou année sur deux chiffres
    $t = $Texte.Trim() -replace '\s+[A-Z]{2,4}$', ' +0000' -replace '^(\w{3}, \d{1,2} \w{3} )(\d{2}) ', '${1}20$2 '
    if ([DateTimeOffset]::TryParse($t, $culture, $style, [ref]$d)) { return $d.UtcDateTime }
    $null
}

function Get-Champ($Noeud, [string[]]$Noms) {
    foreach ($nom in $Noms) {
        $x = $Noeud.SelectSingleNode("*[local-name()='$nom']")
        if ($x) { return $x }
    }
    $null
}

# Lit un flux RSS 2.0 ou Atom ; l'encodage déclaré dans le XML est respecté
function Get-Flux($Flux) {
    $r = Invoke-WebRequest -Uri $Flux.url -UseBasicParsing -TimeoutSec 60 -UserAgent $AgentHttp
    $xml = New-Object Xml.XmlDocument
    $xml.XmlResolver = $null
    $xml.Load((New-Object IO.MemoryStream (, $r.RawContentStream.ToArray())))
    # Fuseau de la source quand ses dates n'en indiquent pas (identifiant Linux, puis Windows)
    $fuseau = $null
    if ($Flux.fuseau) {
        foreach ($nom in @($Flux.fuseau, 'Romance Standard Time')) {
            try { $fuseau = [TimeZoneInfo]::FindSystemTimeZoneById($nom); break } catch { }
        }
    }
    foreach ($it in $xml.SelectNodes('//*[local-name()="item" or local-name()="entry"]')) {
        $texteDate = (Get-Champ $it 'pubDate', 'published', 'updated', 'date').InnerText
        $date = ConvertTo-Date $texteDate
        if ($date -and $fuseau -and $texteDate -notmatch '(Z|[+-]\d{2}:?\d{2}|[A-Z]{2,4})\s*$') {
            $date = [TimeZoneInfo]::ConvertTimeToUtc([datetime]::SpecifyKind($date, 'Unspecified'), $fuseau)
        }
        if (-not $date -or $date -lt $DepuisActualites -or $date -gt $Maintenant.AddHours(2)) { continue }

        $noeudLien = Get-Champ $it 'link'
        $lien = if ($noeudLien.GetAttribute('href')) { $noeudLien.GetAttribute('href') } else { $noeudLien.InnerText.Trim() }
        if (-not $lien) { continue }
        $titre = [Net.WebUtility]::HtmlDecode((Get-Champ $it 'title').InnerText)
        $brut = (Get-Champ $it 'description', 'summary', 'content', 'encoded').InnerText
        $resume = [Net.WebUtility]::HtmlDecode(($brut -replace '<[^>]+>', ' '))
        # Mentions ajoutées par les blogs en fin de résumé (« [...] », « The post X appeared first on Y »)
        $resume = $resume -replace '(?s)\s*(The post|L.article|Le post) .+? (appeared first on|est apparu en premier sur|a été publié sur) .+$', ''
        if ($resume -match '\s*(\[\s*(…|\.{3})\s*\]|\(\s*(…|\.{3})\s*\))\s*$') {
            $resume = $resume.Substring(0, $resume.Length - $Matches[0].Length).TrimEnd()
            if ($resume -notmatch '[.!?…]$') { $resume += '…' }
        }
        $texte = "$titre $resume"

        [ordered]@{
            id     = $lien
            source = $Flux.nom
            langue = $Flux.langue
            titre  = Limit-Texte $titre 220
            resume = Limit-Texte $resume 360
            lien   = $lien
            date   = $date.ToString('yyyy-MM-ddTHH:mm:ssZ', [Globalization.CultureInfo]::InvariantCulture)
            cves   = @([regex]::Matches($texte, 'CVE-\d{4}-\d{4,}', 'IgnoreCase') | ForEach-Object { $_.Value.ToUpper() } | Select-Object -Unique)
            themes = @($Themes.Keys | Where-Object { $texte -match $Themes[$_] })
            vu     = ''
        }
    }
}

function Add-Epss($Elements) {
    $cves = @($Elements | Where-Object { $_.id -match '^CVE-' } | ForEach-Object { $_.id })
    $scores = @{}
    for ($i = 0; $i -lt $cves.Count; $i += 80) {
        $lot = $cves[$i..([Math]::Min($i + 79, $cves.Count - 1))]
        if ($i % 800 -eq 0) { Write-Etape "EPSS : $i / $($cves.Count)" }
        $r = Invoke-Api ("https://api.first.org/data/v1/epss?cve=" + ($lot -join ','))
        foreach ($d in $r.data) { $scores[$d.cve] = [Math]::Round([double]$d.epss, 5) }
    }
    foreach ($e in $Elements) { if ($scores.ContainsKey($e.id)) { $e.epss = $scores[$e.id] } }
}

# --- Collecte --------------------------------------------------------------------------------
# Une source en panne ne doit pas bloquer les autres : on note l'erreur et on continue.

$elements = [ordered]@{}
$erreurs = @()

try {
    foreach ($v in Get-Nvd) { $e = ConvertFrom-Nvd $v; $elements[$e.id] = $e }
} catch { $erreurs += "NVD : $($_.Exception.Message)" }

try {
    foreach ($k in Get-Kev) {
        $id = [string]$k.cveID
        if ($elements.Contains($id)) {
            $e = $elements[$id]
        } elseif ([datetime]$k.dateAdded -ge $DepuisKev.Date) {
            $e = New-Element
            $e.id = $id
            $e.titre = "$($k.vendorProject) $($k.product)"
            $e.desc = Limit-Texte "$($k.vulnerabilityName). $($k.shortDescription)" 700
            $e.lien = "https://nvd.nist.gov/vuln/detail/$id"
            $e.date = Format-Jour $k.dateAdded
            $e.produits = "$($k.vendorProject) $($k.product)"
            $elements[$id] = $e
        } else { continue }
        $e.kev = $true
        $e.sources = @($e.sources) + 'KEV'
        $e.echeance = Format-Jour $k.dueDate
        $e.rancon = $k.knownRansomwareCampaignUse -eq 'Known'
    }
} catch { $erreurs += "CISA KEV : $($_.Exception.Message)" }

try {
    foreach ($e in Get-CertFr) { $elements[$e.id] = $e }
} catch { $erreurs += "CERT-FR : $($_.Exception.Message)" }

$liste = @($elements.Values)
try { Add-Epss $liste } catch { $erreurs += "EPSS : $($_.Exception.Message)" }

if ($liste.Count -eq 0) { throw "Aucune donnée collectée : $($erreurs -join ' | ')" }

# Une source d'actualités en panne n'est pas grave : elle est simplement signalée sur le site
$actualites = [ordered]@{}
$sourcesActualites = @()
foreach ($f in @($Config.Actualites)) {
    Write-Etape "Actualités : $($f.nom)"
    try {
        $n = 0
        foreach ($a in Get-Flux $f) { if (-not $actualites.Contains($a.id)) { $actualites[$a.id] = $a; $n++ } }
        $sourcesActualites += [ordered]@{ nom = $f.nom; langue = $f.langue; site = ([uri]$f.url).Host; articles = $n; erreur = '' }
    } catch {
        Write-Warning "$($f.nom) indisponible : $($_.Exception.Message)"
        $sourcesActualites += [ordered]@{ nom = $f.nom; langue = $f.langue; site = ([uri]$f.url).Host; articles = 0; erreur = $_.Exception.Message }
    }
}
$listeActualites = @($actualites.Values | Sort-Object @{ Expression = { $_.date }; Descending = $true } | Select-Object -First 500)

# --- Premières vues --------------------------------------------------------------------------

$etat = @{}
if (Test-Path $FichierEtat) {
    $brut = Get-Content $FichierEtat -Raw -Encoding UTF8 | ConvertFrom-Json
    foreach ($p in $brut.PSObject.Properties) {
        # PowerShell 7 relit les dates ISO comme [datetime] : on les remet au format ISO
        $valeur = $p.Value
        if ($valeur -is [datetime]) {
            $valeur = $valeur.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ', [Globalization.CultureInfo]::InvariantCulture)
        }
        $etat[$p.Name] = [string]$valeur
    }
}
$horodatage = $Maintenant.ToString('yyyy-MM-ddTHH:mm:ssZ', [Globalization.CultureInfo]::InvariantCulture)
foreach ($e in @($liste) + @($listeActualites)) {
    if (-not $etat.ContainsKey($e.id)) { $etat[$e.id] = $horodatage }
    $e.vu = $etat[$e.id]
}
# On oublie ce qui n'est plus publié depuis longtemps pour garder le fichier léger
$limite = $Maintenant.AddDays(-150).ToString('yyyy-MM-dd')
$etatTrie = [ordered]@{}
foreach ($cle in ($etat.Keys | Sort-Object)) {
    if ($etat[$cle].Substring(0, 10) -ge $limite) { $etatTrie[$cle] = $etat[$cle] }
}
[IO.File]::WriteAllText($FichierEtat, (ConvertTo-Json $etatTrie), (New-Object Text.UTF8Encoding $false))

# --- Sortie ----------------------------------------------------------------------------------

$liste = @($liste | Sort-Object @{ Expression = { $_.date }; Descending = $true }, @{ Expression = { $_.id } })
$sortie = [ordered]@{
    genere      = $horodatage
    fenetres    = [ordered]@{ nvd = $JoursNvd; kev = [int]$Config.JoursKev; certfr = [int]$Config.JoursCertFr; actualites = [int]$Config.JoursActualites }
    erreurs     = $erreurs
    elements    = $liste
    sources     = $sourcesActualites
    actualites  = $listeActualites
}
[IO.File]::WriteAllText($FichierSortie, (ConvertTo-Json $sortie -Depth 4 -Compress), (New-Object Text.UTF8Encoding $false))

Write-Etape "$($liste.Count) vulnérabilités et $($listeActualites.Count) actualités écrites dans docs/donnees.json"
foreach ($err in $erreurs) { Write-Warning $err }
