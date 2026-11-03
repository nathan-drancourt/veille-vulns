// Questionnaire « Mon parc » : construit la liste de mots-clés à partir de questions simples.
// Appelé par index.html via Assistant.ouvrir({ mots, compter, enregistrer, plusTard }).
(function () {
  // Chaque choix ajoute les mots-clés tels qu'ils apparaissent dans les CVE (noms éditeur et produit)
  const QUESTIONS = [
    {
      titre: 'Pare-feu et accès à distance',
      aide: 'Les équipements exposés sur Internet sont la première cible des attaquants.',
      choix: [
        ['Fortinet FortiGate', ['Fortinet', 'FortiGate', 'FortiOS']],
        ['Stormshield', ['Stormshield']],
        ['Palo Alto', ['Palo Alto', 'PAN-OS', 'GlobalProtect']],
        ['Cisco ASA / Firepower', ['Adaptive Security Appliance', 'Firepower', 'Secure Firewall']],
        ['Check Point', ['Check Point']],
        ['SonicWall', ['SonicWall']],
        ['WatchGuard', ['WatchGuard']],
        ['Sophos', ['Sophos']],
        ['pfSense / OPNsense', ['pfSense', 'OPNsense']],
        ['Ivanti Connect Secure', ['Ivanti', 'Connect Secure']],
        ['Citrix NetScaler', ['NetScaler']],
        ['F5 BIG-IP', ['BIG-IP']],
      ],
    },
    {
      titre: 'Commutateurs, routeurs et Wi-Fi',
      aide: 'Le cœur du réseau : une faille ici peut tout exposer.',
      choix: [
        ['Cisco (IOS, Catalyst, Meraki)', ['Cisco IOS', 'IOS XE', 'IOS XR', 'NX-OS', 'Catalyst', 'Meraki']],
        ['HPE Aruba', ['Aruba', 'ArubaOS', 'HPE']],
        ['Juniper', ['Juniper', 'Junos']],
        ['Ubiquiti UniFi', ['Ubiquiti', 'UniFi']],
        ['MikroTik', ['MikroTik', 'RouterOS']],
        ['Huawei', ['Huawei']],
        ['Zyxel', ['Zyxel']],
        ['Netgear', ['Netgear']],
        ['TP-Link', ['TP-Link']],
        ['D-Link', ['D-Link']],
        ['Extreme Networks', ['Extreme Networks', 'ExtremeXOS']],
        ['Ruckus', ['Ruckus']],
      ],
    },
    {
      titre: 'Serveurs et virtualisation',
      aide: 'Systèmes et hyperviseurs qui font tourner vos services.',
      choix: [
        ['VMware (ESXi, vCenter)', ['VMware', 'ESXi', 'vCenter']],
        ['Microsoft Hyper-V', ['Hyper-V']],
        ['Proxmox', ['Proxmox']],
        ['Nutanix', ['Nutanix']],
        ['Windows Server', ['Windows Server']],
        ['Active Directory', ['Active Directory', 'Netlogon']],
        ['Debian / Ubuntu', ['Debian', 'Ubuntu']],
        ['Red Hat / Rocky / Alma', ['Red Hat', 'Rocky Linux', 'AlmaLinux']],
        ['Noyau Linux', ['Linux kernel']],
        ['Docker / Kubernetes', ['Docker', 'Kubernetes']],
      ],
    },
    {
      titre: 'Messagerie et collaboration',
      aide: 'Très visés par l\'hameçonnage et les prises de contrôle de comptes.',
      choix: [
        ['Exchange Server', ['Exchange Server']],
        ['Microsoft 365 / Outlook', ['Microsoft 365', 'Outlook']],
        ['Microsoft Teams', ['Microsoft Teams']],
        ['SharePoint', ['SharePoint']],
        ['Zimbra', ['Zimbra']],
        ['BlueMind', ['BlueMind']],
        ['Roundcube', ['Roundcube']],
        ['Nextcloud', ['Nextcloud']],
        ['Google Workspace', ['Google Workspace']],
      ],
    },
    {
      titre: 'Sauvegarde et stockage',
      aide: 'Les rançongiciels cherchent d\'abord à détruire les sauvegardes.',
      choix: [
        ['Veeam', ['Veeam']],
        ['Synology', ['Synology']],
        ['QNAP', ['QNAP']],
        ['NetApp', ['NetApp', 'ONTAP']],
        ['Dell (PowerStore, Data Domain)', ['PowerStore', 'Data Domain']],
        ['Commvault', ['Commvault']],
        ['Acronis', ['Acronis']],
        ['TrueNAS', ['TrueNAS']],
      ],
    },
    {
      titre: 'Postes de travail',
      aide: 'Systèmes et logiciels installés sur les postes des agents.',
      choix: [
        ['Windows 10 / 11', ['Windows 10', 'Windows 11', 'Microsoft Windows']],
        ['Microsoft Office', ['Microsoft Office', 'Microsoft Word', 'Microsoft Excel']],
        ['Google Chrome', ['Google Chrome', 'Chromium']],
        ['Microsoft Edge', ['Microsoft Edge']],
        ['Mozilla Firefox', ['Firefox']],
        ['Adobe Acrobat / Reader', ['Acrobat']],
        ['7-Zip / WinRAR', ['7-Zip', 'WinRAR']],
        ['Java', ['Oracle Java', 'Java SE']],
        ['macOS', ['macOS']],
      ],
    },
    {
      titre: 'Applications et outils d\'administration',
      aide: 'Logiciels métier, serveurs web et outils de supervision.',
      choix: [
        ['GLPI', ['GLPI']],
        ['Apache HTTP Server', ['Apache HTTP Server']],
        ['nginx', ['nginx']],
        ['IIS', ['Internet Information Services']],
        ['Tomcat', ['Tomcat']],
        ['WordPress', ['WordPress']],
        ['Drupal', ['Drupal']],
        ['OpenSSH', ['OpenSSH']],
        ['OpenSSL', ['OpenSSL']],
        ['Zabbix', ['Zabbix']],
        ['Centreon', ['Centreon']],
        ['Grafana', ['Grafana']],
        ['TeamViewer / AnyDesk', ['TeamViewer', 'AnyDesk']],
        ['GitLab / Jenkins', ['GitLab', 'Jenkins']],
      ],
    },
  ];

  const unique = liste => {
    const vus = new Set();
    return liste.filter(m => { const k = m.toLowerCase(); if (vus.has(k)) return false; vus.add(k); return true; });
  };

  function element(tag, cls, texte) {
    const e = document.createElement(tag);
    if (cls) e.className = cls;
    if (texte != null) e.textContent = texte;
    return e;
  }

  function bouton(cls, texte) {
    const b = element('button', cls, texte);
    b.type = 'button';
    return b;
  }

  function ouvrir(opts) {
    const actuels = new Set((opts.mots || []).map(m => m.toLowerCase()));
    // Pré-coche les choix déjà présents dans la liste actuelle
    const coches = QUESTIONS.map(q => new Set(
      q.choix.map((c, i) => c[1].some(m => actuels.has(m.toLowerCase())) ? i : -1).filter(i => i >= 0)
    ));
    const couverts = new Set(QUESTIONS.flatMap(q => q.choix.flatMap(c => c[1])).map(m => m.toLowerCase()));
    const autres = (opts.mots || []).filter(m => !couverts.has(m.toLowerCase()));
    let etape = -1;   // -1 : accueil, QUESTIONS.length : récapitulatif

    const dlg = element('dialog', 'assistant');
    dlg.setAttribute('aria-label', 'Questionnaire Mon parc');
    document.body.appendChild(dlg);
    dlg.addEventListener('cancel', e => { e.preventDefault(); fermer(false); });

    function fermer(enregistre) {
      dlg.close();
      dlg.remove();
      if (!enregistre && opts.plusTard) opts.plusTard();
    }

    function motsChoisis() {
      return unique(QUESTIONS.flatMap((q, qi) => [...coches[qi]].flatMap(i => q.choix[i][1])));
    }

    function pied(gauche, droite) {
      const p = element('div', 'as-pied');
      const g = element('div', 'as-gauche');
      gauche.forEach(b => g.appendChild(b));
      p.appendChild(g);
      droite.forEach(b => p.appendChild(b));
      return p;
    }

    function progression() {
      const total = QUESTIONS.length + 1;
      const pos = Math.min(etape + 1, total);
      const bloc = element('div', 'as-progression');
      bloc.appendChild(element('span', 'as-etape', etape < QUESTIONS.length ? `Question ${pos} sur ${QUESTIONS.length}` : 'Récapitulatif'));
      const barre = element('div', 'as-barre');
      const rempli = element('span');
      rempli.style.width = (pos / total * 100) + '%';
      barre.appendChild(rempli);
      bloc.appendChild(barre);
      return bloc;
    }

    function accueil() {
      const c = element('div', 'as-corps');
      c.appendChild(element('p', 'as-sur-titre', 'Première visite'));
      c.appendChild(element('h2', 'as-titre', 'Configurons votre veille'));
      c.appendChild(element('p', 'as-texte',
        `${QUESTIONS.length} questions rapides sur vos équipements et logiciels. Les vulnérabilités qui les concernent passeront en tête de liste.`));
      const note = element('p', 'as-note', 'Vos réponses restent dans ce navigateur. Elles ne sont jamais envoyées ni publiées.');
      c.appendChild(note);
      const plusTard = bouton('btn discret', 'Plus tard');
      plusTard.onclick = () => fermer(false);
      const go = bouton('btn', 'Commencer');
      go.onclick = () => { etape = 0; rendre(); };
      c.appendChild(pied([plusTard], [go]));
      return c;
    }

    function question() {
      const q = QUESTIONS[etape];
      const sel = coches[etape];
      const c = element('div', 'as-corps');
      c.appendChild(progression());
      c.appendChild(element('h2', 'as-titre', q.titre));
      c.appendChild(element('p', 'as-texte', q.aide + ' Cochez tout ce que vous utilisez.'));
      const grille = element('div', 'as-choix');
      q.choix.forEach(([lib], i) => {
        const b = bouton('as-option', null);
        b.setAttribute('aria-pressed', sel.has(i));
        b.appendChild(element('span', 'as-case'));
        b.appendChild(element('span', null, lib));
        b.onclick = () => {
          sel.has(i) ? sel.delete(i) : sel.add(i);
          b.setAttribute('aria-pressed', sel.has(i));
          suivant.textContent = libSuivant();
        };
        grille.appendChild(b);
      });
      c.appendChild(grille);
      const precedent = bouton('btn discret', 'Précédent');
      precedent.onclick = () => { etape--; rendre(); };
      const passer = bouton('btn discret', 'Plus tard');
      passer.onclick = () => fermer(false);
      const libSuivant = () => sel.size ? `Suivant (${sel.size})` : 'Je n\'en ai pas';
      const suivant = bouton('btn', libSuivant());
      suivant.onclick = () => { etape++; rendre(); };
      c.appendChild(pied([passer], [precedent, suivant]));
      return c;
    }

    function recapitulatif() {
      const c = element('div', 'as-corps');
      c.appendChild(progression());
      c.appendChild(element('h2', 'as-titre', 'Votre parc'));
      c.appendChild(element('p', 'as-texte',
        'Voici les mots-clés surveillés. Ajoutez ce qui manque, un par ligne : logiciels métier, marques, modèles.'));
      const zone = element('textarea', 'as-zone');
      zone.spellcheck = false;
      zone.setAttribute('aria-label', 'Mots-clés de votre parc');
      zone.value = unique([...motsChoisis(), ...autres]).join('\n');
      c.appendChild(zone);
      const apercu = element('p', 'as-apercu');
      c.appendChild(apercu);
      const lignes = () => unique(zone.value.split(/\r?\n/).map(s => s.trim()).filter(Boolean));
      const majApercu = () => {
        const r = opts.compter ? opts.compter(lignes()) : null;
        apercu.textContent = !lignes().length
          ? 'Aucun mot-clé : toutes les vulnérabilités seront classées « pour information ».'
          : r ? `${lignes().length} mots-clés · ${r.total.toLocaleString('fr-FR')} vulnérabilités récentes vous concernent, dont ${r.urgentes} urgentes.`
            : `${lignes().length} mots-clés.`;
      };
      zone.addEventListener('input', majApercu);
      majApercu();
      const precedent = bouton('btn discret', 'Précédent');
      precedent.onclick = () => { etape--; rendre(); };
      const ok = bouton('btn', 'Enregistrer mon parc');
      ok.onclick = () => { opts.enregistrer(lignes()); fermer(true); };
      c.appendChild(pied([], [precedent, ok]));
      return c;
    }

    function rendre() {
      dlg.replaceChildren(etape < 0 ? accueil() : etape < QUESTIONS.length ? question() : recapitulatif());
      const cible = dlg.querySelector('.as-option, .as-zone, .btn:not(.discret)');
      if (cible) cible.focus();
    }

    rendre();
    if (dlg.showModal) dlg.showModal(); else dlg.setAttribute('open', '');
  }

  window.Assistant = { ouvrir };
})();
