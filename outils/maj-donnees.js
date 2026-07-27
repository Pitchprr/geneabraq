#!/usr/bin/env node
/*
 * Outil de mise à jour des données de index.html (chiffrées ou en clair).
 *
 * Usage :
 *   node outils/maj-donnees.js --exporter donnees.json     Écrit le JSON en clair (à supprimer après usage !)
 *   node outils/maj-donnees.js --ajouter famille.json      Ajoute une nouvelle descendance (racine ou {familles:[...]})
 *   node outils/maj-donnees.js --importer donnees.json     Remplace toutes les données par ce fichier
 *   node outils/maj-donnees.js --dechiffrer                Mode développement : stocke les données EN CLAIR (plus de mot de passe)
 *   node outils/maj-donnees.js --chiffrer                  Rechiffre les données (fin du mode développement)
 *   node outils/maj-donnees.js --restaurer                 Annule la dernière modification (index.html.avant)
 *   Options : --fichier <chemin>  index.html à traiter (défaut : celui du projet)
 *
 * La phrase de passe n'est demandée que si nécessaire (données chiffrées, ou --chiffrer).
 * Elle peut aussi être fournie via la variable d'environnement BRAQ_PHRASE (pour les scripts).
 */
'use strict';
const fs = require('fs');
const path = require('path');
const { webcrypto: wc } = require('crypto');

function lireArgs() {
  const a = process.argv.slice(2), o = {};
  for (let i = 0; i < a.length; i++) {
    if (a[i] === '--exporter') o.exporter = a[++i];
    else if (a[i] === '--ajouter') o.ajouter = a[++i];
    else if (a[i] === '--importer') o.importer = a[++i];
    else if (a[i] === '--dechiffrer') o.dechiffrer = true;
    else if (a[i] === '--chiffrer') o.chiffrer = true;
    else if (a[i] === '--restaurer') o.restaurer = true;
    else if (a[i] === '--fichier') o.fichier = a[++i];
    else { console.error('Argument inconnu :', a[i]); process.exit(1); }
  }
  return o;
}

/* saisie masquée : lecture directe des touches, une étoile par caractère réellement tapé */
function demanderUneFois(invite) {
  return new Promise(res => {
    const entree = process.stdin;
    if (!entree.isTTY) {   /* entrée redirigée (script) : lecture simple */
      const rl = require('readline').createInterface({ input: entree, output: process.stdout });
      process.stdout.write(invite);
      rl.question('', r => { rl.close(); res(r); });
      return;
    }
    process.stdout.write(invite);
    const etaitBrut = entree.isRaw;
    entree.setRawMode(true);
    entree.resume();
    entree.setEncoding('utf8');
    let saisie = '';
    const surTouche = t => {
      for (const c of t) {
        if (c === '\r' || c === '\n') {              /* validation */
          entree.removeListener('data', surTouche);
          entree.setRawMode(etaitBrut || false);
          entree.pause();
          process.stdout.write('\n');
          return res(saisie);
        }
        if (c === '\u0003') {                         /* Ctrl+C */
          entree.setRawMode(etaitBrut || false);
          process.stdout.write('\n');
          process.exit(130);
        }
        if (c === '\u007f' || c === '\b') {           /* effacement */
          if (saisie.length) { saisie = saisie.slice(0, -1); process.stdout.write('\b \b'); }
          continue;
        }
        if (c < ' ') continue;                        /* touches de contrôle ignorées */
        saisie += c;
        process.stdout.write('*');
      }
    };
    entree.on('data', surTouche);
  });
}
async function demanderPhrase(confirmer) {
  if (process.env.BRAQ_PHRASE) return process.env.BRAQ_PHRASE;
  for (let essai = 1; essai <= 3; essai++) {
    const p1 = await demanderUneFois('Phrase de passe : ');
    if (!p1) { console.error('  Phrase vide — recommencez.\n'); continue; }
    if (!confirmer) return p1;
    const p2 = await demanderUneFois('Confirmez la phrase : ');
    if (p1 === p2) return p1;
    console.error('  Les deux saisies diffèrent'
      + (essai < 3 ? ' — recommencez.\n' : ' — abandon après 3 tentatives.'));
  }
  process.exit(1);
}

const b64 = buf => Buffer.from(buf).toString('base64');
const deb64 = s => new Uint8Array(Buffer.from(s, 'base64'));

async function clef(phrase, sel, iterations, usages) {
  const km = await wc.subtle.importKey('raw', Buffer.from(phrase, 'utf8'), 'PBKDF2', false, ['deriveKey']);
  return wc.subtle.deriveKey({ name: 'PBKDF2', salt: sel, iterations, hash: 'SHA-256' },
    km, { name: 'AES-GCM', length: 256 }, false, usages);
}

function extraireBloc(html) {
  const m = html.match(/<script id="data" type="application\/octet-stream">([\s\S]*?)<\/script>/);
  if (!m) { console.error('Bloc de données introuvable dans index.html'); process.exit(1); }
  return m[1];
}

async function chiffrer(objet, phrase, iterations) {
  const sel = wc.getRandomValues(new Uint8Array(16));
  const iv = wc.getRandomValues(new Uint8Array(12));
  const k = await clef(phrase, sel, iterations, ['encrypt']);
  const c = await wc.subtle.encrypt({ name: 'AES-GCM', iv }, k, Buffer.from(JSON.stringify(objet), 'utf8'));
  return JSON.stringify({ s: b64(sel), v: b64(iv), c: b64(c), i: iterations });
}

/* — manipulation de l'arbre — */
function enfantsDe(n) {
  const r = [];
  (n.u || []).forEach(u => (u.c || []).forEach(c => r.push(c)));
  (n.c || []).forEach(c => r.push(c));
  return r;
}
function parcourir(n, fn, prof) {
  fn(n, prof || 0);
  enfantsDe(n).forEach(c => parcourir(c, fn, (prof || 0) + 1));
}
function normaliser(d) {
  if (Array.isArray(d)) return d;
  if (d.familles) return d.familles;
  return [d];
}
function reindexer(familles) {
  let id = 1, total = 0;
  familles.forEach(r => parcourir(r, (n, prof) => { n.i = id++; n.g = prof; total++; }));
  return total;
}
function compter(r) { let c = 0; parcourir(r, () => c++); return c; }

(async () => {
  const args = lireArgs();
  const fichier = args.fichier || path.join(__dirname, '..', 'index.html');
  const sauvegarde = fichier + '.avant';

  if (args.restaurer) {
    if (!fs.existsSync(sauvegarde)) { console.error('Aucune sauvegarde trouvée (' + sauvegarde + ').'); process.exit(1); }
    fs.copyFileSync(sauvegarde, fichier);
    console.log('Restauré : ' + fichier + ' est revenu à l\'état d\'avant la dernière modification.');
    process.exit(0);
  }
  if (!args.exporter && !args.ajouter && !args.importer && !args.dechiffrer && !args.chiffrer) {
    console.log('Rien à faire. Options : --exporter <f> | --ajouter <f> | --importer <f> | --dechiffrer | --chiffrer | --restaurer [--fichier <index.html>]');
    process.exit(0);
  }

  const html = fs.readFileSync(fichier, 'utf8');
  const D = JSON.parse(extraireBloc(html));
  const enClair = !D.c;
  let phrase = null, donnees;

  if (enClair) {
    donnees = D.clair;
    console.log('Source : données EN CLAIR (mode développement).');
  } else {
    phrase = await demanderPhrase(false);
    const k = await clef(phrase, deb64(D.s), D.i, ['decrypt']);
    let clair;
    try {
      clair = await wc.subtle.decrypt({ name: 'AES-GCM', iv: deb64(D.v) }, k, deb64(D.c));
    } catch (e) {
      console.error('Phrase de passe incorrecte (ou données corrompues).');
      process.exit(1);
    }
    donnees = JSON.parse(Buffer.from(clair).toString('utf8'));
  }

  let familles = normaliser(donnees);
  console.log('Données actuelles : ' + familles.map(r => r.n + ' (' + compter(r) + ' pers.)').join(' · '));

  if (args.exporter) {
    fs.writeFileSync(args.exporter, JSON.stringify(donnees, null, 1), 'utf8');
    console.log('Exporté en clair vers ' + args.exporter + ' — pensez à SUPPRIMER ce fichier après usage.');
    process.exit(0);
  }

  if (args.ajouter) {
    const nouvelles = normaliser(JSON.parse(fs.readFileSync(args.ajouter, 'utf8')));
    nouvelles.forEach(r => {
      if (!r.n) { console.error('Racine sans nom (champ n) dans ' + args.ajouter); process.exit(1); }
      console.log('Ajout : ' + r.n + ' (' + compter(r) + ' pers.)');
    });
    familles = familles.concat(nouvelles);
  }
  if (args.importer) {
    familles = normaliser(JSON.parse(fs.readFileSync(args.importer, 'utf8')));
    console.log('Remplacement complet par ' + args.importer);
  }

  const total = reindexer(familles); // identifiants uniques + générations recalculées
  const structure = familles.length === 1 ? familles[0] : { familles };
  const iterations = D.i || 310000;

  const sortirEnClair = args.dechiffrer || (enClair && !args.chiffrer);
  let bloc;
  if (sortirEnClair) {
    bloc = JSON.stringify({ clair: structure, i: iterations });
  } else {
    if (!phrase) phrase = await demanderPhrase(true); // --chiffrer depuis le mode en clair
    bloc = await chiffrer(structure, phrase, iterations);
  }

  const html2 = html.replace(/(<script id="data" type="application\/octet-stream">)[\s\S]*?(<\/script>)/, '$1' + bloc + '$2');
  fs.copyFileSync(fichier, sauvegarde); // pour --restaurer
  fs.writeFileSync(fichier, html2, 'utf8');
  console.log('Terminé : ' + familles.length + ' famille(s), ' + total + ' personnes.');
  if (sortirEnClair) {
    console.log('⚠ Les données sont stockées EN CLAIR (aucun mot de passe demandé au chargement).');
    console.log('⚠ Ne publiez PAS le site dans cet état — lancez « node outils/maj-donnees.js --chiffrer » avant toute mise en ligne ou commit.');
  } else {
    console.log('index.html rechiffré (nouveau sel/IV) — le mot de passe est de nouveau exigé.');
  }
  console.log('Pour annuler : node outils/maj-donnees.js --restaurer');
})();
