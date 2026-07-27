#!/usr/bin/env node
/*
 * Outil de mise à jour des données chiffrées de index.html.
 * La phrase de passe est demandée au clavier (saisie masquée) et ne quitte jamais cette machine.
 *
 * Usage :
 *   node outils/maj-donnees.js --exporter donnees.json     Déchiffre et écrit le JSON en clair (à supprimer après usage !)
 *   node outils/maj-donnees.js --ajouter famille.json      Ajoute une nouvelle descendance (racine ou {familles:[...]})
 *   node outils/maj-donnees.js --importer donnees.json     Remplace toutes les données par ce fichier
 *   Options : --fichier <chemin>  index.html à traiter (défaut : celui du projet)
 * La phrase peut aussi être fournie via la variable d'environnement BRAQ_PHRASE (pour les scripts).
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
    else if (a[i] === '--fichier') o.fichier = a[++i];
    else { console.error('Argument inconnu :', a[i]); process.exit(1); }
  }
  return o;
}

function demanderPhrase() {
  return new Promise(res => {
    if (process.env.BRAQ_PHRASE) return res(process.env.BRAQ_PHRASE);
    const rl = require('readline').createInterface({ input: process.stdin, output: process.stdout });
    process.stdout.write('Phrase de passe : ');
    rl._writeToOutput = function () {}; // saisie masquée
    rl.question('', r => { rl.close(); process.stdout.write('\n'); res(r); });
  });
}

const b64 = buf => Buffer.from(buf).toString('base64');
const deb64 = s => new Uint8Array(Buffer.from(s, 'base64'));

async function clef(phrase, sel, iterations, usages) {
  const km = await wc.subtle.importKey('raw', Buffer.from(phrase, 'utf8'), 'PBKDF2', false, ['deriveKey']);
  return wc.subtle.deriveKey({ name: 'PBKDF2', salt: sel, iterations, hash: 'SHA-256' },
    km, { name: 'AES-GCM', length: 256 }, false, usages);
}

function extraireBloc(html) {
  const m = html.match(/(<script id="data" type="application\/octet-stream">)([\s\S]*?)(<\/script>)/);
  if (!m) { console.error('Bloc de données introuvable dans index.html'); process.exit(1); }
  return { avantApres: [m[1], m[3]], brut: m[2], tout: m[0] };
}

async function dechiffrer(html, phrase) {
  const bloc = extraireBloc(html);
  const D = JSON.parse(bloc.brut);
  const k = await clef(phrase, deb64(D.s), D.i, ['decrypt']);
  let clair;
  try {
    clair = await wc.subtle.decrypt({ name: 'AES-GCM', iv: deb64(D.v) }, k, deb64(D.c));
  } catch (e) {
    console.error('Phrase de passe incorrecte (ou données corrompues).');
    process.exit(1);
  }
  return { D, donnees: JSON.parse(Buffer.from(clair).toString('utf8')) };
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
  if (!args.exporter && !args.ajouter && !args.importer) {
    console.log('Rien à faire. Options : --exporter <f> | --ajouter <f> | --importer <f> [--fichier <index.html>]');
    process.exit(0);
  }
  const html = fs.readFileSync(fichier, 'utf8');
  const phrase = await demanderPhrase();
  const { D, donnees } = await dechiffrer(html, phrase);
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
  const bloc = await chiffrer(structure, phrase, D.i);
  const html2 = html.replace(/(<script id="data" type="application\/octet-stream">)[\s\S]*?(<\/script>)/, '$1' + bloc + '$2');
  fs.writeFileSync(fichier, html2, 'utf8');
  console.log('Terminé : ' + familles.length + ' famille(s), ' + total + ' personnes. index.html rechiffré (nouveau sel/IV).');
})();
