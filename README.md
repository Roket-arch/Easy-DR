# Easy DR

Antivirus + EDR léger pour Windows : installation en un clic, protection en arrière-plan, alertes, historique, quarantaine.

## Obtenir EasyDR-Setup.exe (sans rien installer sur ton PC)
1. Crée un dépôt GitHub (privé ou public) et pousse ce dossier dedans.
2. Onglet **Actions** → « Build Easy DR installer » → **Run workflow** (ou pousse un tag `v1.0.0`).
3. Télécharge l'artefact **EasyDR-Setup** : c'est l'installateur.

Ou sur un PC Windows avec Python 3.10+ et Inno Setup 6 : double-clic sur `build.bat` → `dist\EasyDR-Setup.exe`.

## Ce que fait l'installateur
- installe dans `Program Files\Easy DR`, crée les raccourcis ;
- crée une tâche planifiée « EasyDR » (démarrage à l'ouverture de session, droits maximum, sans limite de durée) ;
- lance la protection immédiatement et télécharge les signatures.

Désinstallation classique (Paramètres Windows) : arrête le service et supprime la tâche.

## Architecture (pensée pour la RAM)
| Processus | Rôle | RAM mesurée* |
|---|---|---|
| `EasyDR.exe --daemon` | surveillance fichiers + comportements, icône, alertes | ~30 Mo |
| `--scan-worker` | analyse hash + YARA ; lancé à la demande, quitte après 90 s d'inactivité | ~50 Mo, seulement pendant l'analyse |
| `--update` | mise à jour des signatures (1×/jour) ; processus court | libéré après la mise à jour |
| interface | ouverte seulement quand tu la lances | — |

\*mesuré sous Linux/Python 3.12 ; attends-toi à un peu plus sous Windows.
Tous communiquent via une base SQLite (`%PROGRAMDATA%\EasyDR`). Erreurs : `easydr.log`.

## Sources GitHub utilisées
- **Neo23x0/signature-base** : ~750 fichiers de règles YARA + hash IOC, retéléchargés chaque jour (licence DRL 1.1 : conserver l'attribution).
Pour en ajouter : `SIGNATURE_SOURCES` dans `easydr/config.py` (les fichiers `.yar` doivent être dans un dossier `yara/`).

## Détection
- hash connus (IOC), règles YARA (score ≥ 80 = critique, 60-79 = suspect), fichier de test EICAR ;
- heuristiques : double extension, exécutable déguisé, packer en dossier à risque ;
- comportements : Office → shell, PowerShell encodé, suppression des copies cliché / sauvegardes (arrêt automatique), certutil/mshta distants.
Critique → quarantaine automatique (chiffrée, restaurable). Suspect → alerte, tu décides (Neutraliser / Faire confiance).

## Limites à connaître
- Pas de pilote noyau : détection **juste après** l'écriture/lancement, pas de blocage préventif.
- Faux positifs possibles (outils de pentest, cracks…) → « Faire confiance ».
- L'exécutable n'est pas signé : SmartScreen affichera un avertissement (un certificat de signature de code règle ça).
- Garde Microsoft Defender actif en complément.
