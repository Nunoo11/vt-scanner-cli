## [1.2] - 2026-03-09
### Ajoutés
- SecureString : Clé API chiffrée avec Export-Clixml
- Persistance automatique : Fichier .vtapikey.secure dans %USERPROFILE%
- Test-ApiKey : Validation automatique au démarrage
- ApiKeyManagement : Sous-menu de gestion (options 5.1-5.4)
- Check-ExistingScan : Consulter un scan par ID (option 6)
- Wait-VTAnalysis : Timeout configurable (max 5 min)
- Validation renforcée : Hash 64 caractères, schéma HTTP/HTTPS

### Corrigés
- Encodage UTF-8 sans BOM sur tous les fichiers texte
- BaseUrl .Trim() : Protection contre les espaces accidentels
- Test-ApiKey Response : Vérification [System.Net.WebException] avant accès
- gitingest aborted : Résolu avec encodage UTF-8 correct

### Statistiques
- Lignes de code : ~668 (vs ~395 en v1.1)
- Fonctions : 17 (vs 9 en v1.1)
- Fichiers documentés : 7 (tous en UTF-8 sans BOM)
# Change Log

## [1.1] - 2026-03-06
### Ajoutés
- Export des Résultats en CSV
- Barre de progression pendant le scan de dossiers
- Détection explicite du quota API (erreur 403)
- Try/Catch robuste dans la boucle de scan

### Corrigés
- Espaces supprimés dans `$script:BaseUrl` (erreur 400)
- Trim() sur les URLs utilisateur
- Nettoyage contenu markdownlint.json du script

## [1.0] - 2026-03-05
- Version initiale avec scanner fichiers/dossiers/URLs/hash

