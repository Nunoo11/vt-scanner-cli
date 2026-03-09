# Sécurité

## 🔐 Clé API

### Stockage Sécurisé (v1.2+)

La clé API est stockée de manière chiffrée dans `%USERPROFILE%\.vtapikey.secure` :

- **Chiffrement** : Utilise `Export-Clixml` avec SecureString (lié au compte utilisateur Windows)
- **Accès** : Seul l'utilisateur courant peut déchiffrer la clé
- **Suppression** : Option disponible dans le menu 5.4

### Bonnes Pratiques

- ✅ Ne jamais partager votre fichier `.vtapikey.secure`
- ✅ Ne jamais commiter `.vtapikey.secure` dans Git (déjà dans `.gitignore`)
- ✅ Régénérer la clé régulièrement via [VirusTotal GUI](https://www.virustotal.com/gui/my-apikey)
- ✅ Utiliser des variables d'environnement pour l'API key en production
- ✅ Vérifier les logs pour s'assurer qu'aucune clé n'est exposée

### Fichiers Sensibles

Les fichiers suivants ne doivent **JAMAIS** être partagés :

| Fichier | Pourquoi |
| ------- | -------- |
| `.vtapikey.secure` | Contient la clé API chiffrée |
| `vt_scan_report_*.csv` | Peut contenir des hashes de fichiers sensibles |
| `*.log` | Peut contenir des traces d'activité |

## 🛡️ Encodage et Intégrité

- Tous les fichiers texte sont encodés en **UTF-8 sans BOM**
- Vérification de l'encodage avant chaque commit (script de validation inclus)
- Utilisation de `.gitattributes` pour forcer les line endings appropriés

## 📊 Limites API VirusTotal

| Type | Limite (Gratuit) | Recommandation |
| ---- | ---------------- | -------------- |
| Fichiers/jour | 4 uploads | Utiliser le cache VT avant upload |
| URLs/minute | 4 scans | Délai de 16s entre requêtes |
| Requêtes/minute | 60 | Respecter `DelayBetweenRequests` |

## 🚨 En Cas de Compromission

1. Supprimer immédiatement `.vtapikey.secure`
2. Régénérer une nouvelle clé sur VirusTotal
3. Mettre à jour la clé dans le script (option 5.1)
4. Vérifier les logs pour toute activité suspecte
