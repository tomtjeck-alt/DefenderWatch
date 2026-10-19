# DefenderWatch

Script PowerShell de surveillance quotidienne de Microsoft Defender.

Il génère un rapport texte (dans `reports/`) des dernières 24 h :
- état du moteur (antivirus, protection temps réel, signatures, dernier scan complet) ;
- historique des menaces détectées ;
- événements à surveiller : détections, comportements suspects, blocages réseau, règles ASR, désactivation de la protection.

Les 30 derniers rapports sont conservés.

## Utilisation

```powershell
powershell -ExecutionPolicy Bypass -File .\defender-watch.ps1
```

À planifier via le Planificateur de tâches pour une exécution quotidienne.
