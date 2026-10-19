# ============================================================
#  Defender Watch  -  collecte quotidienne orientee anomalies
#  Genere un rapport des detections, comportements suspects,
#  blocages reseau et regles ASR (signaux de type zero-day).
#  Les rapports sont lisibles ensuite par une IA (Claude).
# ============================================================

$ErrorActionPreference = 'SilentlyContinue'
$base      = "C:\Users\tomtj\DefenderWatch"
$repDir    = Join-Path $base "reports"
$stamp     = Get-Date -Format "yyyy-MM-dd_HHmm"
$report    = Join-Path $repDir "defender_$stamp.txt"
$since     = (Get-Date).AddHours(-24)

# Codes d'evenements qui comptent (menaces + comportement + reseau + ASR)
$watch = @{
    1006='Malware detecte'; 1007='Action menee sur malware';
    1015='COMPORTEMENT SUSPECT detecte';
    1116='Menace detectee'; 1117='Menace neutralisee';
    1118='Echec neutralisation'; 1119='ECHEC CRITIQUE neutralisation';
    1121='Regle ASR : BLOQUE'; 1122='Regle ASR : audit';
    1125='Protection reseau : BLOQUE (audit)'; 1126='PROTECTION RESEAU : connexion BLOQUEE';
    5001='ALERTE: protection temps reel DESACTIVEE';
    5004='Config protection temps reel modifiee';
    1013='Historique des menaces efface'
}

$out = @()
$out += "================ DEFENDER WATCH ================"
$out += "Genere : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
$out += "Fenetre : dernieres 24 h (depuis $($since.ToString('yyyy-MM-dd HH:mm')))"
$out += ""

# --- Etat moteur ---
$st = Get-MpComputerStatus
$out += "--- ETAT MOTEUR ---"
$out += "Antivirus actif          : $($st.AntivirusEnabled)"
$out += "Protection temps reel    : $($st.RealTimeProtectionEnabled)"
$out += "Signatures (date)        : $($st.AntivirusSignatureLastUpdated)"
$fsa = if ($st.FullScanAge -ge 4294967295) { "jamais finalise (ou scan en cours)" } else { "il y a $($st.FullScanAge) jour(s)" }
$out += "Dernier scan complet     : $fsa"
$out += ""

# --- Menaces enregistrees ---
$threats = Get-MpThreatDetection
$out += "--- DETECTIONS DE MENACES ---"
if ($threats) {
    foreach ($t in ($threats | Sort-Object InitialDetectionTime -Descending | Select-Object -First 30)) {
        $out += "[$($t.InitialDetectionTime)] ThreatID=$($t.ThreatID)  Ressources: $($t.Resources -join '; ')"
    }
} else {
    $out += "Aucune menace detectee dans l'historique."
}
$out += ""

# --- Evenements d'anomalie (24h) ---
$evts = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Windows Defender/Operational'; StartTime=$since} -ErrorAction SilentlyContinue |
        Where-Object { $watch.ContainsKey($_.Id) }
$out += "--- EVENEMENTS A SURVEILLER (24h) ---"
if ($evts) {
    foreach ($e in ($evts | Sort-Object TimeCreated -Descending)) {
        $out += "[$($e.TimeCreated.ToString('MM-dd HH:mm'))] ($($e.Id)) $($watch[$e.Id])"
    }
    $out += ""
    $out += ">>> $($evts.Count) evenement(s) notable(s) a examiner."
} else {
    $out += "Aucun evenement d'anomalie (ni detection, ni comportement suspect, ni blocage reseau, ni ASR) sur 24 h."
}
$out += ""
$out += "================ FIN ================"

$out | Out-File -FilePath $report -Encoding UTF8

# Rotation : ne garder que les 30 derniers rapports
Get-ChildItem $repDir -Filter 'defender_*.txt' | Sort-Object LastWriteTime -Descending |
    Select-Object -Skip 30 | Remove-Item -Force -ErrorAction SilentlyContinue

Write-Output "Rapport ecrit : $report"
