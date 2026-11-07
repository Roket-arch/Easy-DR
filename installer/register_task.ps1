# Enregistre la tâche planifiée Easy DR : démarre à chaque ouverture de session, droits maximum,
# sans limite de durée (le défaut de schtasks coupe au bout de 3 jours), même sur batterie.
param([Parameter(Mandatory = $true)][string]$ExePath)
$action    = New-ScheduledTaskAction -Execute $ExePath -Argument "--daemon"
$trigger   = New-ScheduledTaskTrigger -AtLogOn
$settings  = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
             -StartWhenAvailable -Hidden -ExecutionTimeLimit ([TimeSpan]::Zero) `
             -RestartCount 5 -RestartInterval (New-TimeSpan -Minutes 1)
$principal = New-ScheduledTaskPrincipal -GroupId "S-1-5-32-545" -RunLevel Highest
Register-ScheduledTask -TaskName "EasyDR" -Action $action -Trigger $trigger -Settings $settings `
    -Principal $principal -Description "Protection Easy DR (arrière-plan)" -Force | Out-Null
