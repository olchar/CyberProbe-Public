$ErrorActionPreference = 'Continue'
$p = 'u524|zava|CyberSOC|cog-2o4jt2d674qo4|e34d562e-ef12|0527ecb7-06fb|irvins|elviaa|Hamidah|Claudine|u3087|u332|chat_agent_vii|24\.23\.142\.3|168\.61\.150\.239|47\.161\.156\.103|40\.86\.183\.173|20\.97\.10\.99|128\.85\.236\.131|a1cad83e-f160|ae8b5dc2-b985'
$files = git diff public/main..main --name-only
$dirty = @()
$clean = @()
foreach ($f in $files) {
  $content = git show "main:$f" 2>$null | Out-String
  $hits = ([regex]::Matches($content, $p, 'IgnoreCase')).Count
  if ($hits -gt 0) { $dirty += [pscustomobject]@{ File=$f; Hits=$hits } }
  else { $clean += $f }
}
Write-Host "=== DIRTY (contain PII) ===" -ForegroundColor Red
$dirty | Format-Table -AutoSize
Write-Host "=== CLEAN ===" -ForegroundColor Green
$clean | ForEach-Object { Write-Host "  $_" }
