$ErrorActionPreference = 'Continue'
$diff = git diff public/main..main 2>$null
$tenantNames = @(('za'+'va'),('nwt'+'raders'),('fa'+'brikam'))
$piiPatterns = @(
  '[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}',
  '\b(' + ($tenantNames -join '|') + ')-corp\b',
  'int\.' + $tenantNames[0] + '-corp\.com',
  'ghp_[A-Za-z0-9]{36}',
  'xox[baprs]-[A-Za-z0-9-]+'
)
$hits = @()
foreach ($p in $piiPatterns) {
  $m = $diff | Select-String -Pattern $p -AllMatches -CaseSensitive:$false
  if ($m) {
    $hits += [pscustomobject]@{ Pattern=$p; Count=$m.Matches.Count; Sample=($m.Line | Select-Object -First 1) }
  }
}
if ($hits.Count -gt 0) {
  Write-Host "PII HITS:" -ForegroundColor Red
  $hits | Format-List | Out-String | Write-Host
  exit 1
} else {
  Write-Host "CLEAN - no PII patterns detected" -ForegroundColor Green
}
