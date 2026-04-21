$ErrorActionPreference = 'Stop'
$map = [ordered]@{
  'chat_agent_vii'   = '<AgentName>'
  '168\.61\.150\.239' = '203.0.113.20'
  'Claudine Irwin'   = 'User E'
  'Claudine'         = 'User E'
  'admin\.ops@contoso\.com' = 'user5@contoso.com'
  '24\.23\.142\.3'   = '203.0.113.10'
  '47\.161\.156\.103' = '203.0.113.30'
  '40\.86\.183\.173' = '198.51.100.40'
  '20\.97\.10\.99'   = '198.51.100.50'
  '128\.85\.236\.131' = '198.51.100.60'
  '40\.112\.242\.181' = '198.51.100.70'
  '40\.112\.242\.182' = '198.51.100.71'
  'u524@int\.zava-corp\.com' = 'user1@contoso.com'
  'u524'             = 'user1'
  'u3087'            = 'user6'
  'u332'             = 'user7'
  'int\.zava-corp\.com' = 'contoso.com'
  'zava-corp'        = 'contoso'
  'CyberSOC-Lake'    = '<WorkspaceName>'
  'CyberSOC'         = '<WorkspaceName>'
  'cog-2o4jt2d674qo4' = '<AzureOpenAIResource>'
  'e34d562e-ef12-4c4e-9bc0-7c6ae357c015' = '<WorkspaceId>'
  '0527ecb7-06fb-4769-b324-fd4a3bb865eb' = '<TenantId>'
  'a1cad83e-f160-4f18-b778-d98d8c92f691' = '<UserObjectId>'
  'ae8b5dc2-b985-4d10-9cd2-feec9726a9f9' = '<OAuthObjectId>'
  'irvins'           = 'user2'
  'elviaa'           = 'user3'
  'Hamidah'          = 'user4'
}
$files = @(
  'reports\incident_report_51873_2026-03-18.html',
  'reports\incident_report_55843_2026-03-31.html'
)
foreach ($f in $files) {
  $c = Get-Content -Raw $f
  foreach ($k in $map.Keys) { $c = $c -replace $k, $map[$k] }
  Set-Content -Path $f -Value $c -NoNewline
  Write-Host "Sanitized $f"
}
