$msbuild = 'C:\Program Files\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\MSBuild.exe'
$proj    = 'C:\Users\xmaxt\source\repos\AshesOfCreation\AshesOfCreation\build\x64\aoc_server.vcxproj'
$args2   = @($proj, '/p:Configuration=Release', '/p:Platform=x64', '/v:minimal', '/nologo')
Write-Host "Building: $proj"
& $msbuild @args2
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

# Also compile the EAC popup mover (small C# helper).
# Kill any running instance first so the output file is not locked.
$csc = 'C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe'
$cs  = 'C:\Users\xmaxt\source\repos\AshesOfCreation\AshesOfCreation\src\eac_popup_mover.cs'
$out = 'C:\Users\xmaxt\source\repos\AshesOfCreation\AshesOfCreation\dist\Release\eac_popup_mover.exe'
if (Test-Path $csc) {
    Get-Process 'eac_popup_mover' -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    Write-Host "Building eac_popup_mover.exe ..."
    Push-Location (Split-Path $out)
    & $csc /target:winexe /nologo /out:$out $cs
    Pop-Location
    if ($LASTEXITCODE -ne 0) {
        Write-Warning "eac_popup_mover.exe failed to compile (non-fatal)"
    }
}
exit 0
