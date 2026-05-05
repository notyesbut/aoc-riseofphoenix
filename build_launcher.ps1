$msbuild = 'C:\Program Files\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\MSBuild.exe'
$proj    = 'C:\Users\xmaxt\source\repos\AshesOfCreation\AshesOfCreation\build\x64\launcher.vcxproj'
$args2   = @($proj, '/p:Configuration=Release', '/p:Platform=x64', '/v:minimal', '/nologo')
Write-Host "Building: $proj"
& $msbuild @args2
exit $LASTEXITCODE
