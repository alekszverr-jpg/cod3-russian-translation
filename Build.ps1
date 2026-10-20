$ErrorActionPreference = 'Stop'
$compiler = Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
& $compiler /nologo /target:winexe /platform:anycpu "/out:$PSScriptRoot\COD3_RU_Installer.exe" /reference:System.Windows.Forms.dll /reference:System.Drawing.dll /reference:System.Web.Extensions.dll /reference:System.Core.dll "$PSScriptRoot\src\Installer.cs"
if ($LASTEXITCODE -ne 0) { throw 'Compilation failed' }
