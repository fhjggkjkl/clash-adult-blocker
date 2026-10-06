# This launcher is UTF-8 with BOM for Windows PowerShell 5.1.
$ErrorActionPreference = 'Stop'
$worker = $null
try {
    $projectRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
    $nodeCommand = Get-Command node.exe -ErrorAction SilentlyContinue
    if (!$nodeCommand) { throw '请先安装 Node.js，再重新打开工具。' }
    $info = New-Object Diagnostics.ProcessStartInfo
    $info.FileName = $nodeCommand.Source
    $info.Arguments = '"' + (Join-Path $PSScriptRoot 'web-server.mjs') + '"'
    $info.WorkingDirectory = $projectRoot
    $info.UseShellExecute = $false
    $info.CreateNoWindow = $true
    $info.RedirectStandardOutput = $true
    $info.RedirectStandardError = $true
    $info.StandardOutputEncoding = New-Object Text.UTF8Encoding($false)
    $info.StandardErrorEncoding = New-Object Text.UTF8Encoding($false)
    $worker = New-Object Diagnostics.Process
    $worker.StartInfo = $info
    [void]$worker.Start()
    $stderr = $worker.StandardError.ReadToEndAsync()
    $ready = $worker.StandardOutput.ReadLineAsync()
    if (!$ready.Wait(15000)) { throw '启动超时，请重新打开工具。' }
    $state = $ready.GetAwaiter().GetResult() | ConvertFrom-Json
    if (!$state.ready -or !$state.url) { throw '启动失败，请检查 Node.js 和工具文件是否完整。' }
    Start-Process -FilePath $state.url
    $worker.WaitForExit()
} catch {
    if ($worker) { try { if (!$worker.HasExited) { $worker.Kill() } } catch {} }
    Add-Type -AssemblyName System.Windows.Forms
    $message = '本地网页版启动失败。请确认工具包已完整解压，且已安装 Node.js。'
    if ($_.Exception.Message -match '[\u3400-\u9fff]') { $message = $_.Exception.Message }
    [void][Windows.Forms.MessageBox]::Show($message, '本地网页工具', 'OK', 'Error')
} finally { if ($worker) { $worker.Dispose() } }
