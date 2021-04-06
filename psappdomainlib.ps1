<#
.SYNOPSIS
リモート AppDomain 下における PowerShell スクリプトの実行環境ライブラリ。
.DESCRIPTION
本スクリプトによって定義されるオブジェクトを使用することで、
外部スクリプトをリモート AppDomain にて実行できる。
.EXAMPLE
# デフォルト AppDomain とリモート AppDomain それぞれにて、外部スクリプトを実行する。

$localinstance = New-Object NASsystems.PSDomaining.RunspaceInvoke
    $targetscript = {
        'local AppDomain name ：{0}' -f [System.AppDomain]::CurrentDomain.FriendlyName
    }
    $localinstance.Invoke($targetscript.ToString())
$localinstance.Dispose()

$domain = [System.AppDomain]::CreateDomain('PSRUN')
$remoteinstance = $domain.CreateInstanceFromAndUnwrap($NASPSDMPATH, [NASsystems.PSDomaining.RunspaceInvoke].FullName)
    $targetscript = {
        'remote AppDomain name：{0}' -f [System.AppDomain]::CurrentDomain.FriendlyName
    }
    $remoteinstance.Invoke($targetscript.ToString())
$remoteinstance.Dispose()
[System.AppDomain]::Unload($domain)

# local AppDomain name ：DefaultDomain
# remote AppDomain name：PSRUN
.EXAMPLE
# 外部スクリプトへ入力を与える。

$domain = [System.AppDomain]::CreateDomain('PSRUN')
$instance = $domain.CreateInstanceFromAndUnwrap($NASPSDMPATH, [NASsystems.PSDomaining.RunspaceInvoke].FullName)
    $indata = Get-ChildItem
    $targetscript = {
        $input |% {$_.FullName}
    }
    $instance.Invoke($targetscript.ToString(), $indata)
$instance.Dispose()
[System.AppDomain]::Unload($domain)
.EXAMPLE
# 外部スクリプトへ .NET Framework によってマーシャリングされたオブジェクトを与える。
# 通常は PSSerializer によってシリアル化された疑似オブジェクトを受け取る。

$domain = [System.AppDomain]::CreateDomain('PSRUN')
$instance = $domain.CreateInstanceFromAndUnwrap($NASPSDMPATH, [NASsystems.PSDomaining.RunspaceInvoke].FullName)
    $indata = Get-Item .
    $targetscript = {
        $input |% {$_.psobject.TypeNames[0]}
    }
    $instance.Invoke($targetscript.ToString(), @($indata.psobject.BaseObject))
$instance.Dispose()
[System.AppDomain]::Unload($domain)
.EXAMPLE
# 外部スクリプトへ .NET Framework によってマーシャリングされたオブジェクトのコレクションを与える。
# 通常は PSSerializer によってシリアル化された疑似オブジェクトを受け取る。

$domain = [System.AppDomain]::CreateDomain('PSRUN')
$instance = $domain.CreateInstanceFromAndUnwrap($NASPSDMPATH, [NASsystems.PSDomaining.RunspaceInvoke].FullName)
    $indata = New-Object System.Collections.ObjectModel.Collection[System.MarshalByRefObject]
    Get-ChildItem |% {$indata.Add($_)}
    $targetscript = {
        $input |% {$_.psobject.TypeNames[0]}
    }
    $instance.Invoke($targetscript.ToString(), $indata.psobject.BaseObject)
$instance.Dispose()
[System.AppDomain]::Unload($domain)
.EXAMPLE
# 出力のマーシャリング

$targetscript = {
    Get-Item .
}

$domain = [System.AppDomain]::CreateDomain('PSRUN')
$instance = $domain.CreateInstanceFromAndUnwrap($NASPSDMPATH, [NASsystems.PSDomaining.RunspaceInvoke].FullName)

$outdata = New-Object System.Collections.ObjectModel.Collection[PSObject]
$exception = $instance.Invoke($targetscript.ToString(), $null, [ref] $outdata)
$outdata[0].psobject.TypeNames[0]
# System.Management.Automation.PSCustomObject または
# Deserialized.System.IO.DirectoryInfo

$outdata = New-Object System.Collections.ObjectModel.Collection[MarshalByRefObject]
$exception = $instance.Invoke($targetscript.ToString(), $null, [ref] $outdata)
$outdata[0].psobject.TypeNames[0]
# System.IO.DirectoryInfo

$instance.Dispose()
[System.AppDomain]::Unload($domain)
.EXAMPLE
# 例外のハンドリング1

$domain = $null
try {
    $domain = [System.AppDomain]::CreateDomain('PSRUN')
    $instance = $null
    try {
        $instance = $domain.CreateInstanceFromAndUnwrap($NASPSDMPATH, [NASsystems.PSDomaining.RunspaceInvoke].FullName)
        
        $targetscript = {
            $ErrorActionPreference = [System.Management.Automation.ActionPreference]::Stop
            Get-Date # この結果は、例外で処理が止まる場合は得られない
            Write-Error 'STOP HERE'
        }
        $outdata = New-Object System.Collections.ObjectModel.Collection[PSObject]
        $instance.Invoke($targetscript.ToString(), $null)
    } catch {
        $_.ToString()
    } finally {
        if($instance) {
            $instance.Dispose()
        }
    }
} finally {
    if($domain) {
        [System.AppDomain]::Unload($domain)
    }
}
.EXAMPLE
# 例外のハンドリング2

$domain = [System.AppDomain]::CreateDomain('PSRUN')
$instance = $domain.CreateInstanceFromAndUnwrap($NASPSDMPATH, [NASsystems.PSDomaining.RunspaceInvoke].FullName)

$targetscript = {
    $ErrorActionPreference = [System.Management.Automation.ActionPreference]::Stop
    Get-Date # 次の例外で処理が中断するが、それまでの結果は $outdata によって得られる
    Write-Error 'STOP HERE'
}
$outdata = New-Object System.Collections.ObjectModel.Collection[PSObject]
$exception = $instance.Invoke($targetscript.ToString(), $null, [ref] $outdata)
$outdata
$exception

$instance.Dispose()
[System.AppDomain]::Unload($domain)
.EXAMPLE
# Error ストリームの取得

$domain = [System.AppDomain]::CreateDomain('PSRUN')
$instance = $domain.CreateInstanceFromAndUnwrap($NASPSDMPATH, [NASsystems.PSDomaining.RunspaceInvoke].FullName)

$targetscript = {
    # $ErrorActionPreference を STOP にしなければ、スクリプトの処理は停止しない。
    Write-Error 'MY ERROR'
}
$instance.Invoke($targetscript.ToString())
$instance.Error

$instance.Dispose()
[System.AppDomain]::Unload($domain)
.EXAMPLE
# Error 以外のストリームの取得

$domain = [System.AppDomain]::CreateDomain('PSRUN')
$instance = $domain.CreateInstanceFromAndUnwrap($NASPSDMPATH, [NASsystems.PSDomaining.RunspaceInvoke].FullName)

$targetscript = {
    $VerbosePreference = [System.Management.Automation.ActionPreference]::Continue
    Write-Verbose 'Verbose message 1'
}
$instance.Invoke($targetscript.ToString())

$TargetRecordType = [Type][System.Management.Automation.VerboseRecord]
$VerbMsgList = [System.Management.Automation.PSSerializer]::Deserialize($instance.GetPSSerializedStream($TargetRecordType, 1))
$VerbMsgList

$instance.Dispose()
[System.AppDomain]::Unload($domain)
.NOTES
PS Domaining library version 1.00

MIT License

Copyright (c) 2020 NASsystems.info

Permission is hereby granted, free of charge, to any person obtaining a
copy of this software and associated documentation files (the
"Software"), to deal in the Software without restriction, including
without limitation the rights to use, copy, modify, merge, publish,
distribute, sublicense, and/or sell copies of the Software, and to
permit persons to whom the Software is furnished to do so, subject to
the following conditions:

The above copyright notice and this permission notice shall be included
in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
#>



[CmdletBinding()]
param()
& {
Set-StrictMode -Version 3
$ErrorActionPreference = [System.Management.Automation.ActionPreference]::Stop
New-Variable -Name asmfilepath -Value (Join-Path $pwd.ProviderPath "NASsystems.PSDomaining.dll") -Option Constant
New-Variable -Name asmsource -Option Constant -Value (@'
using System;
using System.Reflection;
using System.Runtime.Serialization;
using System.Management.Automation;
using System.Management.Automation.Runspaces;

namespace NASsystems.PSDomaining {
    [Serializable]
    public class CanNotResolveStream : Exception, ISerializable {
        public CanNotResolveStream() : base("Type から Stream を一意に特定できませんでした。(型 RunspaceInvoke 実装の再検討が必要)") {}
            
        public CanNotResolveStream(SerializationInfo info, StreamingContext context) : this() {}
        public override void GetObjectData(SerializationInfo info, StreamingContext ctx) {
            base.GetObjectData(info, ctx);
        }
    }
    
    public class RunspaceInvoke : MarshalByRefObject, IDisposable {
        public RunspaceInvoke() {
            InitialSessionState initialsessionstate;
            
            initialsessionstate = InitialSessionState.CreateDefault();
            rs = RunspaceFactory.CreateRunspace(initialsessionstate);
            rs.Open();
            ps = PowerShell.Create();
            ps.Runspace = rs;
        }
        
        protected Runspace rs;
        protected PowerShell ps;
        
        protected Runspace Runspace {
            get {
                if(rs == null) {
                    throw new ObjectDisposedException(null);
                }
                return rs;
            }
        }
        
        public void Dispose() {
            if(ps != null){
                ps.Dispose();
                ps = null;
            }
            if(rs != null) {
                rs.Dispose();
                rs = null;
            }
            GC.SuppressFinalize(this);
        }
        
        public override Object InitializeLifetimeService() {
            return null;
        }
        
        public RunspaceState RunspaceState {
            get {
                return Runspace.RunspaceStateInfo.State;
            }
        }
        
        public PSDataCollection<System.Management.Automation.ErrorRecord> Error {
            get {
                return ps.Streams.Error;
            }
        }
        
        protected PropertyInfo FindTargetStream(Type TargetRecordType) {
            PropertyInfo result;
            
            Type targetcollectiontype;
            System.Collections.Generic.List<PropertyInfo> targetproperties;
            Type t_psdatacollection;
            
            targetproperties = new System.Collections.Generic.List<PropertyInfo>();
            
            t_psdatacollection = typeof(System.Management.Automation.PSDataCollection<>);
            targetcollectiontype = t_psdatacollection.MakeGenericType(TargetRecordType);
            
            foreach(PropertyInfo pi in ps.Streams.GetType().GetProperties()) {
                if(pi.PropertyType == targetcollectiontype) {
                    targetproperties.Add(pi);
                }
            }
            if(targetproperties.Count > 1) {
                throw new CanNotResolveStream();
            }
            if(targetproperties.Count != 1) {
                throw new InvalidOperationException();
            }
            result = targetproperties[0];
            
            return result;
        }
        
        public string GetPSSerializedStream(Type TargetRecordType, int SerializeDepth) {
            PropertyInfo targetproperty;
            
            targetproperty = FindTargetStream(TargetRecordType);
            return PSSerializer.Serialize(targetproperty.GetGetMethod().Invoke(ps.Streams, Type.EmptyTypes), SerializeDepth);
        }
        
        public PSDataCollection<T> GetStream<T>() {
            PropertyInfo targetproperty;
            
            targetproperty = FindTargetStream(typeof(T));
            return (PSDataCollection<T>) targetproperty.GetGetMethod().Invoke(ps.Streams, Type.EmptyTypes);
        }
        
        public void RenewPowerShell() {
            if(ps != null){
                ps.Dispose();
                ps = null;
            }
            ps = PowerShell.Create();
            ps.Runspace = rs;
        }
        
        public System.Collections.ObjectModel.Collection<T> Invoke<T>(
            string TargetScript
            ) {
            ps.Commands.Clear();
            ps.AddScript(TargetScript);
            return ps.Invoke<T>();
        }
        
        public System.Collections.ObjectModel.Collection<PSObject> Invoke(
            string TargetScript
            ) {
            return this.Invoke<PSObject>(TargetScript);
        }
        
        public System.Collections.ObjectModel.Collection<T> Invoke<T>(
            string TargetScript,
            System.Collections.IEnumerable input
            ) {
            ps.Commands.Clear();
            ps.AddScript(TargetScript);
            return ps.Invoke<T>(input);
        }
        
        public System.Collections.ObjectModel.Collection<PSObject> Invoke(
            string TargetScript,
            System.Collections.IEnumerable input
            ) {
            return this.Invoke<PSObject>(TargetScript, input);
        }
        
        public Exception Invoke<T>(
            string TargetScript,
            System.Collections.IEnumerable input,
            ref System.Collections.ObjectModel.Collection<T> output
            ) {
            Exception result = null;
            
            ps.Commands.Clear();
            ps.AddScript(TargetScript);
            try {
                ps.Invoke<T>(input, output);
            }
            catch(Exception e) {
                result = e;
            }
            
            return result;
        }
    }
}
'@)

if(-not (Test-Path -LiteralPath $asmfilepath)) {
    Add-Type -TypeDefinition $asmsource -OutputAssembly $asmfilepath -OutputType Library
}

$loadtypelist = Add-Type -LiteralPath $asmfilepath -PassThru

$targetnamelist = @('NASsystems.PSDomaining.RunspaceInvoke')
$targettypelist = New-Object System.Collections.Generic.Dictionary[string`,type]

foreach($targetname in $targetnamelist) {
    $loadtypelist |? {$_.FullName -eq $targetname} |% {
        $targettypelist.Add($targetname, $_)
    }
}

New-Variable -Name NASPSDM     -Scope Global -Option Constant -Value $targettypelist['NASsystems.PSDomaining.RunspaceInvoke']
New-Variable -Name NASPSDMPATH -Scope Global -Option Constant -Value $asmfilepath
}

# SIG # Begin signature block
# MIIYmQYJKoZIhvcNAQcCoIIYijCCGIYCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUFTeq5Usw+h0WdP45cTL3/WAZ
# g0qgghLDMIIExTCCA62gAwIBAgIKGZ+FxAADAAAAhzANBgkqhkiG9w0BAQsFADBC
# MRQwEgYKCZImiZPyLGQBGRYEaW5mbzEaMBgGCgmSJomT8ixkARkWCk5BU3N5c3Rl
# bXMxDjAMBgNVBAMTBW5hc2NhMB4XDTE5MTAxMTE1MDgzNFoXDTMwMDUyNzEyNTE1
# NVowXTEUMBIGCgmSJomT8ixkARkWBGluZm8xGjAYBgoJkiaJk/IsZAEZFgpOQVNz
# eXN0ZW1zMRIwEAYDVQQLEwlPcGVyYXRvcnMxFTATBgNVBAMMDOS9kOiXpOOAgOWK
# nzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMVEDH4f2mkpQDIkWMk8
# BBTOuyibtO0L4i1Ge179GoBRKyywjZdtdr7qpxmt54TQJfneOOzUXDVqB2sHkYtt
# Ho413lsVS66ScvsZ6NrOqC6ANUdb0CamQ5n1kPw/xkMijkSB+qKpWGW/t+bvLN44
# jraCsmpdKvAce84usX3WHZJ3F2i+5gUDW8kfApR4QtZy7HpNtwMv+yYS8ihjcYsQ
# iYtPMt5x5ZxPpub2NY1xi0PQrTgu340zCeIdv3x6mQjM1C3IYRObIpi1KidmX2KH
# q/k9yZoTEJkVyc7oii34VcoXgIFfSPDoP1A8YWZ4cXCOvaJogwlseZ1wzClvC3IX
# 1VkCAwEAAaOCAaAwggGcMD0GCSsGAQQBgjcVBwQwMC4GJisGAQQBgjcVCISa3g6D
# wc1shaWBEoKh2GSD/ec+C4ao3F6G1fV5AgFkAgEDMBMGA1UdJQQMMAoGCCsGAQUF
# BwMDMA4GA1UdDwEB/wQEAwIHgDAbBgkrBgEEAYI3FQoEDjAMMAoGCCsGAQUFBwMD
# MB0GA1UdDgQWBBTqoat+erBrZrC762vQg/KHQeafMDAfBgNVHSMEGDAWgBSUMOqL
# kefSsX6ONUEWmHMSeSewsTBCBgNVHR8EOzA5MDegNaAzhjFodHRwOi8vbmFzY2Eu
# bmFzc3lzdGVtcy5pbmZvL0NlcnRFbnJvbGwvbmFzY2EuY3JsMGAGCCsGAQUFBwEB
# BFQwUjBQBggrBgEFBQcwAoZEaHR0cDovL25hc2NhLm5hc3N5c3RlbXMuaW5mby9D
# ZXJ0RW5yb2xsL25hc2NhLm5hc3N5c3RlbXMuaW5mbygzKS5jcnQwMwYDVR0RBCww
# KqAoBgorBgEEAYI3FAIDoBoMGElzYW9TQVRPQE5BU3N5c3RlbXMuaW5mbzANBgkq
# hkiG9w0BAQsFAAOCAQEAYqgcU8bBGS+BcHrJFeWk/qhZ+x4eipwW5f4bXS3VBWL3
# E44E0ZCOKOkk+GkwUoe9fBrHtgDikPqkoosz7WTXJqV1OFwGsQJc7BH/ZEvna2I8
# iCt3ftqtexuKEcQxshtxeG31Hbis40BMZTuVdaPWedIjHoE0qSdeaCEZxQOhLR6K
# QkhoX+qsvgoXr/96LWZ/iGlQ28bNMFOPF1z4xTiMTMDPRU0A93ZJvNik/Q5IoW6V
# pd0UB48cThn6UbYEOl5AX50CmEZljfWn1PdnkeJulwL9AHvvEOeAvrgJ9tP59lZg
# I2gMqlLq7H69Z++399xdpWh7OfcLgat5dmdby7dG4TCCBuwwggTUoAMCAQICEDAP
# b6zdZph0fKlGNqd4LbkwDQYJKoZIhvcNAQEMBQAwgYgxCzAJBgNVBAYTAlVTMRMw
# EQYDVQQIEwpOZXcgSmVyc2V5MRQwEgYDVQQHEwtKZXJzZXkgQ2l0eTEeMBwGA1UE
# ChMVVGhlIFVTRVJUUlVTVCBOZXR3b3JrMS4wLAYDVQQDEyVVU0VSVHJ1c3QgUlNB
# IENlcnRpZmljYXRpb24gQXV0aG9yaXR5MB4XDTE5MDUwMjAwMDAwMFoXDTM4MDEx
# ODIzNTk1OVowfTELMAkGA1UEBhMCR0IxGzAZBgNVBAgTEkdyZWF0ZXIgTWFuY2hl
# c3RlcjEQMA4GA1UEBxMHU2FsZm9yZDEYMBYGA1UEChMPU2VjdGlnbyBMaW1pdGVk
# MSUwIwYDVQQDExxTZWN0aWdvIFJTQSBUaW1lIFN0YW1waW5nIENBMIICIjANBgkq
# hkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAyBsBr9ksfoiZfQGYPyCQvZyAIVSTuc+g
# PlPvs1rAdtYaBKXOR4O168TMSTTL80VlufmnZBYmCfvVMlJ5LsljwhObtoY/AQWS
# Zm8hq9VxEHmH9EYqzcRaydvXXUlNclYP3MnjU5g6Kh78zlhJ07/zObu5pCNCrNAV
# w3+eolzXOPEWsnDTo8Tfs8VyrC4Kd/wNlFK3/B+VcyQ9ASi8Dw1Ps5EBjm6dJ3VV
# 0Rc7NCF7lwGUr3+Az9ERCleEyX9W4L1GnIK+lJ2/tCCwYH64TfUNP9vQ6oWMilZx
# 0S2UTMiMPNMUopy9Jv/TUyDHYGmbWApU9AXn/TGs+ciFF8e4KRmkKS9G493bkV+f
# PzY+DjBnK0a3Na+WvtpMYMyou58NFNQYxDCYdIIhz2JWtSFzEh79qsoIWId3pBXr
# GVX/0DlULSbuRRo6b83XhPDX8CjFT2SDAtT74t7xvAIo9G3aJ4oG0paH3uhrDvBb
# fel2aZMgHEqXLHcZK5OVmJyXnuuOwXhWxkQl3wYSmgYtnwNe/YOiU2fKsfqNoWTJ
# iJJZy6hGwMnypv99V9sSdvqKQSTUG/xypRSi1K1DHKRJi0E5FAMeKfobpSKupcNN
# gtCN2mu32/cYQFdz8HGj+0p9RTbB942C+rnJDVOAffq2OVgy728YUInXT50zvRq1
# naHelUF6p4MCAwEAAaOCAVowggFWMB8GA1UdIwQYMBaAFFN5v1qqK0rPVIDh2JvA
# nfKyA2bLMB0GA1UdDgQWBBQaofhhGSAPw0F3RSiO0TVfBhIEVTAOBgNVHQ8BAf8E
# BAMCAYYwEgYDVR0TAQH/BAgwBgEB/wIBADATBgNVHSUEDDAKBggrBgEFBQcDCDAR
# BgNVHSAECjAIMAYGBFUdIAAwUAYDVR0fBEkwRzBFoEOgQYY/aHR0cDovL2NybC51
# c2VydHJ1c3QuY29tL1VTRVJUcnVzdFJTQUNlcnRpZmljYXRpb25BdXRob3JpdHku
# Y3JsMHYGCCsGAQUFBwEBBGowaDA/BggrBgEFBQcwAoYzaHR0cDovL2NydC51c2Vy
# dHJ1c3QuY29tL1VTRVJUcnVzdFJTQUFkZFRydXN0Q0EuY3J0MCUGCCsGAQUFBzAB
# hhlodHRwOi8vb2NzcC51c2VydHJ1c3QuY29tMA0GCSqGSIb3DQEBDAUAA4ICAQBt
# VIGlM10W4bVTgZF13wN6MgstJYQRsrDbKn0qBfW8Oyf0WqC5SVmQKWxhy7VQ2+J9
# +Z8A70DDrdPi5Fb5WEHP8ULlEH3/sHQfj8ZcCfkzXuqgHCZYXPO0EQ/V1cPivNVY
# eL9IduFEZ22PsEMQD43k+ThivxMBxYWjTMXMslMwlaTW9JZWCLjNXH8Blr5yUmo7
# Qjd8Fng5k5OUm7Hcsm1BbWfNyW+QPX9FcsEbI9bCVYRm5LPFZgb289ZLXq2jK0KK
# IZL+qG9aJXBigXNjXqC72NzXStM9r4MGOBIdJIct5PwC1j53BLwENrXnd8ucLo0j
# GLmjwkcd8F3WoXNXBWiap8k3ZR2+6rzYQoNDBaWLpgn/0aGUpk6qPQn1BWy30mRa
# 2Coiwkud8TleTN5IPZs0lpoJX47997FSkc4/ifYcobWpdR9xv1tDXWU9UIFuq/DQ
# 0/yysx+2mZYm9Dx5i1xkzM3uJ5rloMAMcofBbk1a0x7q8ETmMm8c6xdOlMN4ZSA7
# D0GqH+mhQZ3+sbigZSo04N6o+TzmwTC7wKBjLPxcFgCo0MR/6hGdHgbGpm0yXbQ4
# CStJB6r97DDa8acvz7f9+tCjhNknnvsBZne5VhDhIG7GrrH5trrINV0zdo7xfCAM
# KneutaIChrop7rRaALGMq+P5CslUXdS5anSevUiumDCCBwYwggTuoAMCAQICED0a
# NXIwFYJjMNATcX6CQQgwDQYJKoZIhvcNAQEMBQAwfTELMAkGA1UEBhMCR0IxGzAZ
# BgNVBAgTEkdyZWF0ZXIgTWFuY2hlc3RlcjEQMA4GA1UEBxMHU2FsZm9yZDEYMBYG
# A1UEChMPU2VjdGlnbyBMaW1pdGVkMSUwIwYDVQQDExxTZWN0aWdvIFJTQSBUaW1l
# IFN0YW1waW5nIENBMB4XDTE5MDUwMjAwMDAwMFoXDTMwMDgwMTIzNTk1OVowgYQx
# CzAJBgNVBAYTAkdCMRswGQYDVQQIDBJHcmVhdGVyIE1hbmNoZXN0ZXIxEDAOBgNV
# BAcMB1NhbGZvcmQxGDAWBgNVBAoMD1NlY3RpZ28gTGltaXRlZDEsMCoGA1UEAwwj
# U2VjdGlnbyBSU0EgVGltZSBTdGFtcGluZyBTaWduZXIgIzEwggIiMA0GCSqGSIb3
# DQEBAQUAA4ICDwAwggIKAoICAQDLUVD/Vv78eGNwAZNanhj0O1P2B68hbPWiD30d
# cC2EdEiLnIqVBT1ZhPmRgHlRLNmKt8ELmroKis1mTwOLAbswyqu928BPEl78Cszi
# RbABOIq7TefUHFSY7TlYz1vCL0WYMQr5NTi4MS5ttB45cuG4Kr6fjIwapUauCytM
# mf4sS/wouSI6ZhfQqlaKIcDzliS00IUma7rwb2SYeaatvVzYU2srCtZyioVG4w0Y
# BtrGe0FWNpsVPvFqEaD3ZvUY0IBVY4doZusOeVWCXKPtSbhxhp6TN7Bro+pibKOu
# lui5/YurxvZZWwA8VyAYLXADp5zvkut5ocdd7Hy0j0vf6138oyDdkjjlalE6a4Wc
# TKCYCGlbBucqGdCVk4s7a4oFCSnY1trb43L6XEovexVWhjK/fwUJnS0qz1Dh5mEg
# 28cGgFxOFEa+rldxoqpsMJMcfnfLBulXzZH11TNyHOHaym7r8w/seVu7J57oHv4v
# 8rt/6eXQZ+u4DXykK1kDi5XtIijN+iw7xxYRr+PWsVBnacWO9XnQrf+HzPh/qvmi
# 7WH4yI1p2rH0UZHrZ1fRZBHrZMsDvUlVOkVDGCwlbNEvDC1v9UE1JKDyY1kWX9mk
# 6SxO27sxEsZt+FtuA9zLFY8bjXLs2w8VkNYSTu7iADElkzVvalulEmNAAYq5aYg6
# iLgPGQIDAQABo4IBeDCCAXQwHwYDVR0jBBgwFoAUGqH4YRkgD8NBd0UojtE1XwYS
# BFUwHQYDVR0OBBYEFG9NhgfYMieeLCnS0BMDgIHdBYMpMA4GA1UdDwEB/wQEAwIG
# wDAMBgNVHRMBAf8EAjAAMBYGA1UdJQEB/wQMMAoGCCsGAQUFBwMIMEAGA1UdIAQ5
# MDcwNQYMKwYBBAGyMQECAQMIMCUwIwYIKwYBBQUHAgEWF2h0dHBzOi8vc2VjdGln
# by5jb20vQ1BTMEQGA1UdHwQ9MDswOaA3oDWGM2h0dHA6Ly9jcmwuc2VjdGlnby5j
# b20vU2VjdGlnb1JTQVRpbWVTdGFtcGluZ0NBLmNybDB0BggrBgEFBQcBAQRoMGYw
# PwYIKwYBBQUHMAKGM2h0dHA6Ly9jcnQuc2VjdGlnby5jb20vU2VjdGlnb1JTQVRp
# bWVTdGFtcGluZ0NBLmNydDAjBggrBgEFBQcwAYYXaHR0cDovL29jc3Auc2VjdGln
# by5jb20wDQYJKoZIhvcNAQEMBQADggIBAMBo7bPY1FCb79N1yw879yTTejdFjSzv
# FvtRqSwftSW1ip9dC8IbIHSNZg82y6r2Ng0Pfo9LSnRDZawNKvYK7WttxQk47QAb
# +OXcpgpABUfvhMoJvENmg7+f7duOPdFBZLFwAi0DV1sYbxwsyx6yAOi6CS9bgQQ1
# ualjbY4IxRjR4SGs+RIKFMAS234lnawdEMBapYPSHxpmVfybKuLsN1eO5d+WMPjA
# kwtDGPkCb6lRr7hXCvMcB2k5jzecbdeRrqUuSelK3rPQjL85kA3Agc7wKgc6DKYt
# UdJy81PG+b3v7wxpSXefLFbE6aEIPQeuxR7WhCLHvH1DG1g4Yk7RBSWExUL4Hy/2
# 2/qrjFTsRYpsEk0wWlLlpBcJIubvb/VfhkPfoS29SkaSoIGWLGGXf0Bv2D+MNVqr
# 0cagO4VmVIDvHxr18ZuwoSd9sucLz/YtnFgTlKmG/EVSoihtf3QPUpFJeukS+Kk7
# sJL9fZEU6VttSJTyyJbuBTizxewwP+EHIASx2Iu8/bM+b/ICUwb0oO3JmnKjl18A
# +8tj0OjNdP11ydQ2Rbp7Elly7efyelAAePhDmkbY379U1F6xx9G8G4P0K+cL6EfI
# U57MGqz2+op1U2wghanVuGq6JI6KKwiRnzcEHPZvot00qpH/xhUuHkIaCSlP9MbN
# 4pGi00AMjnjjMYIFQDCCBTwCAQEwUDBCMRQwEgYKCZImiZPyLGQBGRYEaW5mbzEa
# MBgGCgmSJomT8ixkARkWCk5BU3N5c3RlbXMxDjAMBgNVBAMTBW5hc2NhAgoZn4XE
# AAMAAACHMAkGBSsOAwIaBQCgeDAYBgorBgEEAYI3AgEMMQowCKACgAChAoAAMBkG
# CSqGSIb3DQEJAzEMBgorBgEEAYI3AgEEMBwGCisGAQQBgjcCAQsxDjAMBgorBgEE
# AYI3AgEVMCMGCSqGSIb3DQEJBDEWBBTa2zjGzfHAOU0q0hPyzIr/GdTftTANBgkq
# hkiG9w0BAQEFAASCAQBalx41+TlaJ5xvjlz2GfhCQiqrzRnYMLXhAH96gSvBdnJO
# jba5kuqZTgJYVSeJrYHvrclLujM6s/GXilNNBIfgrG4lbkehAmBegv5HCVx+l15N
# euNtrmvwtl0GCPHcppd/W/0irJ0j4geZIxnhMjPHvaZ/uorYhCi85ErkjF5RhFim
# h18niMjbVnf0jczY+o+ssGkUz63q6/sXb6NCo8+PoUlBdnXNXyyf3iMuxPtop6IG
# IslS9HlhmDXtrzTCtBGw3ATKPP/3G/YzbkAk0ruKLXew5XBSw0cPGTyo5Qq34Vju
# 2vAt1mpABOcYrfZc5A5CbH+rYGbPwL3qko9dootFoYIDSzCCA0cGCSqGSIb3DQEJ
# BjGCAzgwggM0AgEBMIGRMH0xCzAJBgNVBAYTAkdCMRswGQYDVQQIExJHcmVhdGVy
# IE1hbmNoZXN0ZXIxEDAOBgNVBAcTB1NhbGZvcmQxGDAWBgNVBAoTD1NlY3RpZ28g
# TGltaXRlZDElMCMGA1UEAxMcU2VjdGlnbyBSU0EgVGltZSBTdGFtcGluZyBDQQIQ
# PRo1cjAVgmMw0BNxfoJBCDANBglghkgBZQMEAgIFAKB5MBgGCSqGSIb3DQEJAzEL
# BgkqhkiG9w0BBwEwHAYJKoZIhvcNAQkFMQ8XDTIwMDYwNTE2NTAzOVowPwYJKoZI
# hvcNAQkEMTIEMHJy/MoaanT1p8pAqzScGzY0QwncmhN4B5AeBO4yPmZLovimxPV9
# ehSRooxTc6M7WjANBgkqhkiG9w0BAQEFAASCAgDCvpbmSJQhp6rbRzHgItGscg/o
# tBrsTRqItyjgNKDnNYrIXvDdQAzw/64Zfvj5gEpBMJx/0a2wtUdRBPR6B1ApSdi1
# YAM97GGaSoS8gIwk+E3RPDq5i+AQAN0u4/zVjMY0Adq73ftzap/qvYEDa8YkK/Uz
# 0KwJdBjYajdfZG0gqlZZpvf1vm4UKEi8nh1IaRUsj4QhurIh3Gkx2AgJRZadtiNk
# MZPYP/WEa2U4tpvqdD9ipooUy+VEmA80qZJF5N2VoILPXSEC5jwgeUP5rpl3g+mQ
# IOgmAeY3y0U5e2Mfx+HjQmTlD2IEy4X18ZFB3yv17n/Y3s57u8HIvIXmQNbxehFB
# iQ1wtMqa5PDkyya3RukBHiuSdoiH3CQ8mayug17dOvzqvehmN8czotfJhPtRYVh3
# FJbrr3Eyrfe/qxTO+FFm7in4gb5dFti3kvnQ7T037RkRUn4GLSfdJE2hagJPptim
# bCTulM9D5q4Pwaxo3nAzqDdmH1qHrH1DoeIziEAMAN1pV5tkAvkhhsgDv298Oj6H
# 22b4c/Gb+dyZ0+TfTfi7Z975+xuBZluiGn6C07JI5uNqkpt3qVY9Dp9m7cPnDidT
# FQkJsjdJmCiVBCOUiD7vz6651kDrC/MgwH+wYRDwqYRMooBooSaOTCqxdCuLOoMx
# c1G3JGND8JN95F7vFQ==
# SIG # End signature block
