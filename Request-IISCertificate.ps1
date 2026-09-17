<#
.SYNOPSIS
    Renova certificados emitidos por uma CA interna (AD CS) em servidores Windows remotos,
    reaproveitando o Common Name e as SANs do certificado atual, e refaz os bindings do IIS
    preservando as configuracoes existentes.

.DESCRIPTION
    Automatiza o que hoje se faz na mao pelo certlm.msc: Todas as Tarefas > Solicitar Novo
    Certificado > politica de inscricao do Active Directory > preencher Nome Comum e Nome
    Alternativo > Inscrever, e depois refazer o binding no IIS.

    Pressupoe que o servidor JA esta na OU que concede Inscricao (Enroll) no template. O script
    nao mexe em AD, em OU nem em permissao de template.

    TRES FASES

        1. VARREDURA (somente leitura, sempre acontece)
           Vai ao servidor e lista os certificados emitidos pelo template informado, com Nome
           Comum, SANs, validade, loja e quais bindings do IIS usam cada um.

        2. ESCOLHA (na estacao, interativa)
           Mostra a lista e pergunta qual ou quais renovar. Use -Thumbprint para escolher sem
           prompt, ou -All para todos.

        3. SOLICITACAO E BINDING (so com -Apply)
           Para cada escolhido, solicita um certificado novo do mesmo template com O MESMO
           Nome Comum e AS MESMAS SANs, e refaz os bindings que usavam o certificado antigo,
           escrevendo apenas CertificateHash e CertificateStoreName.

    A CHAVE PRIVADA NUNCA SAI DO SERVIDOR. Diferente de um deploy por PFX, aqui o par de
    chaves e gerado no proprio servidor e so a solicitacao vai ate a CA. Nao ha arquivo, nao ha
    senha e nao ha nada para transportar.

    O QUE E PRESERVADO NO BINDING
        sslFlags (SNI, Central Certificate Store, DisableHTTP2, DisableOCSPStapling,
        DisableQUIC, DisableTLS13, DisableLegacyTLS), IP, porta, hostname e a ordem dos
        bindings.

    ENSAIO POR PADRAO
        Sem -Apply o script varre, mostra o que faria e nao solicita nem altera nada.

    ROLLBACK
        Antes de qualquer alteracao de binding, o estado atual vai para um JSON. O certificado
        antigo nao e removido. Para desfazer:
            .\Request-IISCertificate.ps1 -Rollback <arquivo.json>

.PARAMETER ComputerName
    Servidores de destino.

.PARAMETER ComputerListFile
    Arquivo com um servidor por linha. Linhas vazias e iniciadas por # sao ignoradas.

.PARAMETER Template
    Template da CA. Aceita o nome interno (CN no AD, por exemplo WebServerEnergisaV4) ou o nome
    de exibicao (por exemplo "Web Server Energisa V4"). O script resolve um pelo outro
    consultando o Active Directory; sem -Template, lista os templates disponiveis e encerra.

.PARAMETER Thumbprint
    Renova exatamente estes certificados, sem perguntar.

.PARAMETER All
    Renova todos os certificados do template encontrados, sem perguntar.

.PARAMETER ExpiringInDays
    Restringe a varredura aos certificados que vencem dentro deste prazo.

.PARAMETER IncludeUnbound
    Inclui certificados do template que nao estao em nenhum binding do IIS. Por padrao apenas
    os que estao em uso sao oferecidos, porque sao os que a renovacao precisa acompanhar.

.PARAMETER Credential
    Credencial administrativa nos servidores.

.PARAMETER UseSsl
    Usa WinRM sobre HTTPS (porta 5986).

.PARAMETER CertificateStoreName
    Loja de destino do certificado novo, em LocalMachine. Padrao 'My' ("Pessoal" no certlm.msc);
    'WebHosting' e "Hospedagem na Web". Por padrao o script usa a mesma loja do certificado que
    esta sendo renovado.

.PARAMETER CAConfig
    Identificacao da CA no formato "servidor\nome-da-CA". So e necessario no caminho de
    contingencia por certreq.exe; o caminho principal usa a politica de inscricao do AD e
    descobre a CA sozinho.

.PARAMETER Apply
    Efetiva: solicita os certificados e refaz os bindings. Sem este parametro nada e solicitado
    nem alterado.

.PARAMETER BackupPath
    Pasta do JSON de rollback. Padrao: a pasta atual.

.PARAMETER Rollback
    Caminho de um JSON gerado por uma execucao anterior; devolve os bindings ao estado anterior.

.PARAMETER ReportCsv
    Caminho do CSV de resultado, com ';' e UTF-8 com BOM.

.PARAMETER LogFile
    Log opcional em arquivo.

.EXAMPLE
    .\Request-IISCertificate.ps1 -ComputerName WSCCP-HO -Template 'Web Server Energisa V4'

    Varredura. Mostra os certificados daquele template no servidor, com CN, SANs, validade e
    os bindings que os usam. Nada e solicitado nem alterado.

.EXAMPLE
    .\Request-IISCertificate.ps1 -ComputerName WSCCP-HO -Template 'Web Server Energisa V4' -Apply

    Varre, pergunta qual renovar, solicita o certificado novo com o mesmo CN e as mesmas SANs
    e refaz o binding.

.EXAMPLE
    .\Request-IISCertificate.ps1 -ComputerListFile .\servidores.txt `
        -Template WebServerEnergisaV4 -ExpiringInDays 45 -All -Apply -ReportCsv .\renovacao.csv

    Renova, sem perguntar, tudo que vence em 45 dias na lista inteira.

.EXAMPLE
    .\Request-IISCertificate.ps1 -ComputerName WSCCP-HO

    Sem -Template: lista os templates publicados no Active Directory, com nome interno e nome
    de exibicao, e encerra.

.NOTES
    Requisitos: PSRemoting habilitado, conta administrativa, IIS 7.5+ e o servidor com direito
    de Inscricao no template (tipicamente pela OU).

    A inscricao de um template de COMPUTADOR autentica na CA com a conta de maquina do
    servidor, e nao com a sua credencial. E por isso que funciona por PSRemoting sem CredSSP:
    nao ha segundo salto de credencial de usuario. Se o template exigir direito de inscricao do
    USUARIO, esse caminho falha -- e o erro vem com essa explicacao.
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High', DefaultParameterSetName = 'Renovar')]
param(
    [Parameter(ParameterSetName = 'Renovar')]
    [string[]]$ComputerName,

    [Parameter(ParameterSetName = 'Renovar')]
    [string]$ComputerListFile,

    [Parameter(ParameterSetName = 'Renovar')]
    [string]$Template,

    [Parameter(ParameterSetName = 'Renovar')]
    [string[]]$Thumbprint,

    [Parameter(ParameterSetName = 'Renovar')]
    [switch]$All,

    [Parameter(ParameterSetName = 'Renovar')]
    [int]$ExpiringInDays = 0,

    [Parameter(ParameterSetName = 'Renovar')]
    [switch]$IncludeUnbound,

    [pscredential]$Credential,
    [switch]$UseSsl,

    [Parameter(ParameterSetName = 'Renovar')]
    [ValidateSet('My','WebHosting','Mesma')]
    [string]$CertificateStoreName = 'Mesma',

    [Parameter(ParameterSetName = 'Renovar')]
    [string]$CAConfig,

    [Parameter(ParameterSetName = 'Renovar')]
    [switch]$Apply,

    [Parameter(ParameterSetName = 'Renovar')]
    [string]$BackupPath = '.',

    [Parameter(ParameterSetName = 'Rollback', Mandatory = $true)]
    [string]$Rollback,

    [int]$ThrottleLimit = 8,
    [string]$ReportCsv,
    [string]$LogFile
)

$ErrorActionPreference = 'Stop'

#region ---------------------------------------------------------------- Funcoes puras
function Write-ReqLog {
    [CmdletBinding()]
    param([string]$Message, [ValidateSet('INFO','AVISO','ERRO')][string]$Level = 'INFO', [string]$Path)
    $linha = '{0} [{1}] {2}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level, $Message
    Write-Verbose $linha
    if ($Path) {
        try {
            $sw = New-Object System.IO.StreamWriter($Path, $true, (New-Object System.Text.UTF8Encoding($true)))
            try { $sw.WriteLine($linha) } finally { $sw.Dispose() }
        } catch { Write-Verbose ('Falha ao gravar log: ' + $_.Exception.Message) }
    }
}

function Get-ReqErrorText {
    [CmdletBinding()]
    param($ErrorRecord)
    if ($null -eq $ErrorRecord) { return 'erro desconhecido' }
    $ex = if ($ErrorRecord -is [System.Management.Automation.ErrorRecord]) { $ErrorRecord.Exception } else { $ErrorRecord }
    if ($null -eq $ex) { return "$ErrorRecord" }
    $n = 0
    while ($ex.InnerException -and $n -lt 8) { $ex = $ex.InnerException; $n++ }
    return ($ex.Message -replace '\s+', ' ').Trim()
}

function Get-CertificateTemplateInfo {
    <#
    .SYNOPSIS
        Descobre de qual template da CA o certificado veio.
    .DESCRIPTION
        Sao duas extensoes da Microsoft, e um certificado pode trazer uma, outra ou as duas:

          1.3.6.1.4.1.311.20.2  Certificate Template Name -- templates V1. O valor e uma
                                BMPString (tag 0x1E, conteudo em UTF-16BE) com o nome interno.

          1.3.6.1.4.1.311.21.7  Certificate Template Information -- templates V2 e acima. O
                                valor e uma SEQUENCE com o OID do template e as versoes maior
                                e menor.

        Sem interpretar isso nao ha como saber quais certificados do servidor pertencem ao
        template que se quer renovar.
    #>
    [CmdletBinding()]
    param([System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate)

    $r = [ordered]@{ Nome = ''; Oid = ''; VersaoMaior = $null; VersaoMenor = $null; Origem = 'sem extensao de template' }
    if ($null -eq $Certificate) { return [pscustomobject]$r }

    # ---- 1.3.6.1.4.1.311.20.2: BMPString com o nome ----
    $ext = $Certificate.Extensions | Where-Object { $_.Oid.Value -eq '1.3.6.1.4.1.311.20.2' } | Select-Object -First 1
    if ($ext -and $ext.RawData -and $ext.RawData.Length -ge 2) {
        $raw = $ext.RawData
        if ($raw[0] -eq 0x1E) {
            $i = 1
            $len = [int]$raw[$i]
            if ($len -band 0x80) {
                $n = $len -band 0x7F
                $i++
                if ($n -ge 1 -and $n -le 4 -and ($i + $n) -le $raw.Length) {
                    $len = 0
                    for ($k = 0; $k -lt $n; $k++) { $len = ($len -shl 8) -bor [int]$raw[$i]; $i++ }
                } else { $len = 0 }
            } else { $i++ }
            if ($len -gt 0 -and ($i + $len) -le $raw.Length) {
                # BMPString e UTF-16 BIG endian; BigEndianUnicode e o encoding correto
                $r.Nome = [System.Text.Encoding]::BigEndianUnicode.GetString($raw, $i, $len)
                $r.Origem = 'extensao 1.3.6.1.4.1.311.20.2 (nome do template)'
            }
        }
    }

    # ---- 1.3.6.1.4.1.311.21.7: SEQUENCE { OID, INTEGER, INTEGER } ----
    $ext2 = $Certificate.Extensions | Where-Object { $_.Oid.Value -eq '1.3.6.1.4.1.311.21.7' } | Select-Object -First 1
    if ($ext2 -and $ext2.RawData -and $ext2.RawData.Length -ge 4 -and $ext2.RawData[0] -eq 0x30) {
        $raw = $ext2.RawData
        $i = 1
        $len = [int]$raw[$i]
        if ($len -band 0x80) {
            $n = $len -band 0x7F
            $i++
            if ($n -ge 1 -and $n -le 4 -and ($i + $n) -le $raw.Length) {
                $len = 0
                for ($k = 0; $k -lt $n; $k++) { $len = ($len -shl 8) -bor [int]$raw[$i]; $i++ }
            } else { $len = 0 }
        } else { $i++ }

        $fim = [Math]::Min($i + $len, $raw.Length)
        $inteiros = @()
        while ($i -lt $fim) {
            $tag = [int]$raw[$i]; $i++
            if ($i -ge $raw.Length) { break }
            $ll = [int]$raw[$i]
            if ($ll -band 0x80) {
                $n = $ll -band 0x7F
                $i++
                if ($n -lt 1 -or $n -gt 4 -or ($i + $n) -gt $raw.Length) { break }
                $ll = 0
                for ($k = 0; $k -lt $n; $k++) { $ll = ($ll -shl 8) -bor [int]$raw[$i]; $i++ }
            } else { $i++ }
            if ($ll -lt 0 -or ($i + $ll) -gt $raw.Length) { break }

            if ($tag -eq 0x06) {
                $r.Oid = ConvertFrom-DerOid -Bytes ([byte[]]$raw[$i..($i + $ll - 1)])
                if (-not $r.Nome) { $r.Origem = 'extensao 1.3.6.1.4.1.311.21.7 (OID do template)' }
            } elseif ($tag -eq 0x02) {
                $v = 0
                for ($k = 0; $k -lt $ll; $k++) { $v = ($v -shl 8) -bor [int]$raw[$i + $k] }
                $inteiros += $v
            }
            $i += $ll
        }
        if ($inteiros.Count -ge 1) { $r.VersaoMaior = $inteiros[0] }
        if ($inteiros.Count -ge 2) { $r.VersaoMenor = $inteiros[1] }
    }

    return [pscustomobject]$r
}

function ConvertFrom-DerOid {
    <#
    .SYNOPSIS
        Converte o conteudo DER de um OBJECT IDENTIFIER para notacao pontuada.
    #>
    [CmdletBinding()]
    param([byte[]]$Bytes)

    if (-not $Bytes -or $Bytes.Length -eq 0) { return '' }
    $partes = @()
    $primeiro = [int]$Bytes[0]
    $partes += [Math]::Floor($primeiro / 40)
    $partes += $primeiro % 40
    $valor = 0
    for ($i = 1; $i -lt $Bytes.Length; $i++) {
        $b = [int]$Bytes[$i]
        $valor = ($valor -shl 7) -bor ($b -band 0x7F)
        if (-not ($b -band 0x80)) { $partes += $valor; $valor = 0 }
    }
    return ($partes -join '.')
}

function Get-CertificateNames {
    <#
    .SYNOPSIS
        Devolve o Common Name e as SANs de DNS -- exatamente o que a renovacao precisa repetir.
    .DESCRIPTION
        As SANs saem por parsing ASN.1 da extensao 2.5.29.17, e nao por Format(), cujo texto e
        localizado e muda entre plataformas.
    #>
    [CmdletBinding()]
    param([System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate)

    $r = [ordered]@{ CommonName = ''; DnsNames = @() }
    if ($null -eq $Certificate) { return [pscustomobject]$r }

    try {
        $r.CommonName = $Certificate.GetNameInfo([System.Security.Cryptography.X509Certificates.X509NameType]::SimpleName, $false)
    } catch {
        if ($Certificate.Subject -match 'CN=([^,]+)') { $r.CommonName = $Matches[1].Trim() }
    }

    $nomes = New-Object System.Collections.Generic.List[string]
    $ext = $Certificate.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.17' } | Select-Object -First 1
    if ($ext -and $ext.RawData -and $ext.RawData.Length -ge 2 -and $ext.RawData[0] -eq 0x30) {
        $raw = $ext.RawData
        $i = 1
        $len = [int]$raw[$i]
        if ($len -band 0x80) {
            $n = $len -band 0x7F
            $i++
            if ($n -ge 1 -and $n -le 4 -and ($i + $n) -le $raw.Length) {
                $len = 0
                for ($k = 0; $k -lt $n; $k++) { $len = ($len -shl 8) -bor [int]$raw[$i]; $i++ }
            } else { $len = 0 }
        } else { $i++ }

        $fim = [Math]::Min($i + $len, $raw.Length)
        while ($i -lt $fim) {
            $tag = [int]$raw[$i]; $i++
            if ($i -ge $raw.Length) { break }
            $ll = [int]$raw[$i]
            if ($ll -band 0x80) {
                $n = $ll -band 0x7F
                $i++
                if ($n -lt 1 -or $n -gt 4 -or ($i + $n) -gt $raw.Length) { break }
                $ll = 0
                for ($k = 0; $k -lt $n; $k++) { $ll = ($ll -shl 8) -bor [int]$raw[$i]; $i++ }
            } else { $i++ }
            if ($ll -lt 0 -or ($i + $ll) -gt $raw.Length) { break }
            if ($tag -eq 0x82 -and $ll -gt 0) {
                [void]$nomes.Add([System.Text.Encoding]::ASCII.GetString($raw, $i, $ll))
            }
            $i += $ll
        }
    }

    # O CN so entra nas SANs se ainda nao estiver la: emissores modernos exigem o nome no SAN,
    # e repetir gera um certificado com entrada duplicada.
    if ($r.CommonName -and ($nomes -notcontains $r.CommonName)) {
        [void]$nomes.Insert(0, $r.CommonName)
    }
    $r.DnsNames = @($nomes | Where-Object { $_ } | Select-Object -Unique)
    return [pscustomobject]$r
}

function Test-TemplateMatch {
    <#
    .SYNOPSIS
        Diz se o certificado veio do template procurado.
    .DESCRIPTION
        Aceita nome interno, nome de exibicao ou OID, porque o operador conhece o template pelo
        nome que a tela do certlm mostra, que e o de exibicao, enquanto o certificado carrega o
        nome interno. Comparacao sem caixa e ignorando espacos, ja que "Web Server Energisa V4"
        e "WebServerEnergisaV4" sao o mesmo template.
    #>
    [CmdletBinding()]
    param([pscustomobject]$TemplateInfo, [string]$Procurado)

    if (-not $Procurado) { return $false }
    if ($null -eq $TemplateInfo) { return $false }

    $alvo = ($Procurado -replace '\s', '').ToLowerInvariant()
    if ($TemplateInfo.Nome) {
        if (($TemplateInfo.Nome -replace '\s', '').ToLowerInvariant() -eq $alvo) { return $true }
    }
    if ($TemplateInfo.Oid -and $TemplateInfo.Oid -eq $Procurado) { return $true }
    return $false
}
#endregion

#region ---------------------------------------------------------------- Apoio ao binding
function ConvertFrom-SslFlags {
    <#
    .SYNOPSIS
        Traduz o valor numerico de sslFlags para os nomes das opcoes ligadas.
    .DESCRIPTION
        Pares em array, e nao em [ordered]@{}: naquele tipo o indexador com [int] resolve por
        POSICAO e nao por chave, o que devolveria o nome da opcao vizinha.
    #>
    [CmdletBinding()]
    param([int]$Value)

    if ($Value -eq 0) { return 'nenhuma' }
    $mapa = @(
        @{ Bit = 1;  Nome = 'SNI' }
        @{ Bit = 2;  Nome = 'CentralCertStore' }
        @{ Bit = 4;  Nome = 'DisableHTTP2' }
        @{ Bit = 8;  Nome = 'DisableOCSPStapling' }
        @{ Bit = 16; Nome = 'DisableQUIC' }
        @{ Bit = 32; Nome = 'DisableTLS13' }
        @{ Bit = 64; Nome = 'DisableLegacyTLS' }
    )
    $ligadas = @()
    foreach ($e in $mapa) { if ($Value -band $e.Bit) { $ligadas += $e.Nome } }
    $conhecidos = 0; foreach ($e in $mapa) { $conhecidos = $conhecidos -bor $e.Bit }
    $resto = $Value -band (-bnot $conhecidos)
    if ($resto -ne 0) { $ligadas += ('bit desconhecido 0x{0:X}' -f $resto) }
    if (-not $ligadas) { return 'nenhuma' }
    return ($ligadas -join '+')
}

function Get-ThumbprintFromBytes {
    [CmdletBinding()]
    param([byte[]]$Bytes)
    if (-not $Bytes -or $Bytes.Length -eq 0) { return '' }
    return (($Bytes | ForEach-Object { $_.ToString('X2') }) -join '')
}

function New-CertReqInf {
    <#
    .SYNOPSIS
        Monta o arquivo INF do certreq.exe, usado quando o cmdlet Get-Certificate nao existe.
    .DESCRIPTION
        O Get-Certificate acompanha o modulo PKI (Windows 8 / Server 2012 em diante). Em
        servidores mais antigos o caminho e o certreq, que precisa deste INF. As SANs entram
        pela secao [Extensions], no formato "{text}" com um _continue_ por nome.
    #>
    [CmdletBinding()]
    param(
        [string]$CommonName,
        [string[]]$DnsNames,
        [string]$TemplateName,
        [int]$KeyLength = 2048,
        [switch]$Exportable
    )

    if (-not $CommonName) { throw 'New-CertReqInf: CommonName e obrigatorio' }
    if (-not $TemplateName) { throw 'New-CertReqInf: TemplateName e obrigatorio' }

    $linhas = New-Object System.Collections.Generic.List[string]
    [void]$linhas.Add('[NewRequest]')
    [void]$linhas.Add(('Subject = "CN={0}"' -f $CommonName))
    [void]$linhas.Add(('KeyLength = {0}' -f $KeyLength))
    [void]$linhas.Add('KeySpec = 1')
    [void]$linhas.Add('KeyUsage = 0xa0')                     # digitalSignature + keyEncipherment
    [void]$linhas.Add('MachineKeySet = True')
    [void]$linhas.Add('RequestType = PKCS10')
    [void]$linhas.Add('ProviderName = "Microsoft RSA SChannel Cryptographic Provider"')
    [void]$linhas.Add(('Exportable = {0}' -f $(if ($Exportable) { 'TRUE' } else { 'FALSE' })))
    [void]$linhas.Add('')
    [void]$linhas.Add('[RequestAttributes]')
    [void]$linhas.Add(('CertificateTemplate = {0}' -f $TemplateName))

    $dns = @($DnsNames | Where-Object { $_ } | Select-Object -Unique)
    if ($dns.Count -gt 0) {
        [void]$linhas.Add('')
        [void]$linhas.Add('[Extensions]')
        [void]$linhas.Add('2.5.29.17 = "{text}"')
        for ($i = 0; $i -lt $dns.Count; $i++) {
            $sufixo = if ($i -lt ($dns.Count - 1)) { '&' } else { '' }
            [void]$linhas.Add(('_continue_ = "dns={0}{1}"' -f $dns[$i], $sufixo))
        }
    }
    return (($linhas -join "`r`n") + "`r`n")
}

function Get-ServerList {
    [CmdletBinding()]
    param([string[]]$ComputerName, [string]$ComputerListFile)
    $lista = @()
    if ($ComputerName) { $lista += $ComputerName }
    if ($ComputerListFile) {
        if (-not (Test-Path -LiteralPath $ComputerListFile)) { throw ("Arquivo nao encontrado: {0}" -f $ComputerListFile) }
        $lista += @(Get-Content -LiteralPath $ComputerListFile | ForEach-Object {
            $l = "$_".Trim()
            if ($l -and -not $l.StartsWith('#')) { $l }
        })
    }
    return ,@($lista | Where-Object { $_ } | Select-Object -Unique)
}

function Get-RemotingErrorHint {
    [CmdletBinding()]
    param([string]$Message)
    $m = "$Message"
    if (-not $m) { return 'erro sem mensagem' }
    if ($m -match 'Access is denied|Acesso negado') {
        return 'a conta nao tem direito de administracao remota neste servidor: Administrador local ou "Remote Management Users"; para conta local veja LocalAccountTokenFilterPolicy.'
    }
    if ($m -match 'cannot be resolved|nao pode ser resolvido') { return 'o nome nao resolve em DNS a partir desta estacao.' }
    if ($m -match 'TrustedHosts') { return 'autenticacao caiu para NTLM e o destino nao esta em TrustedHosts; use o FQDN.' }
    if ($m -match 'WinRM cannot complete|cannot connect to the destination') { return 'o WinRM nao respondeu: servico parado, nao configurado ou porta 5985/5986 bloqueada.' }
    if ($m -match 'timed out|tempo limite') { return 'tempo esgotado ao conectar.' }
    return 'causa nao reconhecida; veja a mensagem original.'
}
#endregion

#region ---------------------------------------------------------------- Corpos remotos
$script:FuncoesRemotas = @(
    'Get-CertificateTemplateInfo','ConvertFrom-DerOid','Get-CertificateNames',
    'Test-TemplateMatch','ConvertFrom-SslFlags','Get-ThumbprintFromBytes','New-CertReqInf'
)

# ------------------------------------------------------------------ 1. varredura
$script:CorpoScan = @'
$resultado = [ordered]@{ Servidor = $env:COMPUTERNAME; Status = 'OK'; Erro = ''; Certificados = @(); Avisos = @() }

try {
    # ---- bindings do IIS, para saber quais certificados estao em uso ----
    $bindings = @()
    $dll = Join-Path $env:SystemRoot 'system32\inetsrv\Microsoft.Web.Administration.dll'
    if (Test-Path -LiteralPath $dll) {
        Add-Type -Path $dll -ErrorAction Stop
        $sm = New-Object Microsoft.Web.Administration.ServerManager
        foreach ($site in $sm.Sites) {
            foreach ($b in $site.Bindings) {
                if ("$($b.Protocol)" -ne 'https') { continue }
                $flags = 0; try { $flags = [int]$b['sslFlags'] } catch { }
                $partes = "$($b.BindingInformation)".Split(':')
                $bindings += [pscustomobject]@{
                    Site        = $site.Name
                    SiteEstado  = "$($site.State)"
                    BindingInfo = "$($b.BindingInformation)"
                    Ip          = $partes[0]
                    Porta       = if ($partes.Count -gt 1) { $partes[1] } else { '' }
                    HostName    = if ($partes.Count -gt 2) { $partes[2] } else { '' }
                    Thumbprint  = (Get-ThumbprintFromBytes -Bytes $b.CertificateHash)
                    Loja        = "$($b.CertificateStoreName)"
                    SslFlags    = $flags
                }
            }
        }
        $sm.Dispose()
    } else {
        $resultado.Avisos += 'IIS nao instalado; a varredura mostra os certificados, mas nao havera binding a refazer'
    }

    # ---- certificados das lojas ----
    foreach ($nomeLoja in @('My','WebHosting')) {
        $st = New-Object System.Security.Cryptography.X509Certificates.X509Store($nomeLoja,'LocalMachine')
        try { $st.Open('ReadOnly') } catch { continue }
        foreach ($cert in $st.Certificates) {
            $tpl = Get-CertificateTemplateInfo -Certificate $cert
            if (-not (Test-TemplateMatch -TemplateInfo $tpl -Procurado $Ctx.Template)) { continue }

            $nomes = Get-CertificateNames -Certificate $cert
            $dias  = [int][Math]::Floor(($cert.NotAfter - (Get-Date)).TotalDays)
            if ($Ctx.ExpiringInDays -gt 0 -and $dias -gt $Ctx.ExpiringInDays) { continue }

            $usados = @($bindings | Where-Object { $_.Thumbprint -ieq $cert.Thumbprint })
            if ($usados.Count -eq 0 -and -not $Ctx.IncludeUnbound) { continue }

            $resultado.Certificados += [pscustomobject]@{
                Servidor      = $env:COMPUTERNAME
                Thumbprint    = $cert.Thumbprint
                CommonName    = $nomes.CommonName
                DnsNames      = ($nomes.DnsNames -join ', ')
                Emissor       = $cert.Issuer
                ValidoAte     = $cert.NotAfter.ToString('yyyy-MM-dd HH:mm:ss')
                DiasRestantes = $dias
                Loja          = $nomeLoja
                TemplateNome  = $tpl.Nome
                TemplateOid   = $tpl.Oid
                TemplateFonte = $tpl.Origem
                ChavePrivada  = $cert.HasPrivateKey
                Bindings      = (@($usados | ForEach-Object { '{0} [{1}]' -f $_.Site, $_.BindingInfo }) -join ' | ')
                QtdBindings   = $usados.Count
                SslFlagsTexto = (@($usados | ForEach-Object { ConvertFrom-SslFlags -Value $_.SslFlags } | Select-Object -Unique) -join ', ')
                DetalheBindings = $usados
            }
        }
        $st.Close()
    }

    if ($resultado.Certificados.Count -eq 0) {
        $resultado.Avisos += ("nenhum certificado do template '{0}' encontrado com os filtros atuais" -f $Ctx.Template)
    }
} catch {
    $ex = $_.Exception; while ($ex.InnerException) { $ex = $ex.InnerException }
    $resultado.Status = 'ERRO'
    $resultado.Erro   = ($ex.Message -replace '\s+',' ')
}

return [pscustomobject]$resultado
'@

# ------------------------------------------------------------------ 2. solicitacao e binding
$script:CorpoAplicar = @'
$resultado = [ordered]@{ Servidor = $env:COMPUTERNAME; Status = 'OK'; Erro = ''; Itens = @(); Avisos = @() }

function Invoke-EnrollCertificate {
    param($Contexto, [string]$CommonName, [string[]]$DnsNames, [string]$Loja)

    $destino = "Cert:\LocalMachine\$Loja"

    # Caminho principal: Get-Certificate usa a politica de inscricao do AD e acha a CA sozinho
    $temGetCertificate = $null -ne (Get-Command Get-Certificate -ErrorAction SilentlyContinue)
    if ($temGetCertificate) {
        try {
            $p = @{
                Template          = $Contexto.TemplateNome
                SubjectName       = ("CN=" + $CommonName)
                CertStoreLocation = $destino
                ErrorAction       = 'Stop'
            }
            if ($DnsNames -and $DnsNames.Count -gt 0) { $p['DnsName'] = $DnsNames }
            $r = Get-Certificate @p
            if ($r.Status -eq 'Issued' -and $r.Certificate) {
                return [pscustomobject]@{ Sucesso = $true; Certificado = $r.Certificate; Metodo = 'Get-Certificate'; Detalhe = 'emitido pela politica de inscricao do AD' }
            }
            if ("$($r.Status)" -match 'Pending') {
                return [pscustomobject]@{ Sucesso = $false; Certificado = $null; Metodo = 'Get-Certificate'; Detalhe = 'a CA colocou a solicitacao em APROVACAO PENDENTE; emita manualmente e repita o binding' }
            }
            return [pscustomobject]@{ Sucesso = $false; Certificado = $null; Metodo = 'Get-Certificate'; Detalhe = ("status inesperado: " + $r.Status) }
        } catch {
            $m = ($_.Exception.Message -replace '\s+',' ')
            if ($m -match 'denied|negad') {
                $m += ' -- a inscricao autentica com a CONTA DE MAQUINA do servidor; confirme que ela (via OU/grupo) tem Inscricao no template'
            }
            $erroGet = $m
        }
    } else {
        $erroGet = 'cmdlet Get-Certificate indisponivel (modulo PKI ausente)'
    }

    # Contingencia: certreq.exe
    $tmp = Join-Path $env:TEMP ('certreq-' + [guid]::NewGuid().ToString('N'))
    $inf = "$tmp.inf"; $csr = "$tmp.req"; $cer = "$tmp.cer"; $rsp = "$tmp.rsp"
    try {
        $conteudo = New-CertReqInf -CommonName $CommonName -DnsNames $DnsNames -TemplateName $Contexto.TemplateNome
        [System.IO.File]::WriteAllText($inf, $conteudo, (New-Object System.Text.UTF8Encoding($false)))

        $saidaNew = & certreq.exe -new -f -q $inf $csr 2>&1 | Out-String
        if (-not (Test-Path -LiteralPath $csr)) {
            return [pscustomobject]@{ Sucesso = $false; Certificado = $null; Metodo = 'certreq'; Detalhe = ("Get-Certificate: $erroGet | certreq -new falhou: " + ($saidaNew -replace '\s+',' ')) }
        }

        $argsSubmit = @('-submit','-q')
        if ($Contexto.CAConfig) { $argsSubmit += @('-config', $Contexto.CAConfig) }
        $argsSubmit += @($csr, $cer, $rsp)
        $saidaSub = & certreq.exe @argsSubmit 2>&1 | Out-String
        if (-not (Test-Path -LiteralPath $cer)) {
            $dica = if (-not $Contexto.CAConfig) { ' -- informe -CAConfig "servidor\nome-da-CA": sem isso o certreq tenta abrir a janela de escolha da CA, que nao existe numa sessao remota' } else { '' }
            return [pscustomobject]@{ Sucesso = $false; Certificado = $null; Metodo = 'certreq'; Detalhe = ("Get-Certificate: $erroGet | certreq -submit falhou: " + ($saidaSub -replace '\s+',' ') + $dica) }
        }

        $saidaAcc = & certreq.exe -accept -q $cer 2>&1 | Out-String
        $novo = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 $cer
        $st = New-Object System.Security.Cryptography.X509Certificates.X509Store($Loja,'LocalMachine')
        $st.Open('ReadOnly')
        $inst = @($st.Certificates | Where-Object { $_.Thumbprint -ieq $novo.Thumbprint }) | Select-Object -First 1
        $st.Close()
        if ($inst) {
            return [pscustomobject]@{ Sucesso = $true; Certificado = $inst; Metodo = 'certreq'; Detalhe = 'emitido e aceito por certreq' }
        }
        return [pscustomobject]@{ Sucesso = $false; Certificado = $null; Metodo = 'certreq'; Detalhe = ('certreq -accept nao instalou o certificado: ' + ($saidaAcc -replace '\s+',' ')) }
    } catch {
        return [pscustomobject]@{ Sucesso = $false; Certificado = $null; Metodo = 'certreq'; Detalhe = ("Get-Certificate: $erroGet | certreq lancou: " + ($_.Exception.Message -replace '\s+',' ')) }
    } finally {
        foreach ($f in @($inf,$csr,$cer,$rsp)) { if (Test-Path -LiteralPath $f) { Remove-Item -LiteralPath $f -Force -ErrorAction SilentlyContinue } }
    }
}

try {
    $dll = Join-Path $env:SystemRoot 'system32\inetsrv\Microsoft.Web.Administration.dll'
    $temIIS = Test-Path -LiteralPath $dll
    if ($temIIS) { Add-Type -Path $dll -ErrorAction Stop }

    foreach ($alvo in $Ctx.Alvos) {
        $item = [ordered]@{
            Servidor         = $env:COMPUTERNAME
            ThumbprintAntigo = $alvo.Thumbprint
            CommonName       = $alvo.CommonName
            DnsNames         = $alvo.DnsNames
            Loja             = $alvo.Loja
            Acao             = ''
            MetodoEmissao    = ''
            ThumbprintNovo   = ''
            ValidoAte        = ''
            Detalhe          = ''
            Bindings         = ''
            Verificacao      = ''
        }

        # ---- 1. solicitar ----
        $dns = @("$($alvo.DnsNames)".Split(',') | ForEach-Object { $_.Trim() } | Where-Object { $_ })
        $loja = if ($Ctx.StoreName -and $Ctx.StoreName -ne 'Mesma') { $Ctx.StoreName } else { $alvo.Loja }
        $em = Invoke-EnrollCertificate -Contexto $Ctx -CommonName $alvo.CommonName -DnsNames $dns -Loja $loja
        $item.MetodoEmissao = $em.Metodo

        if (-not $em.Sucesso) {
            $item.Acao = 'FALHOU NA EMISSAO'
            $item.Detalhe = $em.Detalhe
            $resultado.Itens += [pscustomobject]$item
            continue
        }

        $novo = $em.Certificado
        $item.ThumbprintNovo = $novo.Thumbprint
        $item.ValidoAte = $novo.NotAfter.ToString('yyyy-MM-dd HH:mm:ss')
        $item.Detalhe = $em.Detalhe

        if (-not $novo.HasPrivateKey) {
            $item.Acao = 'EMITIDO SEM CHAVE PRIVADA'
            $item.Detalhe += ' -- o certificado nao serve para binding; verifique o provedor do template'
            $resultado.Itens += [pscustomobject]$item
            continue
        }

        # ---- 2. refazer os bindings que usavam o antigo ----
        if (-not $temIIS -or -not $alvo.DetalheBindings -or @($alvo.DetalheBindings).Count -eq 0) {
            $item.Acao = 'emitido (sem binding a refazer)'
            $item.Bindings = 'nenhum binding usava o certificado antigo'
            $resultado.Itens += [pscustomobject]$item
            continue
        }

        $feitos = @(); $erros = @()
        $sm = New-Object Microsoft.Web.Administration.ServerManager
        foreach ($bi in @($alvo.DetalheBindings)) {
            try {
                $b = $null
                foreach ($site in $sm.Sites) {
                    if ($site.Name -ne $bi.Site) { continue }
                    foreach ($cand in $site.Bindings) {
                        if ("$($cand.BindingInformation)" -eq $bi.BindingInfo -and "$($cand.Protocol)" -eq 'https') { $b = $cand; break }
                    }
                }
                if (-not $b) { throw 'binding nao encontrado na releitura' }

                $flagsAntes = 0; try { $flagsAntes = [int]$b['sslFlags'] } catch { }

                $bytes = New-Object byte[] ($novo.Thumbprint.Length / 2)
                for ($i = 0; $i -lt $bytes.Length; $i++) { $bytes[$i] = [Convert]::ToByte($novo.Thumbprint.Substring($i*2,2),16) }
                $b.CertificateHash      = $bytes
                $b.CertificateStoreName = $loja
                $sm.CommitChanges()

                $flagsDepois = 0; $conf = ''
                $smV = New-Object Microsoft.Web.Administration.ServerManager
                foreach ($site in $smV.Sites) {
                    if ($site.Name -ne $bi.Site) { continue }
                    foreach ($cand in $site.Bindings) {
                        if ("$($cand.BindingInformation)" -eq $bi.BindingInfo -and "$($cand.Protocol)" -eq 'https') {
                            $conf = Get-ThumbprintFromBytes -Bytes $cand.CertificateHash
                            try { $flagsDepois = [int]$cand['sslFlags'] } catch { }
                        }
                    }
                }
                $smV.Dispose()

                if ($conf -ieq $novo.Thumbprint) {
                    $aviso = if ($flagsDepois -ne $flagsAntes) { (' [ATENCAO: sslFlags mudou de {0} para {1}]' -f $flagsAntes, $flagsDepois) } else { '' }
                    $feitos += ('{0} [{1}] sslFlags={2}{3}' -f $bi.Site, $bi.BindingInfo, (ConvertFrom-SslFlags -Value $flagsDepois), $aviso)
                } else {
                    $erros += ('{0} [{1}]: apos o commit ainda aponta para {2}' -f $bi.Site, $bi.BindingInfo, $conf)
                }
            } catch {
                $erros += ('{0} [{1}]: {2}' -f $bi.Site, $bi.BindingInfo, ($_.Exception.Message -replace '\s+',' '))
            }
        }
        $sm.Dispose()

        $item.Bindings = ($feitos -join ' | ')
        if ($erros.Count -eq 0) {
            $item.Acao = 'renovado e vinculado'
            $item.Verificacao = ('{0} binding(s) confirmados na configuracao do IIS' -f $feitos.Count)
        } else {
            $item.Acao = 'renovado com falha no binding'
            $item.Verificacao = ($erros -join ' | ')
        }
        $resultado.Itens += [pscustomobject]$item
    }
} catch {
    $ex = $_.Exception; while ($ex.InnerException) { $ex = $ex.InnerException }
    $resultado.Status = 'ERRO'
    $resultado.Erro   = ($ex.Message -replace '\s+',' ')
}

return [pscustomobject]$resultado
'@

function New-RemoteScriptBlock {
    <#
    .SYNOPSIS
        Monta o scriptblock remoto com o param() como PRIMEIRA instrucao.
    .DESCRIPTION
        param() vindo depois de qualquer outra coisa -- uma definicao de funcao, por exemplo --
        e interpretado como chamada de um comando chamado 'param'. Os argumentos nunca sao
        vinculados, o corpo roda inteiro com as variaveis nulas e o resultado parece legitimo.
    #>
    [CmdletBinding()]
    param([ValidateSet('Scan','Aplicar')][string]$Tipo)

    $defs = foreach ($n in $script:FuncoesRemotas) {
        $cmd = Get-Command -Name $n -CommandType Function -ErrorAction Stop
        "function $n {`r`n" + $cmd.Definition + "`r`n}"
    }
    $corpo = if ($Tipo -eq 'Scan') { $script:CorpoScan } else { $script:CorpoAplicar }

    $texto = @('param($Ctx)', '', ($defs -join "`r`n`r`n"), '', $corpo) -join "`r`n"
    $sb = [scriptblock]::Create($texto)
    if ($null -eq $sb.Ast.ParamBlock) {
        throw 'Falha ao montar o bloco remoto: o param() nao ficou como primeira instrucao.'
    }
    return $sb
}
#endregion

#region ---------------------------------------------------------------- Templates no AD
function Get-AdCertificateTemplate {
    <#
    .SYNOPSIS
        Lista os templates publicados no Active Directory, com nome interno e nome de exibicao.
    .DESCRIPTION
        O certlm mostra o nome de EXIBICAO ("Web Server Energisa V4"), o certificado carrega o
        nome INTERNO ("WebServerEnergisaV4") e Get-Certificate espera o interno. Ter os dois
        lado a lado evita a confusao mais comum deste fluxo.

        Usa System.DirectoryServices, que faz parte do .NET -- nao exige RSAT.
    #>
    [CmdletBinding()]
    param()

    try {
        $cfg = ([ADSI]'LDAP://RootDSE').Get('configurationNamingContext')
        $caminho = "LDAP://CN=Certificate Templates,CN=Public Key Services,CN=Services,$cfg"
        $raiz = New-Object System.DirectoryServices.DirectoryEntry($caminho)
        $busca = New-Object System.DirectoryServices.DirectorySearcher($raiz)
        $busca.Filter = '(objectClass=pKICertificateTemplate)'
        $busca.PageSize = 500
        [void]$busca.PropertiesToLoad.AddRange(@('cn','displayName','msPKI-Cert-Template-OID'))

        $saida = @()
        foreach ($r in $busca.FindAll()) {
            $p = $r.Properties
            $saida += [pscustomobject]@{
                Nome     = if ($p['cn'].Count)          { "$($p['cn'][0])" }          else { '' }
                Exibicao = if ($p['displayname'].Count) { "$($p['displayname'][0])" } else { '' }
                Oid      = if ($p['mspki-cert-template-oid'].Count) { "$($p['mspki-cert-template-oid'][0])" } else { '' }
            }
        }
        return ,@($saida | Sort-Object Exibicao)
    } catch {
        Write-Warning ('Nao foi possivel consultar os templates no AD: ' + (Get-ReqErrorText $_))
        return ,@()
    }
}

function Resolve-TemplateName {
    <#
    .SYNOPSIS
        Converte o nome de exibicao no nome interno, que e o que a inscricao espera.
    #>
    [CmdletBinding()]
    param([string]$Informado, [object[]]$Templates)

    if (-not $Informado) { return $null }
    if (-not $Templates -or $Templates.Count -eq 0) {
        # Sem AD disponivel, seguir com o que foi informado
        return [pscustomobject]@{ Nome = $Informado; Exibicao = $Informado; Oid = ''; Resolvido = $false }
    }

    $semEspaco = ($Informado -replace '\s','').ToLowerInvariant()
    foreach ($t in $Templates) {
        if (($t.Nome -replace '\s','').ToLowerInvariant() -eq $semEspaco) {
            return [pscustomobject]@{ Nome = $t.Nome; Exibicao = $t.Exibicao; Oid = $t.Oid; Resolvido = $true }
        }
    }
    foreach ($t in $Templates) {
        if (($t.Exibicao -replace '\s','').ToLowerInvariant() -eq $semEspaco) {
            return [pscustomobject]@{ Nome = $t.Nome; Exibicao = $t.Exibicao; Oid = $t.Oid; Resolvido = $true }
        }
    }
    foreach ($t in $Templates) {
        if ($t.Oid -and $t.Oid -eq $Informado) {
            return [pscustomobject]@{ Nome = $t.Nome; Exibicao = $t.Exibicao; Oid = $t.Oid; Resolvido = $true }
        }
    }
    return [pscustomobject]@{ Nome = $Informado; Exibicao = $Informado; Oid = ''; Resolvido = $false }
}
#endregion

#region ---------------------------------------------------------------- Selecao
function Resolve-SelectionInput {
    <#
    .SYNOPSIS
        Interpreta a resposta do operador na escolha dos certificados.
    .DESCRIPTION
        Aceita numeros soltos, faixas e combinacoes: "2", "1,3", "1-3", "1,4-6". Tambem aceita
        "t" ou "todos" para tudo, e vazio para cancelar. Devolve indices base zero, ja
        ordenados e sem repeticao, e recusa qualquer numero fora da faixa em vez de ignorar em
        silencio -- escolher o certificado errado aqui significa renovar o site errado.
    #>
    [CmdletBinding()]
    param([string]$Entrada, [int]$Total)

    $r = [ordered]@{ Indices = @(); Cancelado = $false; Erro = '' }
    $txt = "$Entrada".Trim()

    if (-not $txt) { $r.Cancelado = $true; return [pscustomobject]$r }
    if ($txt -match '^(t|todos|all|\*)$') {
        $r.Indices = @(0..($Total - 1))
        return [pscustomobject]$r
    }

    $indices = New-Object System.Collections.Generic.List[int]
    foreach ($parte in ($txt -split ',')) {
        $p = $parte.Trim()
        if (-not $p) { continue }
        if ($p -match '^(\d+)\s*-\s*(\d+)$') {
            $de = [int]$Matches[1]; $ate = [int]$Matches[2]
            if ($de -gt $ate) { $tmp = $de; $de = $ate; $ate = $tmp }
            for ($i = $de; $i -le $ate; $i++) {
                if ($i -lt 1 -or $i -gt $Total) { $r.Erro = ("numero fora da faixa 1-{0}: {1}" -f $Total, $i); return [pscustomobject]$r }
                [void]$indices.Add($i - 1)
            }
        } elseif ($p -match '^\d+$') {
            $i = [int]$p
            if ($i -lt 1 -or $i -gt $Total) { $r.Erro = ("numero fora da faixa 1-{0}: {1}" -f $Total, $i); return [pscustomobject]$r }
            [void]$indices.Add($i - 1)
        } else {
            $r.Erro = ("nao entendi '{0}'; use numeros, faixas (1-3), 't' para todos ou vazio para cancelar" -f $p)
            return [pscustomobject]$r
        }
    }

    $r.Indices = @($indices | Sort-Object -Unique)
    if ($r.Indices.Count -eq 0) { $r.Cancelado = $true }
    return [pscustomobject]$r
}

function Show-CertificateTable {
    [CmdletBinding()]
    param([object[]]$Certificados)

    $i = 0
    $tab = $Certificados | ForEach-Object {
        $i++
        [pscustomobject]@{
            '#'        = $i
            Servidor   = $_.Servidor
            CommonName = $_.CommonName
            SANs       = $(if ("$($_.DnsNames)".Length -gt 44) { "$($_.DnsNames)".Substring(0,43) + [char]0x2026 } else { "$($_.DnsNames)" })
            ValidoAte  = "$($_.ValidoAte)".Split(' ')[0]
            Dias       = $_.DiasRestantes
            Loja       = $_.Loja
            Bindings   = $(if ($_.QtdBindings -gt 0) { "$($_.QtdBindings)x: $($_.Bindings)" } else { '(nenhum)' })
        }
    }
    ($tab | Format-Table -AutoSize | Out-String -Width 220).TrimEnd() | Write-Host
}
#endregion

#region ---------------------------------------------------------------- Execucao
function Invoke-OnServers {
    [CmdletBinding()]
    param([string[]]$Servers, [scriptblock]$ScriptBlock, [object[]]$ArgumentList,
          [pscredential]$Credential, [bool]$UseSsl, [int]$ThrottleLimit, [string]$LogFile)

    $p = @{
        ComputerName = $Servers; ScriptBlock = $ScriptBlock; ArgumentList = $ArgumentList
        ThrottleLimit = $ThrottleLimit; ErrorAction = 'SilentlyContinue'; ErrorVariable = 'erroRemoto'
    }
    if ($Credential) { $p['Credential'] = $Credential }
    if ($UseSsl)     { $p['UseSSL'] = $true }

    $saida = Invoke-Command @p
    $falhas = @()
    foreach ($e in $erroRemoto) {
        $alvo = if ($e.TargetObject) { "$($e.TargetObject)" } else { '(servidor nao identificado)' }
        $msg  = ($e.Exception.Message -replace '\s+',' ').Trim()
        $falhas += [pscustomobject]@{ Servidor = $alvo; Mensagem = $msg; Dica = (Get-RemotingErrorHint -Message $msg) }
        Write-ReqLog -Message ("Falha em {0}: {1}" -f $alvo, $msg) -Level 'ERRO' -Path $LogFile
    }
    return [pscustomobject]@{ Respostas = @($saida); Falhas = $falhas; Solicitados = @($Servers) }
}

function Show-ServerStatus {
    [CmdletBinding()]
    param([pscustomobject]$Resultado)
    $ok = @($Resultado.Respostas).Count
    $total = @($Resultado.Solicitados).Count
    Write-Host ''
    Write-Host ('Servidores: {0} de {1} responderam' -f $ok, $total) -ForegroundColor $(if ($ok -eq $total) { 'Green' } elseif ($ok -eq 0) { 'Red' } else { 'Yellow' })
    foreach ($f in $Resultado.Falhas) {
        Write-Host ''
        Write-Host ('  {0}: NAO RESPONDEU' -f $f.Servidor) -ForegroundColor Red
        Write-Host ('    erro  : {0}' -f $f.Mensagem)
        Write-Host ('    causa : {0}' -f $f.Dica) -ForegroundColor Yellow
    }
}

function Export-ReqCsv {
    [CmdletBinding()]
    param([object[]]$Linhas, [string]$Path)
    $texto = $Linhas | ConvertTo-Csv -NoTypeInformation -Delimiter ';'
    [System.IO.File]::WriteAllLines($Path, $texto, (New-Object System.Text.UTF8Encoding($true)))
}

function Invoke-CertRenewal {
    [CmdletBinding()]
    param([hashtable]$Cfg)

    $log = $Cfg.LogFile
    Write-ReqLog -Message ('Inicio; PowerShell {0}' -f $PSVersionTable.PSVersion) -Path $log

    $servidores = Get-ServerList -ComputerName $Cfg.ComputerName -ComputerListFile $Cfg.ComputerListFile
    if ($servidores.Count -eq 0) { throw 'Informe -ComputerName ou -ComputerListFile.' }

    # ---- templates ----
    $templates = Get-AdCertificateTemplate
    if (-not $Cfg.Template) {
        Write-Host ''
        Write-Host 'Templates publicados no Active Directory' -ForegroundColor Cyan
        Write-Host ('-' * 76)
        if ($templates.Count -eq 0) {
            Write-Host '  (nao foi possivel consultar o AD a partir desta estacao)' -ForegroundColor Yellow
        } else {
            ($templates | Select-Object @{n='Nome interno';e={$_.Nome}}, @{n='Nome de exibicao';e={$_.Exibicao}} |
                Format-Table -AutoSize | Out-String -Width 160).TrimEnd() | Write-Host
        }
        Write-Host ''
        Write-Host 'Informe -Template com o nome interno ou o de exibicao e rode de novo.' -ForegroundColor Cyan
        return @()
    }

    $tpl = Resolve-TemplateName -Informado $Cfg.Template -Templates $templates
    Write-Host ''
    Write-Host 'Template' -ForegroundColor Cyan
    Write-Host ('  Nome interno    : ' + $tpl.Nome)
    if ($tpl.Exibicao -and $tpl.Exibicao -ne $tpl.Nome) { Write-Host ('  Nome de exibicao: ' + $tpl.Exibicao) }
    if ($tpl.Oid) { Write-Host ('  OID             : ' + $tpl.Oid) }
    if (-not $tpl.Resolvido) {
        Write-Warning ('o template "{0}" nao foi localizado no AD; seguindo com o nome informado. Rode sem -Template para ver a lista.' -f $Cfg.Template)
    }

    # ---- fase 1: varredura ----
    $ctxScan = @{
        Template       = $tpl.Nome
        ExpiringInDays = [int]$Cfg.ExpiringInDays
        IncludeUnbound = [bool]$Cfg.IncludeUnbound
    }
    Write-Host ''
    Write-Host ('Varrendo {0} servidor(es)...' -f $servidores.Count)
    $res1 = Invoke-OnServers -Servers $servidores -ScriptBlock (New-RemoteScriptBlock -Tipo 'Scan') `
                -ArgumentList @($ctxScan) -Credential $Cfg.Credential -UseSsl ([bool]$Cfg.UseSsl) `
                -ThrottleLimit $Cfg.ThrottleLimit -LogFile $log
    Show-ServerStatus -Resultado $res1

    foreach ($r in $res1.Respostas) {
        if ($r.Status -ne 'OK') { Write-Warning ('{0}: {1}' -f $r.Servidor, $r.Erro) }
        foreach ($a in $r.Avisos) { Write-Warning ('{0}: {1}' -f $r.Servidor, $a) }
    }

    $certs = @($res1.Respostas | ForEach-Object { $_.Certificados })
    if ($certs.Count -eq 0) {
        Write-Host ''
        Write-Host 'Nenhum certificado deste template encontrado com os filtros atuais.' -ForegroundColor Yellow
        Write-Host 'Dicas: use -IncludeUnbound para ver os que nao estao em binding, ou aumente -ExpiringInDays.' -ForegroundColor Yellow
        return @()
    }

    Write-Host ''
    Write-Host ('Certificados do template "{0}"' -f $tpl.Nome) -ForegroundColor Cyan
    Show-CertificateTable -Certificados $certs

    # ---- fase 2: escolha ----
    $escolhidos = @()
    if ($Cfg.Thumbprint) {
        $alvoTp = @($Cfg.Thumbprint | ForEach-Object { ($_ -replace '\s','').ToUpperInvariant() })
        $escolhidos = @($certs | Where-Object { $alvoTp -contains $_.Thumbprint.ToUpperInvariant() })
        if ($escolhidos.Count -eq 0) { Write-Host 'Nenhum dos thumbprints informados esta na lista acima.' -ForegroundColor Yellow; return $certs }
    } elseif ($Cfg.All) {
        $escolhidos = $certs
    } else {
        Write-Host ''
        Write-Host 'Quais renovar? Numeros (2), lista (1,3), faixa (1-3), "t" para todos, vazio para cancelar.' -ForegroundColor Cyan
        while ($true) {
            $resp = Read-Host 'Escolha'
            $sel = Resolve-SelectionInput -Entrada $resp -Total $certs.Count
            if ($sel.Erro) { Write-Host ('  ' + $sel.Erro) -ForegroundColor Yellow; continue }
            if ($sel.Cancelado) { Write-Host 'Cancelado. Nada foi solicitado nem alterado.' -ForegroundColor Yellow; return $certs }
            $escolhidos = @($sel.Indices | ForEach-Object { $certs[$_] })
            break
        }
    }

    Write-Host ''
    Write-Host ('Selecionados: {0} certificado(s)' -f $escolhidos.Count) -ForegroundColor Cyan
    foreach ($c in $escolhidos) {
        Write-Host ('  {0} / {1}' -f $c.Servidor, $c.CommonName)
        Write-Host ('     SANs a repetir : {0}' -f $c.DnsNames)
        Write-Host ('     bindings       : {0}' -f $(if ($c.QtdBindings -gt 0) { $c.Bindings } else { '(nenhum)' }))
    }

    if (-not $Cfg.Apply) {
        Write-Host ''
        Write-Host 'ENSAIO: nada foi solicitado nem alterado.' -ForegroundColor Cyan
        Write-Host 'Repita com -Apply para solicitar os certificados e refazer os bindings.' -ForegroundColor Cyan
        return $certs
    }

    # ---- backup antes de qualquer escrita ----
    if (-not (Test-Path -LiteralPath $Cfg.BackupPath)) { [void](New-Item -ItemType Directory -Path $Cfg.BackupPath -Force) }
    $arqBackup = Join-Path $Cfg.BackupPath ('rollback-req-{0}.json' -f (Get-Date -Format 'yyyyMMdd-HHmmss'))
    $backup = @()
    foreach ($c in $escolhidos) {
        foreach ($b in @($c.DetalheBindings)) {
            $backup += [pscustomobject]@{
                Servidor = $c.Servidor; Site = $b.Site; BindingInfo = $b.BindingInfo
                ThumbprintAntes = $c.Thumbprint; LojaAntes = $b.Loja; SslFlags = $b.SslFlags
            }
        }
    }
    if ($backup.Count -gt 0) {
        [System.IO.File]::WriteAllText($arqBackup, ($backup | ConvertTo-Json -Depth 5), (New-Object System.Text.UTF8Encoding($true)))
        Write-Host ''
        Write-Host ('Rollback salvo em: {0}' -f $arqBackup) -ForegroundColor Green
    }

    $porServidor = $escolhidos | Group-Object Servidor
    $descricao = ('solicitar {0} certificado(s) do template {1} e refazer os bindings em {2} servidor(es)' -f $escolhidos.Count, $tpl.Nome, $porServidor.Count)
    if (-not $PSCmdlet.ShouldProcess(($porServidor.Name -join ', '), $descricao)) {
        Write-Host 'Cancelado pelo operador. Nada foi solicitado nem alterado.' -ForegroundColor Yellow
        return $certs
    }

    # ---- fase 3: solicitar e vincular, servidor a servidor ----
    $linhas = @()
    foreach ($g in $porServidor) {
        $ctxAplicar = @{
            TemplateNome = $tpl.Nome
            CAConfig     = $Cfg.CAConfig
            StoreName    = $Cfg.CertificateStoreName
            Alvos        = @($g.Group)
        }
        Write-Host ''
        Write-Host ('Solicitando em {0}...' -f $g.Name)
        $res2 = Invoke-OnServers -Servers @($g.Name) -ScriptBlock (New-RemoteScriptBlock -Tipo 'Aplicar') `
                    -ArgumentList @($ctxAplicar) -Credential $Cfg.Credential -UseSsl ([bool]$Cfg.UseSsl) `
                    -ThrottleLimit 1 -LogFile $log
        foreach ($f in $res2.Falhas) { Write-Warning ('{0}: {1} -- {2}' -f $f.Servidor, $f.Mensagem, $f.Dica) }
        foreach ($r in $res2.Respostas) {
            if ($r.Status -ne 'OK') { Write-Warning ('{0}: {1}' -f $r.Servidor, $r.Erro) }
            $linhas += $r.Itens
        }
    }

    # ---- relatorio ----
    if ($linhas.Count -gt 0) {
        Write-Host ''
        ($linhas | Select-Object Servidor, CommonName,
            @{n='Antes';e={ if ("$($_.ThumbprintAntigo)".Length -ge 8) { "$($_.ThumbprintAntigo)".Substring(0,8) } else { $_.ThumbprintAntigo } }},
            @{n='Depois';e={ if ("$($_.ThumbprintNovo)".Length -ge 8) { "$($_.ThumbprintNovo)".Substring(0,8) } else { '-' } }},
            ValidoAte, MetodoEmissao, Acao |
            Format-Table -AutoSize | Out-String -Width 210).TrimEnd() | Write-Host

        Write-Host ''
        Write-Host 'Resumo' -ForegroundColor Cyan
        Write-Host ('-' * 56)
        foreach ($g in ($linhas | Group-Object Acao | Sort-Object Count -Descending)) {
            Write-Host ('  {0,-38} {1,4}' -f $g.Name, $g.Count)
        }

        $falhas = @($linhas | Where-Object { "$($_.Acao)" -match 'FALHOU|falha|SEM CHAVE' })
        foreach ($f in $falhas) {
            Write-Host ''
            Write-Host ('  {0} / {1}: {2}' -f $f.Servidor, $f.CommonName, $f.Acao) -ForegroundColor Red
            Write-Host ('    {0}' -f $f.Detalhe)
            if ($f.Verificacao) { Write-Host ('    {0}' -f $f.Verificacao) }
        }
        if ($backup.Count -gt 0) {
            Write-Host ''
            Write-Host ('Para desfazer os bindings:  .\Request-IISCertificate.ps1 -Rollback "{0}"' -f $arqBackup) -ForegroundColor Cyan
        }
    }

    Write-ReqLog -Message 'Fim' -Path $log
    return $linhas
}

function Invoke-CertRollback {
    [CmdletBinding()]
    param([hashtable]$Cfg)

    if (-not (Test-Path -LiteralPath $Cfg.Rollback)) { throw ("Arquivo de rollback nao encontrado: {0}" -f $Cfg.Rollback) }
    $itens = @(Get-Content -LiteralPath $Cfg.Rollback -Raw | ConvertFrom-Json)
    if ($itens.Count -eq 0) { throw 'Arquivo de rollback vazio.' }

    $porServidor = $itens | Group-Object Servidor
    Write-Host ('Rollback: {0} binding(s) em {1} servidor(es)' -f $itens.Count, $porServidor.Count) -ForegroundColor Cyan
    if (-not $PSCmdlet.ShouldProcess(($porServidor.Name -join ', '), 'restaurar os certificados anteriores nos bindings')) {
        Write-Host 'Cancelado. Nada foi alterado.' -ForegroundColor Yellow
        return @()
    }

    $sb = [scriptblock]::Create(@'
param($Itens)
$saida = @()
$dll = Join-Path $env:SystemRoot 'system32\inetsrv\Microsoft.Web.Administration.dll'
Add-Type -Path $dll -ErrorAction Stop
$sm = New-Object Microsoft.Web.Administration.ServerManager
foreach ($it in $Itens) {
    $acao = ''; $detalhe = ''
    try {
        if ("$($it.ThumbprintAntes)" -notmatch '^[0-9A-Fa-f]{40}$') { throw ('thumbprint anterior invalido: ' + $it.ThumbprintAntes) }
        $alvo = $null
        foreach ($site in $sm.Sites) {
            if ($site.Name -ne $it.Site) { continue }
            foreach ($b in $site.Bindings) {
                if ("$($b.BindingInformation)" -eq $it.BindingInfo -and "$($b.Protocol)" -eq 'https') { $alvo = $b; break }
            }
        }
        if (-not $alvo) { throw 'binding nao encontrado' }
        $bytes = New-Object byte[] 20
        for ($i = 0; $i -lt 20; $i++) { $bytes[$i] = [Convert]::ToByte($it.ThumbprintAntes.Substring($i*2,2),16) }
        $alvo.CertificateHash = $bytes
        $alvo.CertificateStoreName = $(if ($it.LojaAntes) { $it.LojaAntes } else { 'My' })
        $sm.CommitChanges()
        $acao = 'restaurado'; $detalhe = ('voltou para ' + $it.ThumbprintAntes)
    } catch {
        $acao = 'FALHOU'; $detalhe = ($_.Exception.Message -replace '\s+',' ')
    }
    $saida += [pscustomobject]@{ Servidor = $env:COMPUTERNAME; Site = $it.Site; BindingInfo = $it.BindingInfo; Acao = $acao; Detalhe = $detalhe }
}
$sm.Dispose()
return $saida
'@)

    $todas = @()
    foreach ($g in $porServidor) {
        $p = @{ ComputerName = $g.Name; ScriptBlock = $sb; ArgumentList = @(,@($g.Group)); ErrorAction = 'SilentlyContinue'; ErrorVariable = 'err' }
        if ($Cfg.Credential) { $p['Credential'] = $Cfg.Credential }
        if ($Cfg.UseSsl)     { $p['UseSSL'] = $true }
        $r = Invoke-Command @p
        foreach ($e in $err) { Write-Warning ('{0}: {1}' -f $g.Name, ($e.Exception.Message -replace '\s+',' ')) }
        if ($r) { $todas += $r }
    }
    if ($todas.Count -gt 0) {
        ($todas | Format-Table -AutoSize | Out-String -Width 200).TrimEnd() | Write-Host
    }
    return $todas
}

# Guarda de dot-source: carregado com '.', o script apenas define as funcoes, o que permite que
# os testes Pester exercitem a logica pura sem tocar em servidor, AD ou CA.
if ($MyInvocation.InvocationName -ne '.') {
    $cfg = @{
        ComputerName = $ComputerName; ComputerListFile = $ComputerListFile
        Template = $Template; Thumbprint = $Thumbprint; All = $All
        ExpiringInDays = $ExpiringInDays; IncludeUnbound = $IncludeUnbound
        Credential = $Credential; UseSsl = $UseSsl
        CertificateStoreName = $CertificateStoreName; CAConfig = $CAConfig
        Apply = $Apply; BackupPath = $BackupPath; Rollback = $Rollback
        ThrottleLimit = $ThrottleLimit; LogFile = $LogFile
    }

    $resultado = if ($PSCmdlet.ParameterSetName -eq 'Rollback') {
        Invoke-CertRollback -Cfg $cfg
    } else {
        Invoke-CertRenewal -Cfg $cfg
    }

    if ($ReportCsv -and $resultado) {
        Export-ReqCsv -Linhas $resultado -Path $ReportCsv
        Write-Host ('Relatorio salvo em: {0}' -f $ReportCsv) -ForegroundColor Green
    }
}
#endregion
