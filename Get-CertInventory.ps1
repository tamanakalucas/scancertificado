<#
.SYNOPSIS
    Inventaria certificados TLS de alvos Windows e Linux, identificando o hostname do
    servidor por metodos que nao exigem privilegio administrativo.

.DESCRIPTION
    Para cada endereco informado o script executa tres etapas independentes, cada uma com
    sua propria coluna de status e de detalhe de erro. Nenhum campo fica vazio sem motivo:
    quando nao ha valor, a coluna de detalhe explica por que.

    ETAPA 1 - DNS (StatusDNS / DetalheDNS)
        Resolve A, AAAA e a cadeia de CNAME. Gera uma linha por IP resolvido.

    ETAPA 2 - HOSTNAME (StatusHostname / DetalheHostname / OrigemHostname)
        Ordem de preferencia documentada, do mais autoritativo para o menos:
            1. SSH 'hostname -f'    (requer -SshUser; o proprio host responde)
            2. SNMP sysName         (requer -SnmpCommunity; o proprio host responde)
            3. NTLM via SMB 445     (requer -UseSmb; nome real da maquina)
            4. rootDSE LDAP 389     (requer -UseLdap; dnsHostName de controlador de dominio)
            5. NetBIOS UDP 137      (padrao; Windows e Linux com Samba)
            6. Banner SMTP 25       (requer -UseSmtpBanner)
            7. Certificado RDP 3389 (requer -UseRdp)
            8. PTR                  (padrao; o que o DNS diz, nao o que o host diz)
            9. CN/SAN do certificado (padrao, marcado como 'pista' - e o menos confiavel)

        O principio da ordem: o nome que o proprio host informa sobre si mesmo vence o nome
        que o DNS informa sobre ele, porque em VIP de balanceador o PTR aponta para o
        balanceador e nao para o servidor real.

    ETAPA 3 - TLS (StatusTLS / DetalheTLS / MetodoLeitura)
        Tentativas em sequencia, parando na primeira que entregar o certificado:
            M1 - SslStream com todos os protocolos que a plataforma suportar (inclui TLS 1.3
                 quando o SO permitir; a deteccao e por capacidade real, nao por edicao do
                 PowerShell).
            M2 - SslStream variando o SNI: nome original, alvo do CNAME e sem SNI. Detecta
                 virtual host por SNI e preenche SniDivergente quando os certificados diferem.
            M3 - ClientHello TLS 1.2 em socket bruto, com lista ampla de cipher suites,
                 extraindo a mensagem Certificate (que no TLS 1.2 trafega em claro). Nao
                 depende do Schannel. E o unico caminho quando o servidor encerra o handshake
                 depois de enviar o certificado (mTLS, SNI recusado).
            M4 - openssl s_client -showcerts, se disponivel. E o unico caminho para servidores
                 exclusivamente TLS 1.3 quando o Schannel da maquina nao suporta TLS 1.3.

    O certificado e a cadeia sao capturados dentro do callback de validacao, de modo que
    continuem disponiveis mesmo que o handshake falhe em seguida; o motivo da falha e
    registrado a parte, em DetalheTLS.

.PARAMETER InputFile
    Arquivo com um endereco por linha. Linhas vazias ou iniciadas por # sao ignoradas.
    Formatos aceitos: host, host:porta, IP, IP:porta, URL.

.PARAMETER Targets
    Lista de enderecos informada diretamente, no lugar de -InputFile.

.PARAMETER DefaultPort
    Porta usada quando a entrada nao traz porta explicita. Padrao 443.

.PARAMETER AlternatePorts
    Portas adicionais a tentar SOMENTE quando a porta principal recusar a conexao (RST) ou
    expirar. Desligado por padrao, porque amplia o trafego gerado. Exemplo: 8443,9443,8080.

.PARAMETER PreferIPv4
    Ignora enderecos IPv6 resolvidos. Util em estacoes sem rota IPv6, onde cada AAAA vira
    uma linha de falha sem valor de inventario.

.PARAMETER StartTlsMode
    Auto (padrao), None, Smtp ou Ldap. Em Auto, usa STARTTLS de SMTP nas portas 25 e 587 e
    de LDAP na porta 389.

.PARAMETER CompareSni
    Quando a leitura principal ja obteve o certificado, repete a conexao com o SNI do alvo do
    CNAME e sem SNI, para detectar virtual host por SNI. Dobra o numero de conexoes na porta
    do alvo, por isso e opcional. Quando a leitura principal falha, a variacao de SNI (M2) e
    sempre tentada, independentemente deste parametro.

.PARAMETER SkipNetBios
    Desliga a consulta NetBIOS (UDP 137).

.PARAMETER SkipPtr
    Desliga a consulta PTR.

.PARAMETER UseSmb
    Habilita NTLM via SMB (TCP 445). Abre conexao em porta extra.

.PARAMETER UseRdp
    Habilita leitura do certificado RDP (TCP 3389, com negociacao X.224). Porta extra.

.PARAMETER UseSmtpBanner
    Habilita leitura do banner SMTP (TCP 25). Porta extra.

.PARAMETER UseLdap
    Habilita rootDSE LDAP anonimo (TCP 389). Porta extra.

.PARAMETER UseSshBanner
    Habilita leitura do banner SSH (TCP 22), apenas para inferir o sistema operacional.

.PARAMETER SnmpCommunity
    Community SNMPv2c. Quando informado, consulta sysName (OID 1.3.6.1.2.1.1.5.0) em UDP 161.
    E o metodo que mais resolve para alvos Linux sem Samba.

.PARAMETER SshUser
    Usuario SSH. Quando informado junto de -SshKeyPath, executa 'hostname -f' via ssh.exe.
    Nunca pede senha interativamente e nunca grava credencial.

.PARAMETER SshKeyPath
    Caminho da chave privada usada pelo SSH.

.PARAMETER OpenSslPath
    Caminho de openssl.exe. Quando omitido, o script procura no PATH e nos locais usuais do
    Git for Windows. Opcional: sem ele o script funciona, apenas com menos informacao.

.PARAMETER ThrottleLimit
    Numero de runspaces simultaneos. Padrao 16.

.PARAMETER TcpTimeoutMs
    Timeout de conexao TCP, em milissegundos. Padrao 5000.

.PARAMETER TlsTimeoutMs
    Timeout do handshake TLS e da leitura, em milissegundos. Padrao 7000.

.PARAMETER HostnameTimeoutMs
    Timeout de cada metodo de descoberta de hostname. Padrao 1500.

.PARAMETER WarningDays
    Limite em dias para marcar a situacao como 'EXPIRA EM BREVE'. Padrao 30.

.PARAMETER OutputCsv
    Caminho do CSV de saida. Delimitador ';' e UTF-8 com BOM, para o Excel pt-BR.

.PARAMETER OutputJson
    Caminho opcional do JSON de saida.

.PARAMETER LogFile
    Caminho opcional de log. Todo erro tratado vai para o log, alem da coluna de detalhe.

.PARAMETER PassThru
    Devolve os objetos no pipeline em vez de imprimir a tabela resumida.

.EXAMPLE
    .\Get-CertInventory.ps1 -InputFile .\endereco.txt -OutputCsv .\resultado.csv

    Inventario basico, so com os metodos que nao abrem portas extras.

.EXAMPLE
    .\Get-CertInventory.ps1 -InputFile .\endereco.txt -OutputCsv .\resultado.csv `
        -SnmpCommunity 'publico' -UseSmb -Verbose -LogFile .\scan.log

    Acrescenta SNMP e NTLM/SMB, que sao os metodos que mais resolvem hostname de servidor
    Linux e de servidor Windows, respectivamente.

.EXAMPLE
    .\Get-CertInventory.ps1 -InputFile .\endereco.txt -OutputCsv .\resultado.csv `
        -AlternatePorts 8443,9443,8080 -PreferIPv4

    Quando a porta 443 recusa a conexao, tenta as portas alternativas informadas. Util em
    parques onde a aplicacao escuta em porta nao padrao.

.EXAMPLE
    .\Get-CertInventory.ps1 -InputFile .\endereco.txt -PassThru |
        Where-Object Situacao -ne 'OK' | Format-Table Entrada,IP,StatusTLS,DetalheTLS

    Investiga apenas o que falhou, com o motivo explicito de cada etapa.

.NOTES
    Compativel com Windows PowerShell 5.1 e PowerShell 7. Nao exige RSAT, modulos da
    PSGallery nem privilegio administrativo. openssl.exe e ssh.exe sao opcionais.
#>
[CmdletBinding()]
param(
    [string]$InputFile,
    [string[]]$Targets,

    [int]$DefaultPort = 443,
    [int[]]$AlternatePorts = @(),
    [switch]$PreferIPv4,

    [ValidateSet('Auto','None','Smtp','Ldap')]
    [string]$StartTlsMode = 'Auto',

    [switch]$SkipNetBios,
    [switch]$SkipPtr,
    [switch]$UseSmb,
    [switch]$UseRdp,
    [switch]$UseSmtpBanner,
    [switch]$UseLdap,
    [switch]$UseSshBanner,
    [switch]$CompareSni,

    [string]$SnmpCommunity,
    [string]$SshUser,
    [string]$SshKeyPath,
    [string]$OpenSslPath,

    [int]$ThrottleLimit = 16,
    [int]$TcpTimeoutMs = 5000,
    [int]$TlsTimeoutMs = 7000,
    [int]$HostnameTimeoutMs = 1500,
    [int]$WarningDays = 30,

    [string]$OutputCsv,
    [string]$OutputJson,
    [string]$LogFile,
    [switch]$PassThru
)

$ErrorActionPreference = 'Stop'

#region ---------------------------------------------------------------- Helpers binarios
# Em PowerShell os operadores de deslocamento PRESERVAM o tipo do operando da esquerda.
# [byte]3 -shl 8 devolve 0, nao 768, e o truncamento e silencioso. Todo parsing binario
# deste script passa por estes helpers, que promovem para [int] antes de deslocar.

function ConvertFrom-BigEndianUInt16 {
    [CmdletBinding()]
    param([byte[]]$Bytes, [int]$Offset = 0)
    if ($null -eq $Bytes -or $Offset -lt 0 -or ($Offset + 2) -gt $Bytes.Length) {
        throw "ConvertFrom-BigEndianUInt16: offset $Offset fora do buffer ($($Bytes.Length) bytes)"
    }
    return ((([int]$Bytes[$Offset]) -shl 8) -bor [int]$Bytes[$Offset + 1])
}

function ConvertFrom-BigEndianUInt24 {
    [CmdletBinding()]
    param([byte[]]$Bytes, [int]$Offset = 0)
    if ($null -eq $Bytes -or $Offset -lt 0 -or ($Offset + 3) -gt $Bytes.Length) {
        throw "ConvertFrom-BigEndianUInt24: offset $Offset fora do buffer ($($Bytes.Length) bytes)"
    }
    return ((([int]$Bytes[$Offset]) -shl 16) -bor (([int]$Bytes[$Offset + 1]) -shl 8) -bor [int]$Bytes[$Offset + 2])
}

function ConvertTo-BigEndianBytes {
    [CmdletBinding()]
    param([int]$Value, [ValidateSet(2,3)][int]$Size = 2)
    if ($Size -eq 3) {
        return ,[byte[]]@([byte](($Value -shr 16) -band 0xFF), [byte](($Value -shr 8) -band 0xFF), [byte]($Value -band 0xFF))
    }
    return ,[byte[]]@([byte](($Value -shr 8) -band 0xFF), [byte]($Value -band 0xFF))
}
#endregion

#region ---------------------------------------------------------------- Log
function Write-ScanLog {
    [CmdletBinding()]
    param(
        [string]$Message,
        [ValidateSet('INFO','AVISO','ERRO')][string]$Level = 'INFO',
        [string]$Path
    )
    $line = '{0} [{1}] {2}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level, $Message
    if ($Level -eq 'ERRO')      { Write-Verbose $line }
    elseif ($Level -eq 'AVISO') { Write-Verbose $line }
    else                        { Write-Verbose $line }
    if ($Path) {
        try {
            $sw = New-Object System.IO.StreamWriter($Path, $true, (New-Object System.Text.UTF8Encoding($true)))
            try { $sw.WriteLine($line) } finally { $sw.Dispose() }
        } catch {
            Write-Verbose ('Falha ao gravar log em {0}: {1}' -f $Path, $_.Exception.Message)
        }
    }
}

function Get-ErrorText {
    [CmdletBinding()]
    param($ErrorRecord)
    if ($null -eq $ErrorRecord) { return 'erro desconhecido' }
    $ex = if ($ErrorRecord -is [System.Management.Automation.ErrorRecord]) { $ErrorRecord.Exception } else { $ErrorRecord }
    if ($null -eq $ex) { return "$ErrorRecord" }
    $depth = 0
    while ($ex.InnerException -and $depth -lt 8) { $ex = $ex.InnerException; $depth++ }
    return ($ex.Message -replace '\s+', ' ').Trim()
}
#endregion

#region ---------------------------------------------------------------- Parsing de entrada
function ConvertTo-Target {
    <#
    .SYNOPSIS
        Interpreta uma linha de entrada e devolve Entrada, Host e Porta.
    #>
    [CmdletBinding()]
    param([string]$Line, [int]$DefaultPort = 443)

    $entry = "$Line".Trim()
    if (-not $entry -or $entry.StartsWith('#')) { return $null }

    $hostName = $entry
    $port     = $DefaultPort
    $origem   = 'padrao'

    if ($entry -match '^[a-zA-Z][a-zA-Z0-9+.-]*://') {
        try {
            $uri = [System.Uri]$entry
            $hostName = $uri.DnsSafeHost
            if ($uri.Port -gt 0) { $port = $uri.Port; $origem = 'url' }
        } catch {
            return [pscustomobject]@{
                Entrada = $entry; Host = $null; Porta = $port; OrigemPorta = $origem
                Erro = ('URL invalida: {0}' -f (Get-ErrorText $_))
            }
        }
    }
    elseif ($entry -match '^\[(.+)\]:(\d+)$') {          # [IPv6]:porta
        $hostName = $Matches[1]; $port = [int]$Matches[2]; $origem = 'entrada'
    }
    elseif ($entry -match '^\[(.+)\]$') {                # [IPv6] sem porta
        $hostName = $Matches[1]
    }
    elseif ($entry -match '^([^:]+):(\d+)$') {           # host:porta ou IPv4:porta
        $hostName = $Matches[1]; $port = [int]$Matches[2]; $origem = 'entrada'
    }

    if ($port -lt 1 -or $port -gt 65535) {
        return [pscustomobject]@{
            Entrada = $entry; Host = $hostName; Porta = $DefaultPort; OrigemPorta = 'padrao'
            Erro = ('porta fora da faixa 1-65535: {0}' -f $port)
        }
    }

    return [pscustomobject]@{
        Entrada = $entry; Host = $hostName; Porta = $port; OrigemPorta = $origem; Erro = $null
    }
}
#endregion

#region ---------------------------------------------------------------- DNS
function Resolve-TargetAddress {
    [CmdletBinding()]
    param([string]$HostName, [switch]$PreferIPv4)

    $info = [ordered]@{ IPs = @(); CNAME = @(); Status = 'OK'; Detalhe = ''; IPv6Ignorados = 0 }
    $parsed = $null

    if ([System.Net.IPAddress]::TryParse($HostName, [ref]$parsed)) {
        $info.IPs = @($parsed.IPAddressToString)
        $info.Detalhe = 'entrada ja e um endereco IP; DNS nao consultado'
        return [pscustomobject]$info
    }

    # Nome com caractere invalido para DNS (RFC 1123) falha de forma diferente de NXDOMAIN;
    # registrar isso separadamente evita que o operador procure o registro no servidor errado.
    if ($HostName -match '_') {
        $info.Detalhe = 'nome contem sublinhado, invalido em DNS pela RFC 1123; '
    }

    $erros = @()

    if (Get-Command Resolve-DnsName -ErrorAction SilentlyContinue) {
        try {
            $recs = Resolve-DnsName -Name $HostName -ErrorAction Stop
            $info.CNAME = @($recs | Where-Object { "$($_.Type)" -eq 'CNAME' } | ForEach-Object { $_.NameHost })
            $info.IPs   = @($recs | Where-Object { "$($_.Type)" -in @('A','AAAA') } | ForEach-Object { $_.IPAddress })
        } catch {
            $erros += ('Resolve-DnsName: {0}' -f (Get-ErrorText $_))
        }
    } else {
        $erros += 'Resolve-DnsName indisponivel nesta sessao'
    }

    if (-not $info.IPs) {
        try {
            $info.IPs = @([System.Net.Dns]::GetHostAddresses($HostName) | ForEach-Object { $_.IPAddressToString })
        } catch {
            $erros += ('GetHostAddresses: {0}' -f (Get-ErrorText $_))
        }
    }

    $info.IPs = @($info.IPs | Select-Object -Unique)

    if ($PreferIPv4) {
        $antes = $info.IPs.Count
        $info.IPs = @($info.IPs | Where-Object { ([System.Net.IPAddress]$_).AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork })
        $info.IPv6Ignorados = $antes - $info.IPs.Count
    }

    if (-not $info.IPs) {
        $info.Status  = 'FALHA'
        $info.Detalhe += if ($erros) { $erros -join ' | ' } else { 'nenhum registro A/AAAA retornado' }
    } else {
        $det = @()
        if ($info.Detalhe) { $det += $info.Detalhe.TrimEnd('; ') }
        $det += ('{0} endereco(s) resolvido(s)' -f $info.IPs.Count)
        if ($info.IPv6Ignorados -gt 0) { $det += ('{0} endereco(s) IPv6 ignorado(s) por -PreferIPv4' -f $info.IPv6Ignorados) }
        $info.Detalhe = $det -join '; '
    }

    return [pscustomobject]$info
}
#endregion

#region ---------------------------------------------------------------- Certificado: leitura de campos
function Get-SubjectAlternativeName {
    <#
    .SYNOPSIS
        Extrai as SANs da extensao 2.5.29.17 por parsing ASN.1, independente do idioma do SO.
    .DESCRIPTION
        X509Extension.Format() devolve texto localizado ("DNS Name=" em en-US, "Nome DNS=" em
        pt-BR) e o formato muda entre plataformas, entao nao serve para parsing.
    #>
    [CmdletBinding()]
    param([byte[]]$RawData)

    $out = @()
    if ($null -eq $RawData -or $RawData.Length -lt 2) { return $out }
    if ($RawData[0] -ne 0x30) { return $out }   # precisa ser uma SEQUENCE

    $i = 1
    $len = [int]$RawData[$i]
    if ($len -band 0x80) {
        $n = $len -band 0x7F
        $i++
        if ($n -lt 1 -or $n -gt 4 -or ($i + $n) -gt $RawData.Length) { return $out }
        $len = 0
        for ($k = 0; $k -lt $n; $k++) { $len = ($len -shl 8) -bor [int]$RawData[$i]; $i++ }
    } else { $i++ }

    $end = [Math]::Min($i + $len, $RawData.Length)

    while ($i -lt $end) {
        $tag = [int]$RawData[$i]; $i++
        if ($i -ge $RawData.Length) { break }
        $ll = [int]$RawData[$i]
        if ($ll -band 0x80) {
            $n = $ll -band 0x7F
            $i++
            if ($n -lt 1 -or $n -gt 4 -or ($i + $n) -gt $RawData.Length) { break }
            $ll = 0
            for ($k = 0; $k -lt $n; $k++) { $ll = ($ll -shl 8) -bor [int]$RawData[$i]; $i++ }
        } else { $i++ }

        if ($ll -lt 0 -or ($i + $ll) -gt $RawData.Length) { break }
        $val = if ($ll -gt 0) { [byte[]]$RawData[$i..($i + $ll - 1)] } else { [byte[]]@() }

        switch ($tag) {
            0x81 { $out += 'email:' + [System.Text.Encoding]::ASCII.GetString($val) }
            0x82 { $out += 'DNS:'   + [System.Text.Encoding]::ASCII.GetString($val) }
            0x86 { $out += 'URI:'   + [System.Text.Encoding]::ASCII.GetString($val) }
            0x87 {
                if ($val.Length -eq 4 -or $val.Length -eq 16) {
                    $out += 'IP:' + (New-Object System.Net.IPAddress(,$val)).IPAddressToString
                } else {
                    $out += 'IP:(tamanho invalido)'
                }
            }
            0xA0 { $out += 'otherName:(ASN.1)' }
            0x84 { $out += 'dirName:(ASN.1)' }
            default { $out += ('tag0x{0:X2}:(nao interpretado)' -f $tag) }
        }
        $i += $ll
    }
    # A virgula impede que o PowerShell desenrole a lista: sem ela, uma SAN unica volta como
    # string e o chamador que fizer [0] recebe o primeiro caractere.
    return ,$out
}

function Get-CertificateFacts {
    <#
    .SYNOPSIS
        Extrai algoritmo/tamanho de chave, algoritmo de assinatura, serie e SANs.
    #>
    [CmdletBinding()]
    param([System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate)

    $f = [ordered]@{
        Subject = ''; CN = ''; Emissor = ''; SANs = ''; ValidoDe = $null; ValidoAte = $null
        Thumbprint = ''; NumeroSerie = ''; AlgoritmoAssinatura = ''
        AlgoritmoChave = ''; TamanhoChave = $null
    }
    if ($null -eq $Certificate) { return [pscustomobject]$f }

    $f.Subject    = $Certificate.Subject
    $f.Emissor    = $Certificate.Issuer
    $f.ValidoDe   = $Certificate.NotBefore
    $f.ValidoAte  = $Certificate.NotAfter
    $f.Thumbprint = $Certificate.Thumbprint
    $f.NumeroSerie = $Certificate.SerialNumber

    try { $f.CN = $Certificate.GetNameInfo([System.Security.Cryptography.X509Certificates.X509NameType]::SimpleName, $false) }
    catch { $f.CN = if ($Certificate.Subject -match 'CN=([^,]+)') { $Matches[1] } else { '' } }

    try { $f.AlgoritmoAssinatura = $Certificate.SignatureAlgorithm.FriendlyName }
    catch { $f.AlgoritmoAssinatura = 'nao legivel: ' + (Get-ErrorText $_) }
    if (-not $f.AlgoritmoAssinatura) {
        try { $f.AlgoritmoAssinatura = $Certificate.SignatureAlgorithm.Value } catch { }
    }

    # PublicKey.Key e obsoleto e no .NET Core lanca "KeySize is a write-only property";
    # as extensoes tipadas funcionam no .NET Framework 4.7.2+ e no .NET Core.
    try {
        $f.AlgoritmoChave = $Certificate.PublicKey.Oid.FriendlyName
        if (-not $f.AlgoritmoChave) { $f.AlgoritmoChave = $Certificate.PublicKey.Oid.Value }
    } catch {
        $f.AlgoritmoChave = 'nao legivel: ' + (Get-ErrorText $_)
    }

    $chave = $null
    foreach ($obter in @(
        { [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPublicKey($Certificate) },
        { [System.Security.Cryptography.X509Certificates.ECDsaCertificateExtensions]::GetECDsaPublicKey($Certificate) },
        { $Certificate.PublicKey.Key }
    )) {
        if ($chave) { break }
        try { $chave = & $obter } catch { }
    }

    $tamanho = $null
    if ($chave) {
        # get_KeySize() antes da propriedade: em RSAOpenSsl (PowerShell 7) o adaptador do
        # PowerShell enxerga KeySize como somente-escrita e a leitura direta lanca excecao.
        try { $tamanho = $chave.get_KeySize() } catch { }
        if ($null -eq $tamanho) { try { $tamanho = $chave.KeySize } catch { } }
        if ($null -eq $tamanho) {
            try { $tamanho = $chave.ExportParameters($false).Modulus.Length * 8 } catch { }
        }
        try { $chave.Dispose() } catch { }
    }
    if ($null -ne $tamanho) {
        $f.TamanhoChave = $tamanho
    } else {
        $f.TamanhoChave = 'nao legivel: nenhuma API de chave publica respondeu para este algoritmo'
    }

    try {
        $ext = $Certificate.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.17' } | Select-Object -First 1
        if ($ext) {
            $sans = Get-SubjectAlternativeName -RawData $ext.RawData
            $f.SANs = if ($sans.Count -gt 0) { $sans -join ', ' } else { 'extensao SAN presente mas vazia' }
        } else {
            $f.SANs = 'certificado sem extensao SAN'
        }
    } catch {
        $f.SANs = 'falha ao ler SAN: ' + (Get-ErrorText $_)
    }

    return [pscustomobject]$f
}

function Test-CertificateChain {
    <#
    .SYNOPSIS
        Avalia a cadeia enviada pelo servidor e se ela e confiavel nesta maquina.
    #>
    [CmdletBinding()]
    param(
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Leaf,
        [System.Security.Cryptography.X509Certificates.X509Certificate2[]]$Sent
    )

    $r = [ordered]@{ CadeiaEnviada = ''; CadeiaCompleta = ''; CadeiaConfiavel = ''; }
    if ($null -eq $Leaf) {
        $r.CadeiaEnviada = 'sem certificado'; $r.CadeiaCompleta = 'sem certificado'; $r.CadeiaConfiavel = 'sem certificado'
        return [pscustomobject]$r
    }

    $n = if ($Sent) { $Sent.Count } else { 0 }
    if ($n -gt 0) {
        $r.CadeiaEnviada = (($Sent | ForEach-Object { $_.Subject -replace '^CN=([^,]+).*', '$1' }) -join ' > ')
    } else {
        $r.CadeiaEnviada = 'servidor nao enviou cadeia (ou metodo de leitura nao a expoe)'
    }

    $autoAssinado = ($Leaf.Subject -eq $Leaf.Issuer)
    if ($autoAssinado) {
        $r.CadeiaCompleta = 'certificado autoassinado; nao requer intermediarios'
    } elseif ($n -le 1) {
        $r.CadeiaCompleta = 'INCOMPLETA: servidor enviou apenas o certificado folha, sem intermediarios (erro comum de nginx/Apache)'
    } else {
        $r.CadeiaCompleta = ('servidor enviou {0} certificado(s), incluindo intermediario(s)' -f $n)
    }

    try {
        $chain = New-Object System.Security.Cryptography.X509Certificates.X509Chain
        $chain.ChainPolicy.RevocationMode = [System.Security.Cryptography.X509Certificates.X509RevocationMode]::NoCheck
        $chain.ChainPolicy.VerificationFlags = [System.Security.Cryptography.X509Certificates.X509VerificationFlags]::NoFlag
        if ($n -gt 1) { foreach ($c in $Sent) { [void]$chain.ChainPolicy.ExtraStore.Add($c) } }
        $ok = $chain.Build($Leaf)
        if ($ok) {
            $r.CadeiaConfiavel = 'sim'
        } else {
            $motivos = @($chain.ChainStatus | ForEach-Object { $_.Status.ToString() } | Select-Object -Unique)
            $r.CadeiaConfiavel = 'nao: ' + ($motivos -join ', ')
        }
        $chain.Dispose()
    } catch {
        $r.CadeiaConfiavel = 'nao avaliada: ' + (Get-ErrorText $_)
    }

    return [pscustomobject]$r
}
#endregion

#region ---------------------------------------------------------------- TCP e STARTTLS
function Connect-TcpWithTimeout {
    <#
    .SYNOPSIS
        Conecta com timeout e devolve o TcpClient ou uma descricao precisa da falha.
    #>
    [CmdletBinding()]
    param([string]$IpAddress, [int]$Port, [int]$TimeoutMs)

    $family = ([System.Net.IPAddress]$IpAddress).AddressFamily
    $client = New-Object System.Net.Sockets.TcpClient($family)
    try {
        $iar = $client.BeginConnect($IpAddress, $Port, $null, $null)
        if (-not $iar.AsyncWaitHandle.WaitOne($TimeoutMs)) {
            $client.Close()
            return [pscustomobject]@{ Client = $null; Erro = ('timeout TCP apos {0} ms (porta filtrada ou host inacessivel)' -f $TimeoutMs) }
        }
        $client.EndConnect($iar)
        $client.ReceiveTimeout = $TimeoutMs
        $client.SendTimeout    = $TimeoutMs
        return [pscustomobject]@{ Client = $client; Erro = $null }
    } catch {
        try { $client.Close() } catch { }
        $msg = Get-ErrorText $_
        $hint = switch -Regex ($msg) {
            'refused|recusou'      { ' (porta fechada: nenhum servico escutando)' }
            'unreachable|inacess'  { ' (sem rota ate o destino a partir desta estacao)' }
            default                { '' }
        }
        return [pscustomobject]@{ Client = $null; Erro = ('falha TCP: {0}{1}' -f $msg, $hint) }
    }
}

function Invoke-StartTls {
    <#
    .SYNOPSIS
        Executa a negociacao STARTTLS de SMTP ou LDAP sobre um stream ja conectado.
    #>
    [CmdletBinding()]
    param([System.IO.Stream]$Stream, [ValidateSet('Smtp','Ldap')][string]$Protocol, [int]$TimeoutMs = 5000)

    try {
        $Stream.ReadTimeout = $TimeoutMs; $Stream.WriteTimeout = $TimeoutMs

        if ($Protocol -eq 'Smtp') {
            $buf = New-Object byte[] 2048
            $n = $Stream.Read($buf, 0, $buf.Length)
            $greet = [System.Text.Encoding]::ASCII.GetString($buf, 0, [Math]::Max($n,0))
            if ($greet -notmatch '^220') { return [pscustomobject]@{ Sucesso = $false; Detalhe = ('saudacao SMTP inesperada: ' + ($greet -replace '\s+',' ').Trim()); Banner = $greet } }

            $ehlo = [System.Text.Encoding]::ASCII.GetBytes("EHLO certinventory.local`r`n")
            $Stream.Write($ehlo, 0, $ehlo.Length); $Stream.Flush()
            $n = $Stream.Read($buf, 0, $buf.Length)
            $resp = [System.Text.Encoding]::ASCII.GetString($buf, 0, [Math]::Max($n,0))
            if ($resp -notmatch 'STARTTLS') { return [pscustomobject]@{ Sucesso = $false; Detalhe = 'servidor SMTP nao anuncia STARTTLS'; Banner = $greet } }

            $cmd = [System.Text.Encoding]::ASCII.GetBytes("STARTTLS`r`n")
            $Stream.Write($cmd, 0, $cmd.Length); $Stream.Flush()
            $n = $Stream.Read($buf, 0, $buf.Length)
            $resp = [System.Text.Encoding]::ASCII.GetString($buf, 0, [Math]::Max($n,0))
            if ($resp -notmatch '^220') { return [pscustomobject]@{ Sucesso = $false; Detalhe = ('STARTTLS recusado: ' + ($resp -replace '\s+',' ').Trim()); Banner = $greet } }
            return [pscustomobject]@{ Sucesso = $true; Detalhe = 'STARTTLS SMTP aceito'; Banner = $greet }
        }

        # LDAP: extendedReq com OID 1.3.6.1.4.1.1466.20037
        $oid = [System.Text.Encoding]::ASCII.GetBytes('1.3.6.1.4.1.1466.20037')
        $req = New-Object System.Collections.Generic.List[byte]
        $req.AddRange([byte[]]@(0x30, [byte](0x0C + $oid.Length)))          # SEQUENCE
        $req.AddRange([byte[]]@(0x02, 0x01, 0x01))                           # messageID 1
        $req.AddRange([byte[]]@(0x77, [byte](0x02 + $oid.Length)))           # [APPLICATION 23]
        $req.AddRange([byte[]]@(0x80, [byte]$oid.Length))                    # [0] requestName
        $req.AddRange($oid)
        $bytes = $req.ToArray()
        $Stream.Write($bytes, 0, $bytes.Length); $Stream.Flush()

        $buf = New-Object byte[] 1024
        $n = $Stream.Read($buf, 0, $buf.Length)
        if ($n -le 0) { return [pscustomobject]@{ Sucesso = $false; Detalhe = 'servidor LDAP nao respondeu ao pedido de STARTTLS'; Banner = '' } }
        # resultCode 0 (success) aparece como 0x0A 0x01 0x00 na resposta
        $ok = $false
        for ($k = 0; $k -lt ($n - 2); $k++) {
            if ($buf[$k] -eq 0x0A -and $buf[$k+1] -eq 0x01) { $ok = ($buf[$k+2] -eq 0x00); break }
        }
        if (-not $ok) { return [pscustomobject]@{ Sucesso = $false; Detalhe = 'servidor LDAP recusou STARTTLS'; Banner = '' } }
        return [pscustomobject]@{ Sucesso = $true; Detalhe = 'STARTTLS LDAP aceito'; Banner = '' }
    } catch {
        return [pscustomobject]@{ Sucesso = $false; Detalhe = ('falha no STARTTLS: ' + (Get-ErrorText $_)); Banner = '' }
    }
}

function Get-StartTlsProtocol {
    [CmdletBinding()]
    param([int]$Port, [string]$Mode = 'Auto')
    switch ($Mode) {
        'None' { return $null }
        'Smtp' { return 'Smtp' }
        'Ldap' { return 'Ldap' }
        default {
            if ($Port -eq 25 -or $Port -eq 587) { return 'Smtp' }
            if ($Port -eq 389) { return 'Ldap' }
            return $null
        }
    }
}
#endregion

#region ---------------------------------------------------------------- TLS bruto (M3)
function Get-TlsAlertDescription {
    [CmdletBinding()]
    param([int]$Code)
    $map = @{
        0='close_notify'; 10='unexpected_message'; 20='bad_record_mac'; 40='handshake_failure'
        41='no_certificate'; 42='bad_certificate'; 43='unsupported_certificate'; 44='certificate_revoked'
        45='certificate_expired'; 46='certificate_unknown'; 47='illegal_parameter'; 48='unknown_ca'
        49='access_denied'; 50='decode_error'; 51='decrypt_error'; 70='protocol_version'
        71='insufficient_security'; 80='internal_error'; 86='inappropriate_fallback'
        90='user_canceled'; 109='missing_extension'; 112='unrecognized_name'
        113='bad_certificate_status_response'; 116='certificate_required'; 120='no_application_protocol'
    }
    $nome = if ($map.ContainsKey($Code)) { $map[$Code] } else { "desc_$Code" }
    $explica = switch ($Code) {
        40  { 'sem cipher suite em comum, ou o servidor rejeitou os parametros oferecidos' }
        48  { 'o servidor nao confia na CA do certificado de cliente' }
        70  { 'o servidor nao aceita a versao de TLS oferecida (tipicamente exige TLS 1.3)' }
        112 { 'o servidor nao reconhece o nome enviado no SNI (virtual host desconhecido)' }
        116 { 'o servidor exige certificado de cliente (mTLS)' }
        default { '' }
    }
    if ($explica) { return ('alerta TLS {0} ({1}): {2}' -f $Code, $nome, $explica) }
    return ('alerta TLS {0} ({1})' -f $Code, $nome)
}

function Get-CipherSuiteName {
    [CmdletBinding()]
    param([int]$Code)
    $map = @{
        0x002F='TLS_RSA_WITH_AES_128_CBC_SHA';          0x0035='TLS_RSA_WITH_AES_256_CBC_SHA'
        0x003C='TLS_RSA_WITH_AES_128_CBC_SHA256';       0x003D='TLS_RSA_WITH_AES_256_CBC_SHA256'
        0x009C='TLS_RSA_WITH_AES_128_GCM_SHA256';       0x009D='TLS_RSA_WITH_AES_256_GCM_SHA384'
        0xC009='TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA';  0xC00A='TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA'
        0xC013='TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA';    0xC014='TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA'
        0xC023='TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256'; 0xC024='TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384'
        0xC027='TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256'; 0xC028='TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384'
        0xC02B='TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256'; 0xC02C='TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384'
        0xC02F='TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256'; 0xC030='TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384'
        0xCCA8='TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305';  0xCCA9='TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305'
    }
    if ($map.ContainsKey($Code)) { return $map[$Code] }
    return ('0x{0:X4}' -f $Code)
}

function New-TlsClientHello {
    <#
    .SYNOPSIS
        Monta um ClientHello TLS 1.2 com lista ampla de cipher suites.
    .DESCRIPTION
        A lista cobre RSA e ECDHE, com AES-GCM, AES-CBC e CHACHA20, de modo a obter resposta
        de servidores cujo conjunto de ciphers nao coincide com o do Schannel da estacao.
    #>
    [CmdletBinding()]
    param([string]$ServerName)

    $body = New-Object System.Collections.Generic.List[byte]
    $body.AddRange([byte[]]@(0x03, 0x03))                        # client_version = TLS 1.2
    $rnd = New-Object byte[] 32
    ([System.Security.Cryptography.RandomNumberGenerator]::Create()).GetBytes($rnd)
    $body.AddRange($rnd)
    $body.Add(0x00)                                              # session_id vazio

    $suites = @(
        0xC02C,0xC02B,0xC030,0xC02F,0xCCA9,0xCCA8,
        0xC024,0xC023,0xC028,0xC027,0xC00A,0xC009,0xC014,0xC013,
        0x009D,0x009C,0x003D,0x003C,0x0035,0x002F,0x000A,0x00FF
    )
    $csBytes = New-Object System.Collections.Generic.List[byte]
    foreach ($s in $suites) { $csBytes.AddRange((ConvertTo-BigEndianBytes -Value $s -Size 2)) }
    $body.AddRange((ConvertTo-BigEndianBytes -Value $csBytes.Count -Size 2))
    $body.AddRange($csBytes.ToArray())
    $body.AddRange([byte[]]@(0x01, 0x00))                        # compression: null

    $ext = New-Object System.Collections.Generic.List[byte]

    # server_name (0x0000) - omitido quando -ServerName vier vazio ou for um IP literal
    $ipTmp = $null
    $sniValido = $ServerName -and -not [System.Net.IPAddress]::TryParse($ServerName, [ref]$ipTmp)
    if ($sniValido) {
        $h = [System.Text.Encoding]::ASCII.GetBytes($ServerName)
        $sni = New-Object System.Collections.Generic.List[byte]
        $sni.AddRange((ConvertTo-BigEndianBytes -Value ($h.Length + 3) -Size 2))   # server_name_list
        $sni.Add(0x00)                                                             # host_name
        $sni.AddRange((ConvertTo-BigEndianBytes -Value $h.Length -Size 2))
        $sni.AddRange($h)
        $ext.AddRange([byte[]]@(0x00, 0x00))
        $ext.AddRange((ConvertTo-BigEndianBytes -Value $sni.Count -Size 2))
        $ext.AddRange($sni.ToArray())
    }

    # supported_groups (0x000A)
    $grp = @(0x001D,0x0017,0x0018,0x0019,0x001E)
    $gb = New-Object System.Collections.Generic.List[byte]
    foreach ($g in $grp) { $gb.AddRange((ConvertTo-BigEndianBytes -Value $g -Size 2)) }
    $ext.AddRange([byte[]]@(0x00, 0x0A))
    $ext.AddRange((ConvertTo-BigEndianBytes -Value ($gb.Count + 2) -Size 2))
    $ext.AddRange((ConvertTo-BigEndianBytes -Value $gb.Count -Size 2))
    $ext.AddRange($gb.ToArray())

    # ec_point_formats (0x000B)
    $ext.AddRange([byte[]]@(0x00, 0x0B, 0x00, 0x02, 0x01, 0x00))

    # signature_algorithms (0x000D)
    $sa = @(0x0401,0x0501,0x0601,0x0403,0x0503,0x0603,0x0201,0x0203,0x0804,0x0805,0x0806)
    $sb = New-Object System.Collections.Generic.List[byte]
    foreach ($a in $sa) { $sb.AddRange((ConvertTo-BigEndianBytes -Value $a -Size 2)) }
    $ext.AddRange([byte[]]@(0x00, 0x0D))
    $ext.AddRange((ConvertTo-BigEndianBytes -Value ($sb.Count + 2) -Size 2))
    $ext.AddRange((ConvertTo-BigEndianBytes -Value $sb.Count -Size 2))
    $ext.AddRange($sb.ToArray())

    # renegotiation_info (0xFF01) vazio
    $ext.AddRange([byte[]]@(0xFF, 0x01, 0x00, 0x01, 0x00))

    $body.AddRange((ConvertTo-BigEndianBytes -Value $ext.Count -Size 2))
    $body.AddRange($ext.ToArray())

    $hs = New-Object System.Collections.Generic.List[byte]
    $hs.Add(0x01)                                                # ClientHello
    $hs.AddRange((ConvertTo-BigEndianBytes -Value $body.Count -Size 3))
    $hs.AddRange($body.ToArray())

    $rec = New-Object System.Collections.Generic.List[byte]
    $rec.AddRange([byte[]]@(0x16, 0x03, 0x01))                   # handshake, version TLS 1.0 no record
    $rec.AddRange((ConvertTo-BigEndianBytes -Value $hs.Count -Size 2))
    $rec.AddRange($hs.ToArray())

    return ,$rec.ToArray()
}

function Read-TlsServerResponse {
    <#
    .SYNOPSIS
        Interpreta a resposta do servidor: ServerHello, Certificate, CertificateRequest e alertas.
    #>
    [CmdletBinding()]
    param([byte[]]$Data)

    $r = [ordered]@{
        Certificados = @(); CipherSuite = ''; Versao = ''; ExigeCertCliente = $false
        Alerta = ''; Detalhe = ''
    }
    if ($null -eq $Data -or $Data.Length -lt 5) {
        $r.Detalhe = 'servidor nao respondeu ou respondeu menos que um registro TLS'
        return [pscustomobject]$r
    }

    # 1) Remonta o fluxo de handshake a partir dos registros TLS, tratando alertas
    $hs = New-Object System.Collections.Generic.List[byte]
    $i = 0
    while (($i + 5) -le $Data.Length) {
        $type = [int]$Data[$i]
        try { $len = ConvertFrom-BigEndianUInt16 -Bytes $Data -Offset ($i + 3) } catch { break }
        if ($len -le 0 -or ($i + 5 + $len) -gt $Data.Length) { break }
        if ($type -eq 0x16) {
            $hs.AddRange([byte[]]($Data[($i + 5)..($i + 4 + $len)]))
        } elseif ($type -eq 0x15 -and $len -ge 2) {
            $r.Alerta = Get-TlsAlertDescription -Code ([int]$Data[$i + 6])
        }
        $i += 5 + $len
    }

    $h = $hs.ToArray()
    if ($h.Length -eq 0) {
        if (-not $r.Alerta) { $r.Detalhe = 'nenhum registro de handshake na resposta' }
        return [pscustomobject]$r
    }

    # 2) Percorre as mensagens de handshake
    $j = 0
    while (($j + 4) -le $h.Length) {
        $mt = [int]$h[$j]
        try { $ml = ConvertFrom-BigEndianUInt24 -Bytes $h -Offset ($j + 1) } catch { break }
        if ($ml -lt 0 -or ($j + 4 + $ml) -gt $h.Length) {
            if ($mt -eq 0x0B) { $r.Detalhe = 'mensagem Certificate truncada na leitura' }
            break
        }

        switch ($mt) {
            0x02 {   # ServerHello
                $p = $j + 4
                if (($p + 2) -le $h.Length) {
                    $ver = ConvertFrom-BigEndianUInt16 -Bytes $h -Offset $p
                    $r.Versao = switch ($ver) { 0x0301 {'Tls10'} 0x0302 {'Tls11'} 0x0303 {'Tls12'} 0x0304 {'Tls13'} default {('0x{0:X4}' -f $ver)} }
                }
                $sidOff = $j + 4 + 2 + 32
                if ($sidOff -lt $h.Length) {
                    $sidLen = [int]$h[$sidOff]
                    $csOff = $sidOff + 1 + $sidLen
                    if (($csOff + 2) -le $h.Length) {
                        $r.CipherSuite = Get-CipherSuiteName -Code (ConvertFrom-BigEndianUInt16 -Bytes $h -Offset $csOff)
                    }
                }
            }
            0x0B {   # Certificate
                $p = $j + 4
                if (($p + 3) -le $h.Length) {
                    $listLen = ConvertFrom-BigEndianUInt24 -Bytes $h -Offset $p
                    $p += 3
                    $end = [Math]::Min($p + $listLen, $h.Length)
                    $certs = @()
                    while (($p + 3) -le $end) {
                        $cl = ConvertFrom-BigEndianUInt24 -Bytes $h -Offset $p
                        $p += 3
                        if ($cl -le 0 -or ($p + $cl) -gt $h.Length) { break }
                        try {
                            $certs += New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 (,[byte[]]$h[$p..($p + $cl - 1)])
                        } catch {
                            $r.Detalhe = 'certificado presente mas nao pode ser decodificado: ' + (Get-ErrorText $_)
                        }
                        $p += $cl
                    }
                    $r.Certificados = $certs
                }
            }
            0x0D {   # CertificateRequest
                $r.ExigeCertCliente = $true
            }
        }
        $j += 4 + $ml
    }

    return [pscustomobject]$r
}

function Get-CertificateRaw {
    <#
    .SYNOPSIS
        M3: le o certificado por ClientHello TLS 1.2 em socket bruto, sem depender do Schannel.
    #>
    [CmdletBinding()]
    param(
        [string]$IpAddress, [int]$Port, [string]$ServerName,
        [int]$TcpTimeoutMs = 5000, [int]$TlsTimeoutMs = 7000,
        [string]$StartTls
    )

    $conn = Connect-TcpWithTimeout -IpAddress $IpAddress -Port $Port -TimeoutMs $TcpTimeoutMs
    if (-not $conn.Client) {
        return [pscustomobject]@{ Certificados = @(); CipherSuite = ''; Versao = ''; ExigeCertCliente = $false; Alerta = ''; Detalhe = $conn.Erro }
    }

    $client = $conn.Client
    try {
        $ns = $client.GetStream()
        $ns.ReadTimeout = $TlsTimeoutMs; $ns.WriteTimeout = $TlsTimeoutMs

        if ($StartTls) {
            $st = Invoke-StartTls -Stream $ns -Protocol $StartTls -TimeoutMs $TlsTimeoutMs
            if (-not $st.Sucesso) {
                return [pscustomobject]@{ Certificados = @(); CipherSuite = ''; Versao = ''; ExigeCertCliente = $false; Alerta = ''; Detalhe = $st.Detalhe }
            }
        }

        $hello = New-TlsClientHello -ServerName $ServerName
        $ns.Write($hello, 0, $hello.Length); $ns.Flush()

        $buf = New-Object System.Collections.Generic.List[byte]
        $tmp = New-Object byte[] 16384
        $deadline = (Get-Date).AddMilliseconds($TlsTimeoutMs)
        while ((Get-Date) -lt $deadline) {
            $n = 0
            try { $n = $ns.Read($tmp, 0, $tmp.Length) } catch { break }
            if ($n -le 0) { break }
            $buf.AddRange([byte[]]($tmp[0..($n - 1)]))
            if ($buf.Count -gt 262144) { break }
            $parcial = Read-TlsServerResponse -Data $buf.ToArray()
            if ($parcial.Certificados.Count -gt 0 -or $parcial.Alerta) { break }
        }

        $res = Read-TlsServerResponse -Data $buf.ToArray()
        if ($res.Certificados.Count -eq 0 -and -not $res.Detalhe -and -not $res.Alerta) {
            $res.Detalhe = ('servidor respondeu {0} byte(s) sem mensagem Certificate' -f $buf.Count)
        }
        return $res
    } catch {
        return [pscustomobject]@{ Certificados = @(); CipherSuite = ''; Versao = ''; ExigeCertCliente = $false; Alerta = ''; Detalhe = ('leitura bruta falhou: ' + (Get-ErrorText $_)) }
    } finally {
        try { $client.Close() } catch { }
    }
}
#endregion

#region ---------------------------------------------------------------- SslStream (M1/M2) e openssl (M4)
function Get-SupportedSslProtocols {
    <#
    .SYNOPSIS
        Monta o conjunto de protocolos por capacidade real do enum, nao pela edicao do PowerShell.
    #>
    [CmdletBinding()]
    param([switch]$IncludeTls13)

    $disponiveis = [Enum]::GetNames([System.Security.Authentication.SslProtocols])
    $desejados = @('Tls','Tls11','Tls12')
    if ($IncludeTls13) { $desejados += 'Tls13' }

    $prot = [System.Security.Authentication.SslProtocols]::None
    foreach ($n in $desejados) {
        if ($disponiveis -contains $n) {
            $prot = $prot -bor [System.Security.Authentication.SslProtocols]$n
        }
    }
    return $prot
}

function Get-CertificateViaSslStream {
    <#
    .SYNOPSIS
        M1/M2: handshake com SslStream, capturando certificado e cadeia DENTRO do callback.
    .DESCRIPTION
        O callback guarda certificado e cadeia antes de qualquer decisao de validacao, de modo
        que continuem disponiveis se o handshake falhar em seguida. O motivo da falha vai para
        Detalhe, separado do certificado.
    #>
    [CmdletBinding()]
    param(
        [string]$IpAddress, [int]$Port, [string]$ServerName,
        [int]$TcpTimeoutMs = 5000, [int]$TlsTimeoutMs = 7000,
        [string]$StartTls, [switch]$NoTls13
    )

    $res = [ordered]@{
        Certificado = $null; Cadeia = @(); CipherSuite = ''; Versao = ''
        ErrosValidacao = ''; CallbackDisparou = $false; Sucesso = $false; Detalhe = ''
    }

    $conn = Connect-TcpWithTimeout -IpAddress $IpAddress -Port $Port -TimeoutMs $TcpTimeoutMs
    if (-not $conn.Client) { $res.Detalhe = $conn.Erro; return [pscustomobject]$res }

    $client = $conn.Client
    $ssl = $null
    try {
        $ns = $client.GetStream()
        if ($StartTls) {
            $st = Invoke-StartTls -Stream $ns -Protocol $StartTls -TimeoutMs $TlsTimeoutMs
            if (-not $st.Sucesso) { $res.Detalhe = $st.Detalhe; return [pscustomobject]$res }
        }

        # Hashtable capturada por closure: o delegate escreve aqui antes de validar qualquer coisa
        $captura = @{ Cert = $null; Cadeia = @(); Erros = $null; Disparou = $false }
        $cb = [System.Net.Security.RemoteCertificateValidationCallback]({
            param($remetente, $certificado, $cadeia, $errosPolitica)
            $captura.Disparou = $true
            # Copiar por RawData: o X509Chain e seus elementos sao liberados quando o callback
            # retorna, e as referencias guardadas passam a expor Subject vazio.
            if ($certificado) {
                try { $captura.Cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 (,[byte[]]$certificado.GetRawCertData()) }
                catch { try { $captura.Cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($certificado) } catch { $captura.Cert = $certificado } }
            }
            if ($cadeia -and $cadeia.ChainElements) {
                try {
                    $captura.Cadeia = @($cadeia.ChainElements | ForEach-Object {
                        New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 (,[byte[]]$_.Certificate.RawData)
                    })
                } catch { }
            }
            $captura.Erros = $errosPolitica
            return $true
        }).GetNewClosure()

        $ssl = New-Object System.Net.Security.SslStream($ns, $false, $cb)
        $ssl.ReadTimeout = $TlsTimeoutMs; $ssl.WriteTimeout = $TlsTimeoutMs

        $prot = Get-SupportedSslProtocols -IncludeTls13:(-not $NoTls13)
        try {
            $ssl.AuthenticateAsClient($ServerName, $null, $prot, $false)
            $res.Sucesso = $true
            $res.Versao = "$($ssl.SslProtocol)"
            try { $res.CipherSuite = "$($ssl.NegotiatedCipherSuite)" } catch { $res.CipherSuite = '' }
            if (-not $res.CipherSuite) {
                # Windows PowerShell 5.1 nao expoe NegotiatedCipherSuite
                try {
                    $res.CipherSuite = 'Cipher={0}/{1} bits, Troca={2}, Hash={3}' -f `
                        $ssl.CipherAlgorithm, $ssl.CipherStrength, $ssl.KeyExchangeAlgorithm, $ssl.HashAlgorithm
                } catch { $res.CipherSuite = 'nao exposto por esta versao do PowerShell' }
            }
        } catch {
            $res.Detalhe = 'handshake falhou: ' + (Get-ErrorText $_)
        }

        $res.CallbackDisparou = [bool]$captura.Disparou
        if ($captura.Cert)   { $res.Certificado = $captura.Cert }
        if ($captura.Cadeia) { $res.Cadeia = @($captura.Cadeia) }

        if ($null -ne $captura.Erros) {
            $res.ErrosValidacao = "$($captura.Erros)"
        } elseif (-not $captura.Disparou) {
            $res.ErrosValidacao = 'nao avaliado: o callback de validacao nao chegou a ser chamado'
        }

        if (-not $res.Certificado -and -not $res.Detalhe) {
            $res.Detalhe = 'handshake concluiu sem expor certificado do servidor'
        }
        return [pscustomobject]$res
    } catch {
        $res.Detalhe = 'erro em SslStream: ' + (Get-ErrorText $_)
        return [pscustomobject]$res
    } finally {
        if ($ssl) { try { $ssl.Dispose() } catch { } }
        try { $client.Close() } catch { }
    }
}

function Find-OpenSsl {
    [CmdletBinding()]
    param([string]$OpenSslPath)

    if ($OpenSslPath) {
        if (Test-Path -LiteralPath $OpenSslPath) { return $OpenSslPath }
        return $null
    }
    $cmd = Get-Command 'openssl.exe','openssl' -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($cmd) { return $cmd.Source }
    foreach ($p in @(
        "$env:ProgramFiles\Git\usr\bin\openssl.exe",
        "${env:ProgramFiles(x86)}\Git\usr\bin\openssl.exe",
        "$env:ProgramFiles\Git\mingw64\bin\openssl.exe",
        "$env:LOCALAPPDATA\Programs\Git\usr\bin\openssl.exe"
    )) {
        if ($p -and (Test-Path -LiteralPath $p)) { return $p }
    }
    return $null
}

function Get-CertificateViaOpenSsl {
    <#
    .SYNOPSIS
        M4: fallback por openssl s_client -showcerts. Unico caminho para servidores so TLS 1.3
        quando o Schannel da maquina nao suporta TLS 1.3.
    #>
    [CmdletBinding()]
    param(
        [string]$OpenSslExe, [string]$IpAddress, [int]$Port, [string]$ServerName,
        [int]$TimeoutMs = 10000, [string]$StartTls
    )

    $res = [ordered]@{ Certificados = @(); Versao = ''; CipherSuite = ''; Sucesso = $false; Detalhe = '' }
    if (-not $OpenSslExe) { $res.Detalhe = 'openssl nao encontrado (opcional; informe -OpenSslPath para habilitar)'; return [pscustomobject]$res }

    $args = @('s_client', '-connect', ("{0}:{1}" -f $IpAddress, $Port), '-showcerts')
    $ipTmp = $null
    if ($ServerName -and -not [System.Net.IPAddress]::TryParse($ServerName, [ref]$ipTmp)) {
        $args += @('-servername', $ServerName)
    }
    if ($StartTls -eq 'Smtp') { $args += @('-starttls', 'smtp') }
    elseif ($StartTls -eq 'Ldap') { $args += @('-starttls', 'ldap') }

    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $OpenSslExe
    $psi.Arguments = ($args -join ' ')
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError  = $true
    $psi.RedirectStandardInput  = $true
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow  = $true

    $proc = $null
    try {
        $proc = [System.Diagnostics.Process]::Start($psi)
        $proc.StandardInput.Close()
        $saida = $proc.StandardOutput.ReadToEndAsync()
        $erro  = $proc.StandardError.ReadToEndAsync()
        if (-not $proc.WaitForExit($TimeoutMs)) {
            try { $proc.Kill() } catch { }
            $res.Detalhe = ('openssl excedeu {0} ms' -f $TimeoutMs)
            return [pscustomobject]$res
        }
        $texto = $saida.Result
        $textoErro = $erro.Result

        $certs = @()
        $rx = [regex]'-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----'
        foreach ($m in $rx.Matches($texto)) {
            try {
                $b64 = ($m.Groups[1].Value -replace '\s', '')
                $certs += New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 (,[Convert]::FromBase64String($b64))
            } catch {
                $res.Detalhe = 'certificado PEM ilegivel: ' + (Get-ErrorText $_)
            }
        }
        $res.Certificados = $certs

        if ($texto -match 'Protocol\s*:\s*(\S+)') { $res.Versao = $Matches[1] -replace 'v', '' -replace '\.', '' -replace '^TLS', 'Tls' }
        if ($texto -match 'Cipher\s*:\s*(\S+)')   { $res.CipherSuite = $Matches[1] }

        if ($certs.Count -gt 0) {
            $res.Sucesso = $true
        } elseif (-not $res.Detalhe) {
            $linhaErro = ($textoErro -split "`n" | Where-Object { $_ -match 'error|alert' } | Select-Object -First 1)
            $res.Detalhe = if ($linhaErro) { 'openssl: ' + ($linhaErro -replace '\s+',' ').Trim() } else { 'openssl nao retornou certificado' }
        }
        return [pscustomobject]$res
    } catch {
        $res.Detalhe = 'falha ao executar openssl: ' + (Get-ErrorText $_)
        return [pscustomobject]$res
    } finally {
        if ($proc) { try { $proc.Dispose() } catch { } }
    }
}
#endregion

#region ---------------------------------------------------------------- Orquestrador de leitura de certificado
function Get-CertificateFromTarget {
    <#
    .SYNOPSIS
        Executa M1 -> M2 -> M3 -> M4 e devolve o primeiro resultado com certificado.
    #>
    [CmdletBinding()]
    param(
        [string]$IpAddress, [int]$Port, [string]$ServerName, [string]$CnameTarget,
        [int]$TcpTimeoutMs = 5000, [int]$TlsTimeoutMs = 7000,
        [string]$StartTls, [string]$OpenSslExe, [switch]$CompareSni
    )

    $r = [ordered]@{
        Certificado = $null; Cadeia = @(); MetodoLeitura = ''; TlsVersao = ''; CipherSuite = ''
        ExigeCertCliente = 'nao determinado'; ErrosValidacao = ''; SniUsado = ''; SniDivergente = ''
        Status = 'FALHA'; Detalhe = ''; Tentativas = @()
    }

    $falhas = @()

    # ---------------- M1: SslStream com todos os protocolos disponiveis ----------------
    $m1 = Get-CertificateViaSslStream -IpAddress $IpAddress -Port $Port -ServerName $ServerName `
            -TcpTimeoutMs $TcpTimeoutMs -TlsTimeoutMs $TlsTimeoutMs -StartTls $StartTls

    # Se o Schannel desta maquina nao suporta TLS 1.3, o proprio enum aceita mas o handshake
    # falha; repetir sem TLS 1.3 separa "SO nao suporta" de "servidor recusou".
    if (-not $m1.Certificado -and $m1.Detalhe -match 'not supported|nao suportad|PlatformNotSupported|invalid|argument') {
        $falhas += ('M1(com TLS1.3): ' + $m1.Detalhe)
        $m1 = Get-CertificateViaSslStream -IpAddress $IpAddress -Port $Port -ServerName $ServerName `
                -TcpTimeoutMs $TcpTimeoutMs -TlsTimeoutMs $TlsTimeoutMs -StartTls $StartTls -NoTls13
    }

    if ($m1.Certificado) {
        $r.Certificado = $m1.Certificado
        $r.Cadeia = $m1.Cadeia
        $r.MetodoLeitura = if ($m1.Sucesso) { 'M1 SslStream' } else { 'M1 SslStream (certificado capturado no callback; handshake falhou depois)' }
        $r.TlsVersao = $m1.Versao
        $r.CipherSuite = $m1.CipherSuite
        $r.ErrosValidacao = $m1.ErrosValidacao
        $r.SniUsado = if ($ServerName) { $ServerName } else { '(sem SNI)' }
        $r.Status = if ($m1.Sucesso) { 'OK' } else { 'PARCIAL' }
        if (-not $m1.Sucesso) { $r.Detalhe = $m1.Detalhe }

        if ($CompareSni) {
            $div = @()
            foreach ($alt in @(@{N=$CnameTarget; R='SNI do alvo do CNAME'}, @{N=''; R='sem SNI'})) {
                if ($null -eq $alt.N -and $alt.R -ne 'sem SNI') { continue }
                if ($alt.N -eq $ServerName) { continue }
                if ($alt.R -eq 'SNI do alvo do CNAME' -and -not $CnameTarget) { continue }
                $t = Get-CertificateViaSslStream -IpAddress $IpAddress -Port $Port -ServerName $alt.N `
                        -TcpTimeoutMs $TcpTimeoutMs -TlsTimeoutMs $TlsTimeoutMs -StartTls $StartTls
                if ($t.Certificado -and $t.Certificado.Thumbprint -ne $m1.Certificado.Thumbprint) {
                    $div += ('{0} devolve certificado diferente ({1})' -f $alt.R, ($t.Certificado.Subject -split ',')[0])
                }
            }
            $r.SniDivergente = if ($div) { ($div -join '; ') + ' -- virtual host por SNI: confirme qual e o certificado monitorado' } else { 'nao: mesmo certificado com e sem SNI' }
        } else {
            $r.SniDivergente = 'nao verificado (use -CompareSni)'
        }
        return [pscustomobject]$r
    }
    $falhas += ('M1: ' + $m1.Detalhe)

    # ---------------- M2: variacao de SNI ----------------
    $variantes = @()
    if ($CnameTarget -and $CnameTarget -ne $ServerName) { $variantes += @{ N = $CnameTarget; R = 'SNI do alvo do CNAME' } }
    $variantes += @{ N = ''; R = 'sem SNI' }

    foreach ($v in $variantes) {
        $m2 = Get-CertificateViaSslStream -IpAddress $IpAddress -Port $Port -ServerName $v.N `
                -TcpTimeoutMs $TcpTimeoutMs -TlsTimeoutMs $TlsTimeoutMs -StartTls $StartTls
        if ($m2.Certificado) {
            $r.Certificado = $m2.Certificado
            $r.Cadeia = $m2.Cadeia
            $r.MetodoLeitura = 'M2 SslStream com ' + $v.R
            $r.TlsVersao = $m2.Versao
            $r.CipherSuite = $m2.CipherSuite
            $r.ErrosValidacao = $m2.ErrosValidacao
            $r.SniUsado = if ($v.N) { $v.N } else { '(sem SNI)' }
            $r.SniDivergente = ('o SNI original ({0}) falhou, mas {1} funcionou: virtual host por SNI ou nome nao publicado no servidor' -f $ServerName, $v.R)
            $r.Status = if ($m2.Sucesso) { 'OK' } else { 'PARCIAL' }
            if (-not $m2.Sucesso) { $r.Detalhe = $m2.Detalhe }
            return [pscustomobject]$r
        }
        $falhas += ('M2 ' + $v.R + ': ' + $m2.Detalhe)
    }

    # ---------------- M3: ClientHello TLS 1.2 em socket bruto ----------------
    $m3 = Get-CertificateRaw -IpAddress $IpAddress -Port $Port -ServerName $ServerName `
            -TcpTimeoutMs $TcpTimeoutMs -TlsTimeoutMs $TlsTimeoutMs -StartTls $StartTls
    if ($m3.ExigeCertCliente) { $r.ExigeCertCliente = 'sim (servidor enviou CertificateRequest)' }
    if ($m3.Alerta -match 'certificate_required') { $r.ExigeCertCliente = 'sim (alerta certificate_required)' }

    if ($m3.Certificados.Count -gt 0) {
        $r.Certificado = $m3.Certificados[0]
        $r.Cadeia = $m3.Certificados
        $r.MetodoLeitura = 'M3 ClientHello TLS1.2 bruto'
        $r.TlsVersao = $m3.Versao
        $r.CipherSuite = $m3.CipherSuite
        $r.SniUsado = if ($ServerName) { $ServerName } else { '(sem SNI)' }
        $r.ErrosValidacao = 'nao avaliado: leitura bruta nao executa validacao do Schannel'
        $r.SniDivergente = 'nao verificado (leitura bruta)'
        $r.Status = 'PARCIAL'
        $r.Detalhe = 'certificado obtido por leitura bruta porque o SslStream falhou: ' + ($falhas -join ' | ')
        return [pscustomobject]$r
    }
    $falhas += ('M3: ' + (@($m3.Alerta, $m3.Detalhe) | Where-Object { $_ }) -join ' ')

    # ---------------- M4: openssl s_client ----------------
    $m4 = Get-CertificateViaOpenSsl -OpenSslExe $OpenSslExe -IpAddress $IpAddress -Port $Port `
            -ServerName $ServerName -TimeoutMs ($TlsTimeoutMs + 3000) -StartTls $StartTls
    if ($m4.Certificados.Count -gt 0) {
        $r.Certificado = $m4.Certificados[0]
        $r.Cadeia = $m4.Certificados
        $r.MetodoLeitura = 'M4 openssl s_client'
        $r.TlsVersao = $m4.Versao
        $r.CipherSuite = $m4.CipherSuite
        $r.SniUsado = if ($ServerName) { $ServerName } else { '(sem SNI)' }
        $r.ErrosValidacao = 'nao avaliado: leitura por openssl'
        $r.SniDivergente = 'nao verificado (openssl)'
        $r.Status = 'PARCIAL'
        $r.Detalhe = 'certificado obtido por openssl porque os demais metodos falharam: ' + ($falhas -join ' | ')
        return [pscustomobject]$r
    }
    $falhas += ('M4: ' + $m4.Detalhe)

    $r.MetodoLeitura = 'nenhum metodo obteve o certificado'
    $r.SniUsado = if ($ServerName) { $ServerName } else { '(sem SNI)' }
    $r.SniDivergente = 'nao aplicavel'
    $r.Detalhe = $falhas -join ' | '
    $r.TlsVersao = 'sem handshake completo'
    $r.CipherSuite = 'sem handshake completo'
    if ($r.ErrosValidacao -eq '') { $r.ErrosValidacao = 'nao avaliado: nenhum certificado obtido' }
    return [pscustomobject]$r
}
#endregion

#region ---------------------------------------------------------------- Hostname: metodos sem credencial
function Read-NetBiosResponse {
    <#
    .SYNOPSIS
        Interpreta a lista de nomes de uma resposta NBSTAT. Funcao pura, sem I/O.
    .DESCRIPTION
        Cada entrada tem 18 bytes: 15 de nome, 1 de sufixo e 2 de flags. O nome da estacao e
        o de sufixo 0x00 que nao seja de grupo; o de sufixo 0x00 marcado como grupo e o dominio.
    #>
    [CmdletBinding()]
    param([byte[]]$Buffer)

    if ($null -eq $Buffer -or $Buffer.Length -lt 14) {
        return [pscustomobject]@{ Nome = $null; Dominio = $null; Detalhe = 'resposta NetBIOS menor que o cabecalho' }
    }

    # O nome na resposta vem completo (34 bytes) ou comprimido por ponteiro (2 bytes)
    $nameLen = if (([int]$Buffer[12] -band 0xC0) -eq 0xC0) { 2 } else { 34 }
    $countOffset = 12 + $nameLen + 10        # tipo(2) + classe(2) + TTL(4) + rdlength(2)
    if ($Buffer.Length -le $countOffset) {
        return [pscustomobject]@{ Nome = $null; Dominio = $null; Detalhe = 'resposta NetBIOS truncada antes da lista de nomes' }
    }

    $count = [int]$Buffer[$countOffset]
    $maquina = $null; $dominio = $null
    for ($n = 0; $n -lt $count; $n++) {
        $off = $countOffset + 1 + ($n * 18)
        if (($off + 18) -gt $Buffer.Length) { break }
        $nome   = [System.Text.Encoding]::ASCII.GetString($Buffer, $off, 15).Trim()
        $suffix = [int]$Buffer[$off + 15]
        $flags  = ConvertFrom-BigEndianUInt16 -Bytes $Buffer -Offset ($off + 16)
        $grupo  = [bool]($flags -band 0x8000)
        if ($suffix -eq 0x00 -and -not $grupo -and -not $maquina) { $maquina = $nome }
        if ($suffix -eq 0x00 -and $grupo -and -not $dominio) { $dominio = $nome }
    }
    if ($maquina) { return [pscustomobject]@{ Nome = $maquina; Dominio = $dominio; Detalhe = 'NetBIOS respondeu' } }
    return [pscustomobject]@{ Nome = $null; Dominio = $dominio; Detalhe = ('NetBIOS respondeu com {0} nome(s), nenhum de estacao' -f $count) }
}

function Get-NetBiosName {
    <#
    .SYNOPSIS
        Consulta NBSTAT (UDP 137). Responde Windows e Linux com Samba (nmbd).
    #>
    [CmdletBinding()]
    param([string]$IpAddress, [int]$TimeoutMs = 1500)

    $udp = $null
    try {
        $udp = New-Object System.Net.Sockets.UdpClient
        $udp.Client.ReceiveTimeout = $TimeoutMs
        $udp.Client.SendTimeout    = $TimeoutMs

        # Cabecalho + nome "*" codificado (CK + 'A' x30) + tipo NBSTAT (0x21) + classe IN
        $query = [byte[]](
            @(0x13,0x37,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x20,0x43,0x4B) +
            (@(0x41) * 30) +
            @(0x00,0x00,0x21,0x00,0x01)
        )
        [void]$udp.Send($query, $query.Length, $IpAddress, 137)
        $remote = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Any, 0)
        $resp = $udp.Receive([ref]$remote)

        return (Read-NetBiosResponse -Buffer $resp)
    } catch [System.Net.Sockets.SocketException] {
        return [pscustomobject]@{ Nome = $null; Dominio = $null; Detalhe = 'sem resposta NetBIOS (host nao e Windows nem roda Samba, ou UDP 137 bloqueado)' }
    } catch {
        return [pscustomobject]@{ Nome = $null; Dominio = $null; Detalhe = ('falha NetBIOS: ' + (Get-ErrorText $_)) }
    } finally {
        if ($udp) { try { $udp.Close() } catch { } }
    }
}

function Get-PtrRecord {
    [CmdletBinding()]
    param([string]$IpAddress)
    try {
        $nome = [System.Net.Dns]::GetHostEntry($IpAddress).HostName
        if ($nome -and $nome -ne $IpAddress) { return [pscustomobject]@{ Nome = $nome; Detalhe = 'PTR resolvido' } }
        return [pscustomobject]@{ Nome = $null; Detalhe = 'PTR devolveu o proprio IP' }
    } catch {
        return [pscustomobject]@{ Nome = $null; Detalhe = ('sem PTR: ' + (Get-ErrorText $_)) }
    }
}

function Read-SmtpBanner {
    <#
    .SYNOPSIS
        Extrai o hostname de uma saudacao SMTP 220. Funcao pura, sem I/O.
    #>
    [CmdletBinding()]
    param([string]$Banner)

    $b = ("$Banner" -replace '\s+', ' ').Trim()
    if (-not $b) { return [pscustomobject]@{ Nome = $null; Banner = ''; Detalhe = 'SMTP aceitou a conexao mas nao enviou saudacao' } }
    if ($b -match '^220[- ]+([A-Za-z0-9][A-Za-z0-9\-]*(\.[A-Za-z0-9\-]+)+)') {
        return [pscustomobject]@{ Nome = $Matches[1]; Banner = $b; Detalhe = 'nome extraido da saudacao SMTP' }
    }
    if ($b -match '^220[- ]+(\S+)') {
        return [pscustomobject]@{ Nome = $Matches[1]; Banner = $b; Detalhe = 'nome extraido da saudacao SMTP (nao qualificado)' }
    }
    return [pscustomobject]@{ Nome = $null; Banner = $b; Detalhe = 'saudacao SMTP sem nome reconhecivel' }
}

function Get-SmtpBannerName {
    <#
    .SYNOPSIS
        Le a saudacao 220 do SMTP. Postfix e Sendmail costumam anunciar o FQDN.
    #>
    [CmdletBinding()]
    param([string]$IpAddress, [int]$Port = 25, [int]$TimeoutMs = 1500)

    $conn = Connect-TcpWithTimeout -IpAddress $IpAddress -Port $Port -TimeoutMs $TimeoutMs
    if (-not $conn.Client) { return [pscustomobject]@{ Nome = $null; Banner = ''; Detalhe = ('SMTP {0}: {1}' -f $Port, $conn.Erro) } }
    try {
        $ns = $conn.Client.GetStream(); $ns.ReadTimeout = $TimeoutMs
        $buf = New-Object byte[] 1024
        $n = $ns.Read($buf, 0, $buf.Length)
        if ($n -le 0) { return [pscustomobject]@{ Nome = $null; Banner = ''; Detalhe = 'SMTP aceitou a conexao mas nao enviou saudacao' } }
        $banner = ([System.Text.Encoding]::ASCII.GetString($buf, 0, $n) -replace '\s+', ' ').Trim()
        return (Read-SmtpBanner -Banner $banner)
    } catch {
        return [pscustomobject]@{ Nome = $null; Banner = ''; Detalhe = ('falha no banner SMTP: ' + (Get-ErrorText $_)) }
    } finally { try { $conn.Client.Close() } catch { } }
}

function Get-SshBanner {
    <#
    .SYNOPSIS
        Le apenas o banner do SSH (TCP 22), para inferir o sistema operacional.
    #>
    [CmdletBinding()]
    param([string]$IpAddress, [int]$Port = 22, [int]$TimeoutMs = 1500)

    $conn = Connect-TcpWithTimeout -IpAddress $IpAddress -Port $Port -TimeoutMs $TimeoutMs
    if (-not $conn.Client) { return [pscustomobject]@{ Banner = ''; Detalhe = ('SSH 22: ' + $conn.Erro) } }
    try {
        $ns = $conn.Client.GetStream(); $ns.ReadTimeout = $TimeoutMs
        $buf = New-Object byte[] 512
        $n = $ns.Read($buf, 0, $buf.Length)
        if ($n -le 0) { return [pscustomobject]@{ Banner = ''; Detalhe = 'porta 22 aberta sem banner' } }
        $b = ([System.Text.Encoding]::ASCII.GetString($buf, 0, $n) -replace '\s+', ' ').Trim()
        return [pscustomobject]@{ Banner = $b; Detalhe = 'banner SSH lido' }
    } catch {
        return [pscustomobject]@{ Banner = ''; Detalhe = ('falha no banner SSH: ' + (Get-ErrorText $_)) }
    } finally { try { $conn.Client.Close() } catch { } }
}

function Get-LdapRootDseName {
    <#
    .SYNOPSIS
        searchRequest anonimo na rootDSE pedindo dnsHostName. Responde controlador de dominio.
    #>
    [CmdletBinding()]
    param([string]$IpAddress, [int]$Port = 389, [int]$TimeoutMs = 1500)

    $conn = Connect-TcpWithTimeout -IpAddress $IpAddress -Port $Port -TimeoutMs $TimeoutMs
    if (-not $conn.Client) { return [pscustomobject]@{ Nome = $null; Detalhe = ('LDAP {0}: {1}' -f $Port, $conn.Erro) } }
    try {
        $ns = $conn.Client.GetStream(); $ns.ReadTimeout = $TimeoutMs; $ns.WriteTimeout = $TimeoutMs

        # bind anonimo: messageID 1, bindRequest v3, nome vazio, simple vazio
        $bind = [byte[]]@(0x30,0x0C,0x02,0x01,0x01,0x60,0x07,0x02,0x01,0x03,0x04,0x00,0x80,0x00)
        $ns.Write($bind, 0, $bind.Length); $ns.Flush()
        $buf = New-Object byte[] 4096
        $n = $ns.Read($buf, 0, $buf.Length)
        if ($n -le 0) { return [pscustomobject]@{ Nome = $null; Detalhe = 'LDAP nao respondeu ao bind anonimo' } }

        # searchRequest: base "", scope base(0), filtro present(objectClass), atributo dnsHostName
        $attr = [System.Text.Encoding]::ASCII.GetBytes('dnsHostName')
        $filtro = [byte[]]@(0x87,0x0B) + [System.Text.Encoding]::ASCII.GetBytes('objectClass')
        $corpo = New-Object System.Collections.Generic.List[byte]
        $corpo.AddRange([byte[]]@(0x04,0x00))                       # baseObject ""
        $corpo.AddRange([byte[]]@(0x0A,0x01,0x00))                  # scope baseObject
        $corpo.AddRange([byte[]]@(0x0A,0x01,0x00))                  # derefAliases never
        $corpo.AddRange([byte[]]@(0x02,0x01,0x01))                  # sizeLimit 1
        $corpo.AddRange([byte[]]@(0x02,0x01,0x05))                  # timeLimit 5
        $corpo.AddRange([byte[]]@(0x01,0x01,0x00))                  # typesOnly false
        $corpo.AddRange($filtro)
        $corpo.AddRange([byte[]]@(0x30,[byte]($attr.Length + 2),0x04,[byte]$attr.Length))
        $corpo.AddRange($attr)
        $req = New-Object System.Collections.Generic.List[byte]
        $req.AddRange([byte[]]@(0x30,[byte]($corpo.Count + 7),0x02,0x01,0x02,0x63,[byte]$corpo.Count))
        $req.AddRange($corpo.ToArray())
        $bytes = $req.ToArray()
        $ns.Write($bytes, 0, $bytes.Length); $ns.Flush()

        $n = $ns.Read($buf, 0, $buf.Length)
        if ($n -le 0) { return [pscustomobject]@{ Nome = $null; Detalhe = 'LDAP nao respondeu a consulta da rootDSE' } }
        $texto = [System.Text.Encoding]::UTF8.GetString($buf, 0, $n)
        if ($texto -match 'dnsHostName') {
            # o valor vem logo apos o nome do atributo, em OCTET STRING
            $idx = $texto.IndexOf('dnsHostName') + 'dnsHostName'.Length
            $resto = $texto.Substring($idx)
            if ($resto -match '([A-Za-z0-9][A-Za-z0-9\-]*\.[A-Za-z0-9.\-]+)') {
                return [pscustomobject]@{ Nome = $Matches[1]; Detalhe = 'dnsHostName da rootDSE' }
            }
        }
        return [pscustomobject]@{ Nome = $null; Detalhe = 'LDAP respondeu sem dnsHostName (tipico de OpenLDAP, que nao publica esse atributo)' }
    } catch {
        return [pscustomobject]@{ Nome = $null; Detalhe = ('falha no LDAP: ' + (Get-ErrorText $_)) }
    } finally { try { $conn.Client.Close() } catch { } }
}
#endregion

#region ---------------------------------------------------------------- Hostname: portas extras e credenciais
function ConvertFrom-LittleEndianUInt16 {
    [CmdletBinding()]
    param([byte[]]$Bytes, [int]$Offset = 0)
    if ($null -eq $Bytes -or $Offset -lt 0 -or ($Offset + 2) -gt $Bytes.Length) {
        throw "ConvertFrom-LittleEndianUInt16: offset $Offset fora do buffer"
    }
    return ((([int]$Bytes[$Offset + 1]) -shl 8) -bor [int]$Bytes[$Offset])
}

function ConvertFrom-LittleEndianUInt32 {
    [CmdletBinding()]
    param([byte[]]$Bytes, [int]$Offset = 0)
    if ($null -eq $Bytes -or $Offset -lt 0 -or ($Offset + 4) -gt $Bytes.Length) {
        throw "ConvertFrom-LittleEndianUInt32: offset $Offset fora do buffer"
    }
    return ((([int]$Bytes[$Offset + 3]) -shl 24) -bor (([int]$Bytes[$Offset + 2]) -shl 16) -bor
            (([int]$Bytes[$Offset + 1]) -shl 8)  -bor [int]$Bytes[$Offset])
}

function Read-NtlmChallenge {
    <#
    .SYNOPSIS
        Extrai nomes do TargetInfo de uma mensagem NTLMSSP CHALLENGE (tipo 2).
    .DESCRIPTION
        Localiza a assinatura "NTLMSSP\0" no buffer, o que torna a leitura tolerante a
        respostas encapsuladas em SPNEGO.
    #>
    [CmdletBinding()]
    param([byte[]]$Buffer)

    $r = [ordered]@{ NomeNetBios = $null; DominioNetBios = $null; NomeDns = $null; DominioDns = $null; Detalhe = '' }
    if ($null -eq $Buffer -or $Buffer.Length -lt 56) { $r.Detalhe = 'buffer menor que uma mensagem NTLM CHALLENGE'; return [pscustomobject]$r }

    $sig = [byte[]]@(0x4E,0x54,0x4C,0x4D,0x53,0x53,0x50,0x00)     # "NTLMSSP\0"
    $base = -1
    for ($i = 0; $i -le ($Buffer.Length - 12); $i++) {
        $match = $true
        for ($k = 0; $k -lt 8; $k++) { if ($Buffer[$i + $k] -ne $sig[$k]) { $match = $false; break } }
        if ($match) {
            if ((ConvertFrom-LittleEndianUInt32 -Bytes $Buffer -Offset ($i + 8)) -eq 2) { $base = $i; break }
        }
    }
    if ($base -lt 0) { $r.Detalhe = 'nenhuma mensagem NTLMSSP CHALLENGE na resposta'; return [pscustomobject]$r }
    if (($base + 48) -gt $Buffer.Length) { $r.Detalhe = 'mensagem NTLM CHALLENGE truncada'; return [pscustomobject]$r }

    $tiLen = ConvertFrom-LittleEndianUInt16 -Bytes $Buffer -Offset ($base + 40)
    $tiOff = ConvertFrom-LittleEndianUInt32 -Bytes $Buffer -Offset ($base + 44)
    $ini = $base + $tiOff
    if ($tiLen -le 0 -or $ini -lt 0 -or ($ini + $tiLen) -gt $Buffer.Length) {
        $r.Detalhe = 'CHALLENGE sem bloco TargetInfo utilizavel'
        return [pscustomobject]$r
    }

    $p = $ini
    $fim = $ini + $tiLen
    while (($p + 4) -le $fim) {
        $id  = ConvertFrom-LittleEndianUInt16 -Bytes $Buffer -Offset $p
        $len = ConvertFrom-LittleEndianUInt16 -Bytes $Buffer -Offset ($p + 2)
        $p += 4
        if ($id -eq 0) { break }                                   # MsvAvEOL
        if ($len -lt 0 -or ($p + $len) -gt $fim) { break }
        $valor = if ($len -gt 0) { [System.Text.Encoding]::Unicode.GetString($Buffer, $p, $len) } else { '' }
        switch ($id) {
            1 { $r.NomeNetBios    = $valor }
            2 { $r.DominioNetBios = $valor }
            3 { $r.NomeDns        = $valor }
            4 { $r.DominioDns     = $valor }
        }
        $p += $len
    }
    $r.Detalhe = 'NTLM CHALLENGE interpretado'
    return [pscustomobject]$r
}

function Get-NtlmHostInfo {
    <#
    .SYNOPSIS
        Negocia SMB2 em TCP 445 e le o CHALLENGE NTLM. Responde Windows e Linux com Samba.
    #>
    [CmdletBinding()]
    param([string]$IpAddress, [int]$TimeoutMs = 1500)

    $conn = Connect-TcpWithTimeout -IpAddress $IpAddress -Port 445 -TimeoutMs $TimeoutMs
    if (-not $conn.Client) {
        return [pscustomobject]@{ NomeNetBios=$null; DominioNetBios=$null; NomeDns=$null; DominioDns=$null; Detalhe = ('SMB 445: ' + $conn.Erro) }
    }

    try {
        $ns = $conn.Client.GetStream(); $ns.ReadTimeout = $TimeoutMs; $ns.WriteTimeout = $TimeoutMs

        function New-Smb2Header([int]$Command, [int]$MessageId) {
            $h = New-Object System.Collections.Generic.List[byte]
            $h.AddRange([byte[]]@(0xFE,0x53,0x4D,0x42))            # ProtocolId
            $h.AddRange([byte[]]@(0x40,0x00))                      # StructureSize 64
            $h.AddRange([byte[]]@(0x00,0x00))                      # CreditCharge
            $h.AddRange([byte[]]@(0x00,0x00,0x00,0x00))            # Status
            $h.AddRange([byte[]]@([byte]($Command -band 0xFF),[byte](($Command -shr 8) -band 0xFF)))
            $h.AddRange([byte[]]@(0x01,0x00))                      # Credits
            $h.AddRange([byte[]]@(0x00,0x00,0x00,0x00))            # Flags
            $h.AddRange([byte[]]@(0x00,0x00,0x00,0x00))            # NextCommand
            $h.AddRange([byte[]]@([byte]$MessageId,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
            $h.AddRange([byte[]]@(0x00,0x00,0x00,0x00))            # Reserved
            $h.AddRange([byte[]]@(0x00,0x00,0x00,0x00))            # TreeId
            $h.AddRange((New-Object byte[] 8))                     # SessionId
            $h.AddRange((New-Object byte[] 16))                    # Signature
            return ,$h.ToArray()
        }
        function Send-Smb2([System.IO.Stream]$S, [byte[]]$Payload) {
            $t = New-Object System.Collections.Generic.List[byte]
            $t.Add(0x00)
            $t.AddRange((ConvertTo-BigEndianBytes -Value $Payload.Length -Size 3))
            $t.AddRange($Payload)
            $b = $t.ToArray()
            $S.Write($b, 0, $b.Length); $S.Flush()
        }
        function Receive-Smb2([System.IO.Stream]$S) {
            $hdr = New-Object byte[] 4
            $lidos = 0
            while ($lidos -lt 4) { $n = $S.Read($hdr, $lidos, 4 - $lidos); if ($n -le 0) { return $null }; $lidos += $n }
            $tam = ConvertFrom-BigEndianUInt24 -Bytes $hdr -Offset 1
            if ($tam -le 0 -or $tam -gt 1048576) { return $null }
            $body = New-Object byte[] $tam
            $lidos = 0
            while ($lidos -lt $tam) { $n = $S.Read($body, $lidos, $tam - $lidos); if ($n -le 0) { break }; $lidos += $n }
            return ,$body
        }

        # --- NEGOTIATE ---
        $neg = New-Object System.Collections.Generic.List[byte]
        $neg.AddRange((New-Smb2Header 0x0000 1))
        $neg.AddRange([byte[]]@(0x24,0x00))                        # StructureSize 36
        $neg.AddRange([byte[]]@(0x02,0x00))                        # DialectCount 2
        $neg.AddRange([byte[]]@(0x01,0x00))                        # SecurityMode
        $neg.AddRange([byte[]]@(0x00,0x00))                        # Reserved
        $neg.AddRange([byte[]]@(0x00,0x00,0x00,0x00))              # Capabilities
        $neg.AddRange((New-Object byte[] 16))                      # ClientGuid
        $neg.AddRange((New-Object byte[] 8))                       # ClientStartTime
        $neg.AddRange([byte[]]@(0x02,0x02,0x10,0x02))              # Dialects 2.0.2 e 2.1
        Send-Smb2 $ns $neg.ToArray()
        $resp = Receive-Smb2 $ns
        if (-not $resp) { return [pscustomobject]@{ NomeNetBios=$null; DominioNetBios=$null; NomeDns=$null; DominioDns=$null; Detalhe='SMB 445 aberto mas sem resposta ao NEGOTIATE (pode ser SMB1 apenas)' } }

        # --- SESSION_SETUP com NTLMSSP NEGOTIATE ---
        $ntlm = New-Object System.Collections.Generic.List[byte]
        $ntlm.AddRange([byte[]]@(0x4E,0x54,0x4C,0x4D,0x53,0x53,0x50,0x00))   # NTLMSSP\0
        $ntlm.AddRange([byte[]]@(0x01,0x00,0x00,0x00))                        # tipo 1
        $ntlm.AddRange([byte[]]@(0x07,0x82,0x08,0xA2))                        # flags
        $ntlm.AddRange((New-Object byte[] 8))                                 # DomainNameFields
        $ntlm.AddRange((New-Object byte[] 8))                                 # WorkstationFields
        $ntlm.AddRange([byte[]]@(0x06,0x01,0xB1,0x1D,0x00,0x00,0x00,0x0F))    # Version
        $tok = $ntlm.ToArray()

        $ss = New-Object System.Collections.Generic.List[byte]
        $ss.AddRange((New-Smb2Header 0x0001 2))
        $ss.AddRange([byte[]]@(0x19,0x00))                          # StructureSize 25
        $ss.Add(0x00)                                               # Flags
        $ss.Add(0x01)                                               # SecurityMode
        $ss.AddRange([byte[]]@(0x00,0x00,0x00,0x00))                # Capabilities
        $ss.AddRange([byte[]]@(0x00,0x00,0x00,0x00))                # Channel
        $ss.AddRange([byte[]]@(0x58,0x00))                          # SecurityBufferOffset = 88
        $ss.AddRange([byte[]]@([byte]($tok.Length -band 0xFF),[byte](($tok.Length -shr 8) -band 0xFF)))
        $ss.AddRange((New-Object byte[] 8))                         # PreviousSessionId
        $ss.AddRange($tok)
        Send-Smb2 $ns $ss.ToArray()
        $resp = Receive-Smb2 $ns
        if (-not $resp) { return [pscustomobject]@{ NomeNetBios=$null; DominioNetBios=$null; NomeDns=$null; DominioDns=$null; Detalhe='SMB nao respondeu ao SESSION_SETUP' } }

        return Read-NtlmChallenge -Buffer $resp
    } catch {
        return [pscustomobject]@{ NomeNetBios=$null; DominioNetBios=$null; NomeDns=$null; DominioDns=$null; Detalhe = ('falha no NTLM/SMB: ' + (Get-ErrorText $_)) }
    } finally { try { $conn.Client.Close() } catch { } }
}

function Get-RdpCertificateName {
    <#
    .SYNOPSIS
        Negocia X.224 em TCP 3389, sobe TLS e le o CN do certificado do RDP.
    #>
    [CmdletBinding()]
    param([string]$IpAddress, [int]$TimeoutMs = 2000)

    $conn = Connect-TcpWithTimeout -IpAddress $IpAddress -Port 3389 -TimeoutMs $TimeoutMs
    if (-not $conn.Client) { return [pscustomobject]@{ Nome = $null; Detalhe = ('RDP 3389: ' + $conn.Erro) } }

    $ssl = $null
    try {
        $ns = $conn.Client.GetStream(); $ns.ReadTimeout = $TimeoutMs; $ns.WriteTimeout = $TimeoutMs

        # TPKT + X.224 Connection Request + RDP_NEG_REQ pedindo TLS (protocolo 1)
        $cr = [byte[]]@(
            0x03,0x00,0x00,0x13,                 # TPKT: versao 3, tamanho 19
            0x0E,0xE0,0x00,0x00,0x00,0x00,0x00,  # X.224 CR
            0x01,0x00,0x08,0x00,0x01,0x00,0x00,0x00   # RDP_NEG_REQ: TLS
        )
        $ns.Write($cr, 0, $cr.Length); $ns.Flush()

        $buf = New-Object byte[] 64
        $n = $ns.Read($buf, 0, $buf.Length)
        if ($n -lt 11) { return [pscustomobject]@{ Nome = $null; Detalhe = 'RDP nao respondeu a negociacao X.224' } }
        if ($buf[11] -eq 0x03) { return [pscustomobject]@{ Nome = $null; Detalhe = 'RDP recusou TLS (RDP_NEG_FAILURE); provavel seguranca padrao RDP' } }

        $captura = @{ Cert = $null }
        $cb = [System.Net.Security.RemoteCertificateValidationCallback]({
            param($remetente, $certificado, $cadeia, $erros)
            if ($certificado) { try { $captura.Cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 (,[byte[]]$certificado.GetRawCertData()) } catch { } }
            return $true
        }).GetNewClosure()

        $ssl = New-Object System.Net.Security.SslStream($ns, $false, $cb)
        try { $ssl.AuthenticateAsClient($IpAddress, $null, (Get-SupportedSslProtocols -IncludeTls13), $false) } catch { }
        if (-not $captura.Cert) { return [pscustomobject]@{ Nome = $null; Detalhe = 'TLS do RDP nao expos certificado' } }

        $cn = $null
        try { $cn = $captura.Cert.GetNameInfo([System.Security.Cryptography.X509Certificates.X509NameType]::SimpleName, $false) } catch { }
        if (-not $cn -and $captura.Cert.Subject -match 'CN=([^,]+)') { $cn = $Matches[1] }
        if ($cn) { return [pscustomobject]@{ Nome = $cn; Detalhe = 'CN do certificado do RDP' } }
        return [pscustomobject]@{ Nome = $null; Detalhe = 'certificado do RDP sem CN legivel' }
    } catch {
        return [pscustomobject]@{ Nome = $null; Detalhe = ('falha no RDP: ' + (Get-ErrorText $_)) }
    } finally {
        if ($ssl) { try { $ssl.Dispose() } catch { } }
        try { $conn.Client.Close() } catch { }
    }
}

function Get-SnmpSysName {
    <#
    .SYNOPSIS
        GET SNMPv2c de sysName (1.3.6.1.2.1.1.5.0) direto em UDP 161.
    .DESCRIPTION
        E o metodo sem agente que mais resolve hostname de servidor Linux.
    #>
    [CmdletBinding()]
    param([string]$IpAddress, [string]$Community, [int]$TimeoutMs = 1500)

    if (-not $Community) { return [pscustomobject]@{ Nome = $null; Detalhe = 'SNMP nao consultado (informe -SnmpCommunity)' } }

    $udp = $null
    try {
        $udp = New-Object System.Net.Sockets.UdpClient
        $udp.Client.ReceiveTimeout = $TimeoutMs
        $udp.Client.SendTimeout    = $TimeoutMs

        $com = [System.Text.Encoding]::ASCII.GetBytes($Community)
        $oid = [byte[]]@(0x2B,0x06,0x01,0x02,0x01,0x01,0x05,0x00)      # 1.3.6.1.2.1.1.5.0

        $vb = New-Object System.Collections.Generic.List[byte]
        $vb.AddRange([byte[]]@(0x06,[byte]$oid.Length)); $vb.AddRange($oid)
        $vb.AddRange([byte[]]@(0x05,0x00))                              # valor NULL
        $vbSeq = New-Object System.Collections.Generic.List[byte]
        $vbSeq.AddRange([byte[]]@(0x30,[byte]$vb.Count)); $vbSeq.AddRange($vb.ToArray())
        $vbList = New-Object System.Collections.Generic.List[byte]
        $vbList.AddRange([byte[]]@(0x30,[byte]$vbSeq.Count)); $vbList.AddRange($vbSeq.ToArray())

        $pdu = New-Object System.Collections.Generic.List[byte]
        $pdu.AddRange([byte[]]@(0x02,0x04,0x12,0x34,0x56,0x78))         # request-id
        $pdu.AddRange([byte[]]@(0x02,0x01,0x00))                        # error-status
        $pdu.AddRange([byte[]]@(0x02,0x01,0x00))                        # error-index
        $pdu.AddRange($vbList.ToArray())
        $pduWrap = New-Object System.Collections.Generic.List[byte]
        $pduWrap.AddRange([byte[]]@(0xA0,[byte]$pdu.Count)); $pduWrap.AddRange($pdu.ToArray())

        $msg = New-Object System.Collections.Generic.List[byte]
        $msg.AddRange([byte[]]@(0x02,0x01,0x01))                        # version 1 = SNMPv2c
        $msg.AddRange([byte[]]@(0x04,[byte]$com.Length)); $msg.AddRange($com)
        $msg.AddRange($pduWrap.ToArray())
        $pkt = New-Object System.Collections.Generic.List[byte]
        $pkt.AddRange([byte[]]@(0x30,[byte]$msg.Count)); $pkt.AddRange($msg.ToArray())

        $bytes = $pkt.ToArray()
        [void]$udp.Send($bytes, $bytes.Length, $IpAddress, 161)
        $remote = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Any, 0)
        $resp = $udp.Receive([ref]$remote)

        return (Read-SnmpSysNameResponse -Buffer $resp)
    } catch [System.Net.Sockets.SocketException] {
        return [pscustomobject]@{ Nome = $null; Detalhe = 'sem resposta SNMP (agente ausente, community incorreta ou UDP 161 bloqueado)' }
    } catch {
        return [pscustomobject]@{ Nome = $null; Detalhe = ('falha no SNMP: ' + (Get-ErrorText $_)) }
    } finally { if ($udp) { try { $udp.Close() } catch { } } }
}

function Read-SnmpSysNameResponse {
    <#
    .SYNOPSIS
        Extrai o valor OCTET STRING que segue o OID de sysName numa resposta SNMP.
    #>
    [CmdletBinding()]
    param([byte[]]$Buffer)

    if ($null -eq $Buffer -or $Buffer.Length -lt 10) { return [pscustomobject]@{ Nome = $null; Detalhe = 'resposta SNMP curta demais' } }
    $oid = [byte[]]@(0x2B,0x06,0x01,0x02,0x01,0x01,0x05,0x00)
    for ($i = 0; $i -le ($Buffer.Length - $oid.Length - 2); $i++) {
        $match = $true
        for ($k = 0; $k -lt $oid.Length; $k++) { if ($Buffer[$i + $k] -ne $oid[$k]) { $match = $false; break } }
        if (-not $match) { continue }
        $p = $i + $oid.Length
        if (($p + 2) -gt $Buffer.Length) { break }
        if ($Buffer[$p] -ne 0x04) {
            return [pscustomobject]@{ Nome = $null; Detalhe = ('SNMP respondeu com tipo 0x{0:X2} em vez de OCTET STRING (OID ausente no agente)' -f $Buffer[$p]) }
        }
        $len = [int]$Buffer[$p + 1]
        $p += 2
        if ($len -le 0 -or ($p + $len) -gt $Buffer.Length) { return [pscustomobject]@{ Nome = $null; Detalhe = 'valor de sysName truncado' } }
        $nome = [System.Text.Encoding]::UTF8.GetString($Buffer, $p, $len).Trim()
        if ($nome) { return [pscustomobject]@{ Nome = $nome; Detalhe = 'sysName via SNMP' } }
        return [pscustomobject]@{ Nome = $null; Detalhe = 'sysName vazio no agente' }
    }
    return [pscustomobject]@{ Nome = $null; Detalhe = 'OID de sysName ausente na resposta SNMP' }
}

function Get-SshHostname {
    <#
    .SYNOPSIS
        Executa 'hostname -f' via ssh.exe. Nunca pede senha nem grava credencial.
    #>
    [CmdletBinding()]
    param([string]$IpAddress, [string]$User, [string]$KeyPath, [int]$TimeoutMs = 8000)

    if (-not $User) { return [pscustomobject]@{ Nome = $null; Detalhe = 'SSH nao consultado (informe -SshUser)' } }
    $ssh = Get-Command 'ssh.exe','ssh' -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $ssh) { return [pscustomobject]@{ Nome = $null; Detalhe = 'ssh.exe nao encontrado (opcional; presente no Windows 10+/Server 2019+)' } }
    if ($KeyPath -and -not (Test-Path -LiteralPath $KeyPath)) {
        return [pscustomobject]@{ Nome = $null; Detalhe = ('chave SSH nao encontrada em {0}' -f $KeyPath) }
    }

    $args = @(
        '-o','BatchMode=yes'                     # nunca perguntar senha
        '-o','StrictHostKeyChecking=no'
        '-o','UserKnownHostsFile=/dev/null'
        '-o',('ConnectTimeout={0}' -f [Math]::Max(1, [int]($TimeoutMs / 1000)))
        '-o','LogLevel=ERROR'
    )
    if ($KeyPath) { $args += @('-i', ('"{0}"' -f $KeyPath), '-o', 'IdentitiesOnly=yes') }
    $args += @(('{0}@{1}' -f $User, $IpAddress), 'hostname -f')

    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $ssh.Source
    $psi.Arguments = ($args -join ' ')
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError  = $true
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow  = $true

    $proc = $null
    try {
        $proc = [System.Diagnostics.Process]::Start($psi)
        $saida = $proc.StandardOutput.ReadToEndAsync()
        $erro  = $proc.StandardError.ReadToEndAsync()
        if (-not $proc.WaitForExit($TimeoutMs)) {
            try { $proc.Kill() } catch { }
            return [pscustomobject]@{ Nome = $null; Detalhe = ('SSH excedeu {0} ms' -f $TimeoutMs) }
        }
        $nome = ($saida.Result -replace '\s+', ' ').Trim()
        if ($proc.ExitCode -eq 0 -and $nome) { return [pscustomobject]@{ Nome = $nome; Detalhe = "'hostname -f' via SSH" } }
        $msg = ($erro.Result -replace '\s+', ' ').Trim()
        if (-not $msg) { $msg = ('ssh terminou com codigo {0}' -f $proc.ExitCode) }
        return [pscustomobject]@{ Nome = $null; Detalhe = ('SSH falhou: ' + $msg) }
    } catch {
        return [pscustomobject]@{ Nome = $null; Detalhe = ('falha ao executar ssh: ' + (Get-ErrorText $_)) }
    } finally { if ($proc) { try { $proc.Dispose() } catch { } } }
}
#endregion

#region ---------------------------------------------------------------- Inferencia de SO
function Get-TtlGuess {
    <#
    .SYNOPSIS
        TTL observado por ICMP. Nao exige privilegio. Pode ser bloqueado pela rede.
    #>
    [CmdletBinding()]
    param([string]$IpAddress, [int]$TimeoutMs = 1000)
    $ping = $null
    try {
        $ping = New-Object System.Net.NetworkInformation.Ping
        $rep = $ping.Send($IpAddress, $TimeoutMs)
        if ($rep.Status -ne [System.Net.NetworkInformation.IPStatus]::Success) {
            return [pscustomobject]@{ Ttl = $null; Detalhe = ('ICMP: ' + $rep.Status) }
        }
        $ttl = $null
        try { $ttl = $rep.Options.Ttl } catch { }
        if ($null -eq $ttl) { return [pscustomobject]@{ Ttl = $null; Detalhe = 'ICMP respondeu sem expor TTL' } }
        return [pscustomobject]@{ Ttl = $ttl; Detalhe = ('TTL ' + $ttl) }
    } catch {
        return [pscustomobject]@{ Ttl = $null; Detalhe = ('ICMP indisponivel: ' + (Get-ErrorText $_)) }
    } finally { if ($ping) { try { $ping.Dispose() } catch { } } }
}

function Get-OsGuess {
    <#
    .SYNOPSIS
        Estima o sistema operacional a partir das evidencias coletadas. E estimativa, nao fato.
    #>
    [CmdletBinding()]
    param(
        [bool]$NetBiosRespondeu = $false,
        [string]$SshBanner = '',
        [string]$SmtpBanner = '',
        [bool]$NtlmRespondeu = $false,
        [string]$NtlmDominioDns = '',
        [bool]$RdpTls = $false,
        [object]$Ttl = $null,
        [string]$NomeObservado = ''
    )

    $pontosWin = 0; $pontosLin = 0; $ev = @()

    if ($SshBanner) {
        if ($SshBanner -match 'OpenSSH_for_Windows|Windows') { $pontosWin += 3; $ev += 'banner SSH do OpenSSH para Windows' }
        elseif ($SshBanner -match 'Ubuntu|Debian|CentOS|Red Hat|SUSE|FreeBSD|OpenSSH') { $pontosLin += 3; $ev += ('banner SSH: ' + ($SshBanner -replace '^SSH-\d\.\d-', '')) }
    }
    if ($SmtpBanner) {
        if ($SmtpBanner -match 'Microsoft|Exchange') { $pontosWin += 3; $ev += 'banner SMTP da Microsoft' }
        elseif ($SmtpBanner -match 'Postfix|Sendmail|Exim') { $pontosLin += 3; $ev += 'banner SMTP de MTA Unix' }
    }
    if ($NetBiosRespondeu) { $pontosWin += 1; $ev += 'respondeu NetBIOS (Windows ou Samba)' }
    if ($NtlmRespondeu)    { $pontosWin += 2; $ev += 'respondeu NTLM em SMB (Windows ou Samba)' }
    if ($NtlmDominioDns -match '\.') { $pontosWin += 1; $ev += ('dominio NTLM: ' + $NtlmDominioDns) }
    if ($RdpTls)           { $pontosWin += 2; $ev += 'RDP com TLS (Windows ou xrdp)' }

    if ($NomeObservado -match 'ocp|openshift|\.apps\.|kube|k8s|ec2-|compute\.internal|ip-\d+-\d+') {
        $pontosLin += 2; $ev += 'nome sugere OpenShift/Kubernetes/EC2'
    }

    if ($null -ne $Ttl) {
        $t = [int]$Ttl
        if ($t -gt 64 -and $t -le 128)     { $pontosWin += 1; $ev += ('TTL ' + $t + ' (compativel com Windows)') }
        elseif ($t -gt 0 -and $t -le 64)   { $pontosLin += 1; $ev += ('TTL ' + $t + ' (compativel com Linux)') }
    }

    $so = 'Desconhecido'
    if ($pontosWin -gt $pontosLin -and $pontosWin -ge 2)      { $so = 'Windows' }
    elseif ($pontosLin -gt $pontosWin -and $pontosLin -ge 2)  { $so = 'Linux' }
    elseif ($pontosWin -gt 0 -or $pontosLin -gt 0)            { $so = if ($pontosWin -ge $pontosLin) { 'Windows (fraco)' } else { 'Linux (fraco)' } }

    $detalhe = if ($ev) { ($ev -join '; ') } else { 'sem evidencia coletada' }
    return [pscustomobject]@{ SO = $so; Evidencia = ('estimativa: ' + $detalhe) }
}
#endregion

#region ---------------------------------------------------------------- Orquestrador de hostname
function Resolve-HostIdentity {
    <#
    .SYNOPSIS
        Aplica a ordem de preferencia documentada e registra sempre a origem do nome.
    #>
    [CmdletBinding()]
    param(
        [string]$IpAddress,
        [hashtable]$Opcoes
    )

    $det = @()
    $nome = $null; $origem = $null
    $evidencia = @{ NetBios = $false; Ssh = ''; Smtp = ''; Ntlm = $false; NtlmDominio = ''; Rdp = $false; Ttl = $null }
    $to = $Opcoes.HostnameTimeoutMs

    # 1. SSH 'hostname -f'
    if ($Opcoes.SshUser) {
        $r = Get-SshHostname -IpAddress $IpAddress -User $Opcoes.SshUser -KeyPath $Opcoes.SshKeyPath -TimeoutMs ([Math]::Max($to, 8000))
        $det += ('SSH: ' + $r.Detalhe)
        if ($r.Nome -and -not $nome) { $nome = $r.Nome; $origem = 'SSH hostname -f' }
    } else { $det += 'SSH: desabilitado' }

    # 2. SNMP sysName
    if (-not $nome -and $Opcoes.SnmpCommunity) {
        $r = Get-SnmpSysName -IpAddress $IpAddress -Community $Opcoes.SnmpCommunity -TimeoutMs $to
        $det += ('SNMP: ' + $r.Detalhe)
        if ($r.Nome) { $nome = $r.Nome; $origem = 'SNMP sysName' }
    } elseif (-not $Opcoes.SnmpCommunity) { $det += 'SNMP: desabilitado' }

    # 3. NTLM via SMB 445
    if ($Opcoes.UseSmb) {
        $r = Get-NtlmHostInfo -IpAddress $IpAddress -TimeoutMs $to
        $det += ('NTLM/SMB: ' + $r.Detalhe)
        if ($r.NomeNetBios -or $r.NomeDns) {
            $evidencia.Ntlm = $true
            $evidencia.NtlmDominio = "$($r.DominioDns)"
            if (-not $nome) {
                $nome = if ($r.NomeDns) { $r.NomeDns } else { $r.NomeNetBios }
                $origem = 'NTLM via SMB'
            }
        }
    } else { $det += 'NTLM/SMB: desabilitado' }

    # 4. rootDSE LDAP
    if (-not $nome -and $Opcoes.UseLdap) {
        $r = Get-LdapRootDseName -IpAddress $IpAddress -TimeoutMs $to
        $det += ('LDAP: ' + $r.Detalhe)
        if ($r.Nome) { $nome = $r.Nome; $origem = 'rootDSE LDAP' }
    } elseif (-not $Opcoes.UseLdap) { $det += 'LDAP: desabilitado' }

    # 5. NetBIOS
    if (-not $Opcoes.SkipNetBios) {
        $ehIPv4 = ([System.Net.IPAddress]$IpAddress).AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork
        if ($ehIPv4) {
            $r = Get-NetBiosName -IpAddress $IpAddress -TimeoutMs $to
            $det += ('NetBIOS: ' + $r.Detalhe)
            if ($r.Nome) {
                $evidencia.NetBios = $true
                if (-not $nome) { $nome = $r.Nome; $origem = 'NetBIOS' }
            }
        } else { $det += 'NetBIOS: nao se aplica a IPv6' }
    } else { $det += 'NetBIOS: desabilitado' }

    # 6. Banner SMTP
    if ($Opcoes.UseSmtpBanner) {
        $r = Get-SmtpBannerName -IpAddress $IpAddress -TimeoutMs $to
        $det += ('SMTP: ' + $r.Detalhe)
        $evidencia.Smtp = $r.Banner
        if ($r.Nome -and -not $nome) { $nome = $r.Nome; $origem = 'banner SMTP' }
    } else { $det += 'SMTP: desabilitado' }

    # 7. Certificado do RDP
    if ($Opcoes.UseRdp) {
        $r = Get-RdpCertificateName -IpAddress $IpAddress -TimeoutMs ([Math]::Max($to, 2000))
        $det += ('RDP: ' + $r.Detalhe)
        if ($r.Nome) {
            $evidencia.Rdp = $true
            if (-not $nome) { $nome = $r.Nome; $origem = 'certificado do RDP' }
        }
    } else { $det += 'RDP: desabilitado' }

    # 8. PTR
    if (-not $Opcoes.SkipPtr) {
        $r = Get-PtrRecord -IpAddress $IpAddress
        $det += ('PTR: ' + $r.Detalhe)
        if ($r.Nome -and -not $nome) { $nome = $r.Nome; $origem = 'PTR' }
    } else { $det += 'PTR: desabilitado' }

    # Banner SSH apenas para inferencia de SO
    if ($Opcoes.UseSshBanner) {
        $r = Get-SshBanner -IpAddress $IpAddress -TimeoutMs $to
        $evidencia.Ssh = $r.Banner
        $det += ('banner SSH: ' + $r.Detalhe)
    }

    $ttl = Get-TtlGuess -IpAddress $IpAddress -TimeoutMs ([Math]::Min($to, 1000))
    $evidencia.Ttl = $ttl.Ttl
    $det += ('TTL: ' + $ttl.Detalhe)

    $status = if ($nome) { 'OK' } else { 'NAO IDENTIFICADO' }
    if (-not $nome) { $origem = 'nenhum metodo devolveu nome' }

    return [pscustomobject]@{
        Hostname  = $nome
        Origem    = $origem
        Status    = $status
        Detalhe   = ($det -join ' | ')
        Evidencia = $evidencia
    }
}
#endregion

#region ---------------------------------------------------------------- Processamento de um alvo
function Invoke-TargetScan {
    <#
    .SYNOPSIS
        Executa as tres etapas para um par (alvo, IP) e devolve a linha de resultado.
    #>
    [CmdletBinding()]
    param(
        [pscustomobject]$Alvo,
        [pscustomobject]$Dns,
        [string]$Ip,
        [hashtable]$Opcoes
    )

    $linha = [ordered]@{
        Entrada = $Alvo.Entrada; Host = $Alvo.Host; Porta = $Alvo.Porta; PortaUsada = $Alvo.Porta
        CNAME = ''; IP = $Ip; EntradasNoMesmoIP = 0
        Hostname = ''; OrigemHostname = ''; SOProvavel = 'Desconhecido'; EvidenciaSO = ''
        StatusDNS = ''; DetalheDNS = ''; StatusHostname = ''; DetalheHostname = ''
        StatusTLS = ''; DetalheTLS = ''; MetodoLeitura = ''; TlsVersao = ''; CipherSuite = ''
        ExigeCertCliente = ''; SniUsado = ''; SniDivergente = ''
        Subject = ''; CN = ''; Emissor = ''; SANs = ''
        ValidoDe = ''; ValidoAte = ''; DiasRestantes = ''; Situacao = ''
        AlgoritmoChave = ''; TamanhoChave = ''; AlgoritmoAssinatura = ''; NumeroSerie = ''; Thumbprint = ''
        CadeiaEnviada = ''; CadeiaCompleta = ''; CadeiaConfiavel = ''; ErrosValidacao = ''
    }

    $linha.CNAME      = if ($Dns.CNAME) { $Dns.CNAME -join ' > ' } else { 'sem CNAME' }
    if (-not $Ip) { $linha.IP = 'sem IP: DNS nao resolveu' }
    $linha.StatusDNS  = $Dns.Status
    $linha.DetalheDNS = $Dns.Detalhe

    if (-not $Ip) {
        $linha.StatusHostname = 'NAO APLICAVEL'; $linha.DetalheHostname = 'sem IP para consultar'
        $linha.StatusTLS = 'NAO APLICAVEL';     $linha.DetalheTLS = 'sem IP para conectar'
        $linha.Situacao = 'FALHA DNS'
        foreach ($k in @('Hostname','OrigemHostname','MetodoLeitura','TlsVersao','CipherSuite','ExigeCertCliente',
                         'SniUsado','SniDivergente','Subject','CN','Emissor','SANs','ValidoDe','ValidoAte',
                         'DiasRestantes','AlgoritmoChave','TamanhoChave','AlgoritmoAssinatura','NumeroSerie',
                         'Thumbprint','CadeiaEnviada','CadeiaCompleta','CadeiaConfiavel','ErrosValidacao','EvidenciaSO')) {
            $linha[$k] = 'nao aplicavel: DNS nao resolveu'
        }
        return [pscustomobject]$linha
    }

    # ---------------- Hostname ----------------
    $id = Resolve-HostIdentity -IpAddress $Ip -Opcoes $Opcoes
    $linha.Hostname        = if ($id.Hostname) { $id.Hostname } else { '' }
    $linha.OrigemHostname  = $id.Origem
    $linha.StatusHostname  = $id.Status
    $linha.DetalheHostname = $id.Detalhe

    # ---------------- TLS ----------------
    $startTls = Get-StartTlsProtocol -Port $Alvo.Porta -Mode $Opcoes.StartTlsMode
    $cnameAlvo = if ($Dns.CNAME -and $Dns.CNAME.Count -gt 0) { $Dns.CNAME[-1] } else { $null }

    $portas = @($Alvo.Porta)
    if ($Opcoes.AlternatePorts) { $portas += @($Opcoes.AlternatePorts | Where-Object { $_ -ne $Alvo.Porta }) }

    $cert = $null
    $tentativasPorta = @()
    foreach ($p in $portas) {
        $st = if ($p -eq $Alvo.Porta) { $startTls } else { Get-StartTlsProtocol -Port $p -Mode $Opcoes.StartTlsMode }
        $c = Get-CertificateFromTarget -IpAddress $Ip -Port $p -ServerName $Alvo.Host -CnameTarget $cnameAlvo `
                -TcpTimeoutMs $Opcoes.TcpTimeoutMs -TlsTimeoutMs $Opcoes.TlsTimeoutMs `
                -StartTls $st -OpenSslExe $Opcoes.OpenSslExe -CompareSni:$Opcoes.CompareSni
        if ($c.Certificado) { $cert = $c; $linha.PortaUsada = $p; break }
        $tentativasPorta += ('porta {0}: {1}' -f $p, $c.Detalhe)
        $cert = $c
        # So vale a pena tentar outra porta quando a falha foi de conexao, nao de TLS
        if ($c.Detalhe -notmatch 'timeout TCP|falha TCP') { break }
    }

    $linha.MetodoLeitura    = $cert.MetodoLeitura
    $linha.TlsVersao        = if ($cert.TlsVersao) { $cert.TlsVersao } else { 'sem handshake completo' }
    $linha.CipherSuite      = if ($cert.CipherSuite) { $cert.CipherSuite } else { 'sem handshake completo' }
    $linha.ExigeCertCliente = $cert.ExigeCertCliente
    $linha.SniUsado         = $cert.SniUsado
    $linha.SniDivergente    = $cert.SniDivergente
    $linha.ErrosValidacao   = $cert.ErrosValidacao

    if ($cert.Certificado) {
        $f = Get-CertificateFacts -Certificate $cert.Certificado
        $linha.Subject             = $f.Subject
        $linha.CN                  = $f.CN
        $linha.Emissor             = $f.Emissor
        $linha.SANs                = $f.SANs
        $linha.ValidoDe            = if ($f.ValidoDe)  { $f.ValidoDe.ToString('yyyy-MM-dd HH:mm:ss') } else { 'nao legivel' }
        $linha.ValidoAte           = if ($f.ValidoAte) { $f.ValidoAte.ToString('yyyy-MM-dd HH:mm:ss') } else { 'nao legivel' }
        $linha.AlgoritmoChave      = $f.AlgoritmoChave
        $linha.TamanhoChave        = if ($f.TamanhoChave) { $f.TamanhoChave } else { 'nao legivel' }
        $linha.AlgoritmoAssinatura = $f.AlgoritmoAssinatura
        $linha.NumeroSerie         = $f.NumeroSerie
        $linha.Thumbprint          = $f.Thumbprint

        $ch = Test-CertificateChain -Leaf $cert.Certificado -Sent $cert.Cadeia
        $linha.CadeiaEnviada   = $ch.CadeiaEnviada
        $linha.CadeiaCompleta  = $ch.CadeiaCompleta
        $linha.CadeiaConfiavel = $ch.CadeiaConfiavel

        if ($f.ValidoAte) {
            $dias = [int][Math]::Floor(($f.ValidoAte - (Get-Date)).TotalDays)
            $linha.DiasRestantes = $dias
            $linha.Situacao = if ($dias -lt 0) { 'EXPIRADO' } elseif ($dias -le $Opcoes.WarningDays) { 'EXPIRA EM BREVE' } else { 'OK' }
        } else {
            $linha.DiasRestantes = 'nao calculavel: validade ilegivel'
            $linha.Situacao = 'CERTIFICADO ILEGIVEL'
        }

        $linha.StatusTLS  = $cert.Status
        $linha.DetalheTLS = if ($cert.Detalhe) { $cert.Detalhe } else { 'handshake completo sem erro' }

        # Ultimo recurso para hostname: CN/SAN do certificado, sempre marcado como pista
        if (-not $linha.Hostname) {
            $pista = $f.CN
            if (-not $pista -and $f.SANs -match 'DNS:([^,]+)') { $pista = $Matches[1] }
            if ($pista) {
                $linha.Hostname = $pista
                $linha.OrigemHostname = 'PISTA: CN/SAN do certificado (nao confirma o nome real da maquina)'
                $linha.StatusHostname = 'PISTA'
            }
        }
    } else {
        $linha.StatusTLS  = 'FALHA'
        $detalhe = @($cert.Detalhe) + $tentativasPorta | Where-Object { $_ } | Select-Object -Unique
        $linha.DetalheTLS = ($detalhe -join ' | ')
        $linha.Situacao   = 'FALHA TLS'
        foreach ($k in @('Subject','CN','Emissor','SANs','ValidoDe','ValidoAte','DiasRestantes',
                         'AlgoritmoChave','TamanhoChave','AlgoritmoAssinatura','NumeroSerie','Thumbprint',
                         'CadeiaEnviada','CadeiaCompleta','CadeiaConfiavel')) {
            $linha[$k] = 'sem certificado: ' + ($(if ($cert.Detalhe) { ($cert.Detalhe -split '\|')[0].Trim() } else { 'motivo nao registrado' }))
        }
    }

    if (-not $linha.Hostname) {
        $linha.Hostname = 'nao identificado'
    }

    # ---------------- SO provavel ----------------
    $ev = $id.Evidencia
    $g = Get-OsGuess -NetBiosRespondeu $ev.NetBios -SshBanner $ev.Ssh -SmtpBanner $ev.Smtp `
            -NtlmRespondeu $ev.Ntlm -NtlmDominioDns $ev.NtlmDominio -RdpTls $ev.Rdp -Ttl $ev.Ttl `
            -NomeObservado (($linha.Hostname, $linha.CN, $linha.SANs) -join ' ')
    $linha.SOProvavel  = $g.SO
    $linha.EvidenciaSO = $g.Evidencia

    return [pscustomobject]$linha
}
#endregion

#region ---------------------------------------------------------------- Paralelismo por runspaces
function Invoke-InParallel {
    <#
    .SYNOPSIS
        Executa um scriptblock sobre uma lista usando runspaces. Compativel com PowerShell 5.1.
    #>
    [CmdletBinding()]
    param(
        [object[]]$InputObject,
        [scriptblock]$ScriptBlock,
        [string[]]$FunctionNames = @(),
        [hashtable]$Parameters = @{},
        [int]$ThrottleLimit = 16,
        [string]$Activity = 'Processando'
    )

    if (-not $InputObject -or $InputObject.Count -eq 0) { return @() }

    $iss = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
    foreach ($fn in $FunctionNames) {
        $cmd = Get-Command -Name $fn -CommandType Function -ErrorAction SilentlyContinue
        if ($cmd) {
            $entry = New-Object System.Management.Automation.Runspaces.SessionStateFunctionEntry($fn, $cmd.Definition)
            $iss.Commands.Add($entry)
        }
    }

    $pool = [runspacefactory]::CreateRunspacePool(1, [Math]::Max(1, $ThrottleLimit), $iss, $Host)
    $pool.Open()

    $jobs = @()
    try {
        foreach ($item in $InputObject) {
            $ps = [powershell]::Create()
            $ps.RunspacePool = $pool
            [void]$ps.AddScript($ScriptBlock.ToString())
            [void]$ps.AddArgument($item)
            [void]$ps.AddArgument($Parameters)
            $jobs += [pscustomobject]@{ Shell = $ps; Handle = $ps.BeginInvoke(); Item = $item }
        }

        $total = $jobs.Count
        $resultados = New-Object System.Collections.Generic.List[object]
        $concluidos = 0
        while ($concluidos -lt $total) {
            $concluidos = 0
            foreach ($j in $jobs) {
                if ($j.Handle.IsCompleted) { $concluidos++ }
            }
            Write-Progress -Activity $Activity -Status ("$concluidos de $total") -PercentComplete (($concluidos / $total) * 100)
            if ($concluidos -lt $total) { Start-Sleep -Milliseconds 200 }
        }

        foreach ($j in $jobs) {
            try {
                $saida = $j.Shell.EndInvoke($j.Handle)
                foreach ($s in $saida) { if ($null -ne $s) { [void]$resultados.Add($s) } }
                foreach ($e in $j.Shell.Streams.Error) {
                    Write-Verbose ('Erro em runspace: ' + (Get-ErrorText $e))
                }
            } catch {
                Write-Verbose ('Falha ao coletar runspace: ' + (Get-ErrorText $_))
            } finally {
                try { $j.Shell.Dispose() } catch { }
            }
        }
        Write-Progress -Activity $Activity -Completed
        return $resultados.ToArray()
    } finally {
        try { $pool.Close(); $pool.Dispose() } catch { }
    }
}
#endregion

#region ---------------------------------------------------------------- Saida
function Export-ResultCsv {
    <#
    .SYNOPSIS
        Grava CSV com ';' e UTF-8 COM BOM nas duas versoes do PowerShell.
    .DESCRIPTION
        Export-Csv -Encoding UTF8 grava BOM no 5.1 e NAO grava no PowerShell 7; escrever o
        arquivo aqui garante que o Excel pt-BR leia os acentos igual nos dois.
    #>
    [CmdletBinding()]
    param([object[]]$Resultados, [string]$Path)

    $texto = $Resultados | ConvertTo-Csv -NoTypeInformation -Delimiter ';'
    $enc = New-Object System.Text.UTF8Encoding($true)
    [System.IO.File]::WriteAllLines($Path, $texto, $enc)
}
#endregion

#region ---------------------------------------------------------------- Execucao
function Invoke-CertInventory {
    [CmdletBinding()]
    param([hashtable]$Config)

    $log = $Config.LogFile
    Write-ScanLog -Message ('Inicio do inventario; PowerShell {0} ({1})' -f $PSVersionTable.PSVersion, $PSVersionTable.PSEdition) -Path $log

    # ---- entrada ----
    if ($Config.InputFile) {
        if (-not (Test-Path -LiteralPath $Config.InputFile)) { throw ("Arquivo nao encontrado: {0}" -f $Config.InputFile) }
        $linhas = Get-Content -LiteralPath $Config.InputFile
    } elseif ($Config.Targets) {
        $linhas = $Config.Targets
    } else {
        throw 'Informe -InputFile ou -Targets.'
    }

    $alvos = @()
    foreach ($l in $linhas) {
        $t = ConvertTo-Target -Line $l -DefaultPort $Config.DefaultPort
        if ($t) {
            if ($t.Erro) { Write-ScanLog -Message ("Entrada invalida '{0}': {1}" -f $t.Entrada, $t.Erro) -Level 'AVISO' -Path $log }
            $alvos += $t
        }
    }
    if ($alvos.Count -eq 0) { throw 'Nenhum endereco valido informado.' }
    Write-ScanLog -Message ('{0} alvo(s) apos o parsing da entrada' -f $alvos.Count) -Path $log

    # ---- openssl ----
    $openssl = Find-OpenSsl -OpenSslPath $Config.OpenSslPath
    if ($openssl) { Write-ScanLog -Message ('openssl encontrado em ' + $openssl) -Path $log }
    else { Write-ScanLog -Message 'openssl nao encontrado; M4 indisponivel (servidores so TLS 1.3 podem ficar sem leitura no PowerShell 5.1)' -Level 'AVISO' -Path $log }

    $opcoes = @{
        TcpTimeoutMs      = $Config.TcpTimeoutMs
        TlsTimeoutMs      = $Config.TlsTimeoutMs
        HostnameTimeoutMs = $Config.HostnameTimeoutMs
        WarningDays       = $Config.WarningDays
        StartTlsMode      = $Config.StartTlsMode
        AlternatePorts    = $Config.AlternatePorts
        SkipNetBios       = $Config.SkipNetBios
        SkipPtr           = $Config.SkipPtr
        UseSmb            = $Config.UseSmb
        UseRdp            = $Config.UseRdp
        UseSmtpBanner     = $Config.UseSmtpBanner
        UseLdap           = $Config.UseLdap
        UseSshBanner      = $Config.UseSshBanner
        SnmpCommunity     = $Config.SnmpCommunity
        SshUser           = $Config.SshUser
        SshKeyPath        = $Config.SshKeyPath
        OpenSslExe        = $openssl
        CompareSni        = $Config.CompareSni
    }

    $funcoes = @(
        'ConvertFrom-BigEndianUInt16','ConvertFrom-BigEndianUInt24','ConvertTo-BigEndianBytes'
        'ConvertFrom-LittleEndianUInt16','ConvertFrom-LittleEndianUInt32'
        'Get-ErrorText','Write-ScanLog','ConvertTo-Target','Resolve-TargetAddress'
        'Get-SubjectAlternativeName','Get-CertificateFacts','Test-CertificateChain'
        'Connect-TcpWithTimeout','Invoke-StartTls','Get-StartTlsProtocol'
        'Get-TlsAlertDescription','Get-CipherSuiteName','New-TlsClientHello','Read-TlsServerResponse','Get-CertificateRaw'
        'Get-SupportedSslProtocols','Get-CertificateViaSslStream','Find-OpenSsl','Get-CertificateViaOpenSsl'
        'Get-CertificateFromTarget','Read-NetBiosResponse','Get-NetBiosName','Get-PtrRecord'
        'Read-SmtpBanner','Get-SmtpBannerName','Get-SshBanner'
        'Get-LdapRootDseName','Read-NtlmChallenge','Get-NtlmHostInfo','Get-RdpCertificateName'
        'Get-SnmpSysName','Read-SnmpSysNameResponse','Get-SshHostname'
        'Get-TtlGuess','Get-OsGuess','Resolve-HostIdentity','Invoke-TargetScan'
    )

    # ---- etapa 1: DNS em paralelo ----
    $sbDns = {
        param($item, $p)
        $d = Resolve-TargetAddress -HostName $item.Host -PreferIPv4:$p.PreferIPv4
        [pscustomobject]@{ Alvo = $item; Dns = $d }
    }
    $dnsResult = Invoke-InParallel -InputObject $alvos -ScriptBlock $sbDns `
        -FunctionNames @('Resolve-TargetAddress','Get-ErrorText') `
        -Parameters @{ PreferIPv4 = [bool]$Config.PreferIPv4 } `
        -ThrottleLimit $Config.ThrottleLimit -Activity 'Resolvendo DNS'

    # ---- monta a lista de trabalho e conta entradas por IP ----
    $trabalho = @()
    foreach ($d in $dnsResult) {
        if ($d.Dns.IPs -and $d.Dns.IPs.Count -gt 0) {
            foreach ($ip in $d.Dns.IPs) { $trabalho += [pscustomobject]@{ Alvo = $d.Alvo; Dns = $d.Dns; Ip = $ip } }
        } else {
            $trabalho += [pscustomobject]@{ Alvo = $d.Alvo; Dns = $d.Dns; Ip = $null }
        }
    }

    $contagemIp = @{}
    foreach ($t in $trabalho) {
        if ($t.Ip) {
            if (-not $contagemIp.ContainsKey($t.Ip)) { $contagemIp[$t.Ip] = @() }
            if ($contagemIp[$t.Ip] -notcontains $t.Alvo.Entrada) { $contagemIp[$t.Ip] += $t.Alvo.Entrada }
        }
    }
    Write-ScanLog -Message ('{0} par(es) alvo/IP a verificar' -f $trabalho.Count) -Path $log

    # ---- etapa 2 e 3: hostname e TLS em paralelo ----
    $sbScan = {
        param($item, $p)
        Invoke-TargetScan -Alvo $item.Alvo -Dns $item.Dns -Ip $item.Ip -Opcoes $p
    }
    $resultados = Invoke-InParallel -InputObject $trabalho -ScriptBlock $sbScan `
        -FunctionNames $funcoes -Parameters $opcoes `
        -ThrottleLimit $Config.ThrottleLimit -Activity 'Lendo certificados'

    foreach ($r in $resultados) {
        if ($r.IP -and $contagemIp.ContainsKey($r.IP)) {
            $r.EntradasNoMesmoIP = $contagemIp[$r.IP].Count
        } else {
            $r.EntradasNoMesmoIP = 0
        }
        if ($r.StatusTLS -eq 'FALHA' -or $r.StatusHostname -ne 'OK') {
            Write-ScanLog -Message ("{0} [{1}] TLS={2} hostname={3}" -f $r.Entrada, $r.IP, $r.DetalheTLS, $r.StatusHostname) -Level 'AVISO' -Path $log
        }
    }

    # ordena pelo arquivo de entrada, mantendo linhas do mesmo alvo juntas
    $ordem = @{}
    for ($i = 0; $i -lt $alvos.Count; $i++) { if (-not $ordem.ContainsKey($alvos[$i].Entrada)) { $ordem[$alvos[$i].Entrada] = $i } }
    $resultados = @($resultados | Sort-Object @{ E = { $ordem[$_.Entrada] } }, IP)

    Write-ScanLog -Message ('Fim do inventario; {0} linha(s)' -f $resultados.Count) -Path $log
    return $resultados
}

function Show-ResultSummary {
    <#
    .SYNOPSIS
        Tabela resumida no console. Os motivos longos ficam no CSV; aqui sao abreviados.
    .DESCRIPTION
        Format-Table -AutoSize nao imprime nada quando o host nao tem largura de buffer
        (execucao com -File, redirecionamento, tarefa agendada), porque BufferSize.Width vale
        -1. Passar por Out-String com largura explicita garante a saida nos dois casos.
    #>
    [CmdletBinding()]
    param([object[]]$Resultados, [int]$Width = 200)

    function Limitar([object]$Valor, [int]$Max) {
        $t = "$Valor"
        if ($t.Length -le $Max) { return $t }
        return $t.Substring(0, $Max - 1) + [char]0x2026
    }

    $tabela = $Resultados | ForEach-Object {
        [pscustomobject]@{
            Entrada       = Limitar $_.Entrada 34
            IP            = Limitar $_.IP 39
            Hostname      = Limitar $_.Hostname 28
            SOProvavel    = Limitar $_.SOProvavel 14
            ValidoAte     = if ($_.ValidoAte -match '^\d{4}-') { $_.ValidoAte } else { '-' }
            DiasRestantes = if ("$($_.DiasRestantes)" -match '^-?\d+$') { $_.DiasRestantes } else { '-' }
            Situacao      = Limitar $_.Situacao 18
        }
    }
    ($tabela | Format-Table -AutoSize | Out-String -Width $Width).TrimEnd() | Write-Host
}

# Guarda de dot-source: ao ser carregado com '.', o script apenas define as funcoes,
# o que permite que os testes Pester exercitem as funcoes puras sem executar o scan.
if ($MyInvocation.InvocationName -ne '.') {
    $config = @{
        InputFile = $InputFile; Targets = $Targets; DefaultPort = $DefaultPort
        AlternatePorts = $AlternatePorts; PreferIPv4 = $PreferIPv4; StartTlsMode = $StartTlsMode
        SkipNetBios = $SkipNetBios; SkipPtr = $SkipPtr; UseSmb = $UseSmb; UseRdp = $UseRdp
        UseSmtpBanner = $UseSmtpBanner; UseLdap = $UseLdap; UseSshBanner = $UseSshBanner
        SnmpCommunity = $SnmpCommunity; SshUser = $SshUser; SshKeyPath = $SshKeyPath
        OpenSslPath = $OpenSslPath; ThrottleLimit = $ThrottleLimit
        TcpTimeoutMs = $TcpTimeoutMs; TlsTimeoutMs = $TlsTimeoutMs
        HostnameTimeoutMs = $HostnameTimeoutMs; WarningDays = $WarningDays
        LogFile = $LogFile; CompareSni = $CompareSni
    }

    $resultados = Invoke-CertInventory -Config $config

    if ($OutputCsv) {
        Export-ResultCsv -Resultados $resultados -Path $OutputCsv
        Write-Host ("CSV salvo em: {0}" -f $OutputCsv) -ForegroundColor Green
    }
    if ($OutputJson) {
        $json = $resultados | ConvertTo-Json -Depth 4
        [System.IO.File]::WriteAllText($OutputJson, $json, (New-Object System.Text.UTF8Encoding($true)))
        Write-Host ("JSON salvo em: {0}" -f $OutputJson) -ForegroundColor Green
    }

    if ($PassThru) { $resultados } else { Show-ResultSummary -Resultados $resultados }
}
#endregion
