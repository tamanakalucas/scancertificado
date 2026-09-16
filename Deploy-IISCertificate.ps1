<#
.SYNOPSIS
    Instala um certificado PFX em servidores Windows remotos e refaz os bindings HTTPS do IIS
    preservando as configuracoes existentes.

.DESCRIPTION
    Executa de uma estacao central sobre uma lista de servidores, via PSRemoting. Para cada
    servidor:

        1. Importa o PFX em LocalMachine\My. O arquivo NAO e gravado em disco no servidor: os
           bytes vao pela sessao e o certificado e montado em memoria.
        2. Localiza os bindings HTTPS candidatos.
        3. Refaz cada binding trocando apenas CertificateHash e CertificateStoreName.
        4. Confere no HTTP.SYS se a troca realmente valeu, e corrige com netsh se nao valeu.

    O QUE E PRESERVADO
        sslFlags (SNI, Central Certificate Store, DisableHTTP2, DisableOCSPStapling,
        DisableQUIC, DisableTLS13, DisableLegacyTLS), IP, porta, hostname, o binding em si e a
        ordem dos bindings. O script escreve dois campos do binding e mais nada.

    SELECAO CONSERVADORA DOS BINDINGS
        Sem filtro explicito, o script so mexe em binding cujo hostname seja coberto pelos
        nomes do certificado novo (com casamento de curinga correto) e que hoje aponte para
        outro certificado. Nao toca em:
          - binding sem hostname, a menos que -IncludeEmptyHostName seja informado, porque nao
            ha como saber se o curinga e apropriado para um binding coringa;
          - binding com Central Certificate Store, cujo certificado vem do compartilhamento;
          - binding que ja aponta para o certificado novo.

    ENSAIO OBRIGATORIO NA PRIMEIRA VEZ
        Sem -Apply o script roda em modo ensaio: conecta, importa nada, e mostra exatamente
        quais bindings mudariam em quais servidores. Use -Apply para efetivar. -WhatIf e
        -Confirm tambem funcionam.

    ROLLBACK
        Antes de qualquer alteracao, o estado atual de cada binding vai para um arquivo JSON
        (-BackupPath). Para desfazer:  .\Deploy-IISCertificate.ps1 -Rollback <arquivo.json>
        O certificado antigo nao e removido, justamente para o rollback funcionar.

.PARAMETER PfxPath
    Caminho do .pfx na estacao onde o script roda.

.PARAMETER PfxPassword
    Senha do PFX como SecureString. Prefira -AskPfxPassword: uma senha digitada direto na linha
    de comando fica em texto puro no ConsoleHost_history.txt do PSReadLine.

.PARAMETER AskPfxPassword
    Pergunta a senha do PFX sem eco e sem passar pela linha de comando.

.PARAMETER PfxPasswordFile
    Arquivo com a senha protegida por DPAPI, para execucao desatendida (tarefa agendada, SCCM).
    -PfxPassword nao serve nesses casos: ao chamar 'powershell.exe -File', a linha de comando
    entrega texto e nada se converte em SecureString.

    Gere o arquivo UMA VEZ, na mesma conta e na mesma maquina que vao rodar o deploy:

        Read-Host 'Senha do PFX' -AsSecureString | ConvertFrom-SecureString |
            Set-Content .\senha-pfx.txt

    A protecao e do DPAPI: o arquivo so pode ser lido por aquela conta naquela maquina. Ainda
    assim, trate-o como segredo e restrinja a ACL.

.PARAMETER ComputerName
    Servidores de destino.

.PARAMETER ComputerListFile
    Arquivo com um servidor por linha. Linhas vazias e iniciadas por # sao ignoradas.

.PARAMETER Credential
    Credencial administrativa nos servidores. Sem ela, usa a identidade da sessao atual.

.PARAMETER UseSsl
    Usa WinRM sobre HTTPS (porta 5986).

.PARAMETER SiteName
    Limita a troca aos sites informados.

.PARAMETER HostNameFilter
    Limita a troca aos bindings cujo hostname casa com este padrao (curingas do PowerShell).

.PARAMETER ReplaceThumbprint
    Em vez de casar por hostname, troca exatamente os bindings que hoje usam este thumbprint.
    E a forma mais previsivel quando voce sabe qual certificado esta vencendo.

.PARAMETER IncludeEmptyHostName
    Permite trocar bindings sem hostname. Em binding sem hostname e sem SNI o certificado vale
    para todo o IP:porta, entao a troca afeta todos os sites que compartilham esse IP:porta.

.PARAMETER Apply
    Efetiva as mudancas. Sem este parametro o script apenas relata o que faria.

.PARAMETER Exportable
    Importa a chave privada como exportavel. Desligado por padrao: um curinga replicado em
    varios servidores nao deveria poder ser reexportado de cada um deles.

.PARAMETER BackupPath
    Pasta onde gravar o JSON de rollback. Padrao: a pasta atual.

.PARAMETER Rollback
    Caminho de um JSON gerado por uma execucao anterior. Restaura os bindings daquele estado.

.PARAMETER ThrottleLimit
    Servidores tratados em paralelo. Padrao 8.

.PARAMETER ReportCsv
    Caminho do CSV de resultado, com ';' e UTF-8 com BOM.

.PARAMETER LogFile
    Log opcional em arquivo.

.EXAMPLE
    .\Deploy-IISCertificate.ps1 -PfxPath .\wildcard.pfx -AskPfxPassword `
        -ComputerListFile .\servidores.txt

    Ensaio: mostra o que mudaria, sem alterar nada. Rode sempre assim da primeira vez.

.EXAMPLE
    .\Deploy-IISCertificate.ps1 -PfxPath .\wildcard.pfx -AskPfxPassword `
        -ComputerListFile .\servidores.txt -Apply -ReportCsv .\deploy.csv

    Efetiva, gravando o JSON de rollback e o relatorio.

.EXAMPLE
    .\Deploy-IISCertificate.ps1 -PfxPath .\wildcard.pfx -AskPfxPassword `
        -ComputerName WEB01,WEB02 -ReplaceThumbprint A1B2C3... -Apply

    Troca exatamente os bindings que hoje usam o certificado vencendo.

.EXAMPLE
    .\Deploy-IISCertificate.ps1 -Rollback .\rollback-20260916-140233.json

    Desfaz, devolvendo cada binding ao certificado que tinha antes.

.EXAMPLE
    .\Deploy-IISCertificate.ps1 -PfxPath \\fs01\certs\wildcard.pfx `
        -PfxPasswordFile C:\deploy\senha-pfx.txt -ComputerListFile C:\deploy\servidores.txt -Apply

    Execucao desatendida, sem senha na linha de comando e sem prompt.

.NOTES
    Requisitos: PSRemoting habilitado nos destinos, conta administrativa, IIS 7.5+.
    Usa Microsoft.Web.Administration, que acompanha o IIS -- nao exige o modulo
    WebAdministration nem nada da PSGallery.

    A senha do PFX trafega como SecureString pela sessao do PSRemoting, que e criptografada com
    Kerberos ou HTTPS. NAO use autenticacao Basic sobre HTTP: ali a senha vai em claro.
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High', DefaultParameterSetName = 'Deploy')]
param(
    [Parameter(ParameterSetName = 'Deploy')]
    [string]$PfxPath,

    [Parameter(ParameterSetName = 'Deploy')]
    [securestring]$PfxPassword,

    [Parameter(ParameterSetName = 'Deploy')]
    [switch]$AskPfxPassword,

    [Parameter(ParameterSetName = 'Deploy')]
    [string]$PfxPasswordFile,

    [Parameter(ParameterSetName = 'Deploy')]
    [string[]]$ComputerName,

    [Parameter(ParameterSetName = 'Deploy')]
    [string]$ComputerListFile,

    [pscredential]$Credential,
    [switch]$UseSsl,

    [Parameter(ParameterSetName = 'Deploy')]
    [string[]]$SiteName,

    [Parameter(ParameterSetName = 'Deploy')]
    [string]$HostNameFilter,

    [Parameter(ParameterSetName = 'Deploy')]
    [string]$ReplaceThumbprint,

    [Parameter(ParameterSetName = 'Deploy')]
    [switch]$IncludeEmptyHostName,

    [Parameter(ParameterSetName = 'Deploy')]
    [switch]$Apply,

    [Parameter(ParameterSetName = 'Deploy')]
    [switch]$Exportable,

    [Parameter(ParameterSetName = 'Deploy')]
    [string]$BackupPath = '.',

    [Parameter(ParameterSetName = 'Rollback', Mandatory = $true)]
    [string]$Rollback,

    [int]$ThrottleLimit = 8,
    [string]$ReportCsv,
    [string]$LogFile
)

$ErrorActionPreference = 'Stop'

#region ---------------------------------------------------------------- Funcoes puras
function Write-DeployLog {
    [CmdletBinding()]
    param([string]$Message, [ValidateSet('INFO','AVISO','ERRO')][string]$Level = 'INFO', [string]$Path)
    $linha = '{0} [{1}] {2}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level, $Message
    Write-Verbose $linha
    if ($Path) {
        try {
            $sw = New-Object System.IO.StreamWriter($Path, $true, (New-Object System.Text.UTF8Encoding($true)))
            try { $sw.WriteLine($linha) } finally { $sw.Dispose() }
        } catch { Write-Verbose ("Falha ao gravar log: " + $_.Exception.Message) }
    }
}

function Get-CertificateSubjectNames {
    <#
    .SYNOPSIS
        Devolve os nomes que o certificado cobre: CN do subject e todas as SANs de DNS.
    .DESCRIPTION
        As SANs saem por parsing ASN.1 da extensao 2.5.29.17, nao por Format(), cujo texto e
        localizado (em Windows pt-BR vira "Nome DNS=") e muda entre plataformas.
    #>
    [CmdletBinding()]
    param([System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate)

    $nomes = New-Object System.Collections.Generic.List[string]
    if ($null -eq $Certificate) { return ,@() }

    try {
        $cn = $Certificate.GetNameInfo([System.Security.Cryptography.X509Certificates.X509NameType]::SimpleName, $false)
        if ($cn) { [void]$nomes.Add($cn) }
    } catch {
        if ($Certificate.Subject -match 'CN=([^,]+)') { [void]$nomes.Add($Matches[1].Trim()) }
    }

    $ext = $Certificate.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.17' } | Select-Object -First 1
    if ($ext) {
        $raw = $ext.RawData
        if ($raw -and $raw.Length -ge 2 -and $raw[0] -eq 0x30) {
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
    }

    return ,@($nomes | Where-Object { $_ } | Select-Object -Unique)
}

function Test-HostNameMatchesCertificate {
    <#
    .SYNOPSIS
        Diz se um hostname e coberto por um dos nomes do certificado, seguindo a RFC 6125.
    .DESCRIPTION
        O curinga cobre exatamente UM rotulo, e so o rotulo mais a esquerda:
            *.energisa.com.br  cobre  app.energisa.com.br
            *.energisa.com.br  NAO cobre  energisa.com.br        (falta o rotulo)
            *.energisa.com.br  NAO cobre  a.b.energisa.com.br    (sobra rotulo)
        Errar isso num deploy significa trocar o certificado de um site que o curinga nao
        cobre, e derrubar o site com erro de nome.
    #>
    [CmdletBinding()]
    param([string]$HostName, [string[]]$CertificateNames)

    if ([string]::IsNullOrWhiteSpace($HostName)) { return $false }
    if (-not $CertificateNames) { return $false }

    $alvo = $HostName.Trim().TrimEnd('.').ToLowerInvariant()
    if (-not $alvo) { return $false }

    foreach ($bruto in $CertificateNames) {
        if ([string]::IsNullOrWhiteSpace($bruto)) { continue }
        $nome = $bruto.Trim().TrimEnd('.').ToLowerInvariant()

        if ($nome -eq $alvo) { return $true }
        if ($nome -notlike '*`**') { continue }

        # curinga valido: um unico '*', sozinho no rotulo mais a esquerda
        $partesNome = $nome.Split('.')
        if ($partesNome[0] -ne '*') { continue }
        if (($nome.ToCharArray() | Where-Object { $_ -eq '*' }).Count -ne 1) { continue }
        if ($partesNome.Count -lt 3) { continue }   # '*.br' e curinga amplo demais; recusar

        $partesAlvo = $alvo.Split('.')
        if ($partesAlvo.Count -ne $partesNome.Count) { continue }
        if ($partesAlvo[0] -eq '') { continue }

        $sufixoNome = ($partesNome[1..($partesNome.Count - 1)]) -join '.'
        $sufixoAlvo = ($partesAlvo[1..($partesAlvo.Count - 1)]) -join '.'
        if ($sufixoNome -eq $sufixoAlvo) { return $true }
    }
    return $false
}

function ConvertFrom-SslFlags {
    <#
    .SYNOPSIS
        Traduz o valor numerico de sslFlags para os nomes das opcoes ligadas.
    .DESCRIPTION
        Sao exatamente estas opcoes que precisam sobreviver a troca de certificado.
    #>
    [CmdletBinding()]
    param([int]$Value)

    if ($Value -eq 0) { return 'nenhuma' }
    # Pares em array, e nao em [ordered]@{}: naquele tipo o indexador com [int] resolve por
    # POSICAO e nao por chave, o que devolveria silenciosamente o nome da opcao vizinha.
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

function Select-BindingAction {
    <#
    .SYNOPSIS
        Decide, para um binding, se ele deve ser trocado -- e registra o porque.
    .DESCRIPTION
        Funcao pura: recebe a descricao do binding e devolve a decisao com justificativa. Toda
        a politica conservadora de selecao vive aqui, o que a torna testavel sem IIS.
    #>
    [CmdletBinding()]
    param(
        [pscustomobject]$Binding,       # Site, HostName, Ip, Porta, Thumbprint, SslFlags
        [string[]]$CertificateNames,
        [string]$NewThumbprint,
        [string[]]$SiteName,
        [string]$HostNameFilter,
        [string]$ReplaceThumbprint,
        [bool]$IncludeEmptyHostName = $false
    )

    $r = [ordered]@{ Trocar = $false; Motivo = '' }

    if ($Binding.Thumbprint -and $NewThumbprint -and
        ($Binding.Thumbprint -replace '\s','') -ieq ($NewThumbprint -replace '\s','')) {
        $r.Motivo = 'ja usa o certificado novo'
        return [pscustomobject]$r
    }

    if (($Binding.SslFlags -band 2) -ne 0) {
        $r.Motivo = 'Central Certificate Store: o certificado vem do compartilhamento, nao do store local'
        return [pscustomobject]$r
    }

    if ($SiteName -and ($SiteName -notcontains $Binding.Site)) {
        $r.Motivo = 'site fora de -SiteName'
        return [pscustomobject]$r
    }

    if ($ReplaceThumbprint) {
        if ($Binding.Thumbprint -and ($Binding.Thumbprint -replace '\s','') -ieq ($ReplaceThumbprint -replace '\s','')) {
            $r.Trocar = $true
            $r.Motivo = 'usa o thumbprint informado em -ReplaceThumbprint'
        } else {
            $r.Motivo = 'nao usa o thumbprint informado em -ReplaceThumbprint'
        }
        return [pscustomobject]$r
    }

    if ([string]::IsNullOrWhiteSpace($Binding.HostName)) {
        if ($IncludeEmptyHostName) {
            $r.Trocar = $true
            $r.Motivo = 'binding sem hostname, incluido por -IncludeEmptyHostName'
        } else {
            $r.Motivo = 'binding sem hostname: nao da para saber se o curinga se aplica (use -IncludeEmptyHostName)'
        }
        return [pscustomobject]$r
    }

    if ($HostNameFilter -and ($Binding.HostName -notlike $HostNameFilter)) {
        $r.Motivo = 'hostname fora de -HostNameFilter'
        return [pscustomobject]$r
    }

    if (-not (Test-HostNameMatchesCertificate -HostName $Binding.HostName -CertificateNames $CertificateNames)) {
        $r.Motivo = ('o certificado novo nao cobre {0} (nomes: {1})' -f $Binding.HostName, ($CertificateNames -join ', '))
        return [pscustomobject]$r
    }

    $r.Trocar = $true
    $r.Motivo = ('o certificado novo cobre {0}' -f $Binding.HostName)
    return [pscustomobject]$r
}

function Get-SharedBindingWarning {
    <#
    .SYNOPSIS
        Avisa quando um binding sem SNI divide IP:porta com outros sites.
    .DESCRIPTION
        Sem SNI o certificado e registrado no HTTP.SYS por IP:porta, nao por site. Trocar um
        troca para todos os sites que compartilham aquele IP:porta -- inclusive os que o
        curinga nao cobre.
    #>
    [CmdletBinding()]
    param([pscustomobject]$Binding, [pscustomobject[]]$TodosOsBindings)

    if (($Binding.SslFlags -band 1) -ne 0) { return '' }   # com SNI o registro e por hostname
    $chave = '{0}:{1}' -f $Binding.Ip, $Binding.Porta
    $vizinhos = @($TodosOsBindings | Where-Object {
        ('{0}:{1}' -f $_.Ip, $_.Porta) -eq $chave -and
        ($_.SslFlags -band 1) -eq 0 -and
        ($_.Site -ne $Binding.Site -or $_.HostName -ne $Binding.HostName)
    })
    if ($vizinhos.Count -eq 0) { return '' }
    $sites = @($vizinhos | ForEach-Object { $_.Site } | Select-Object -Unique)
    return ('ATENCAO: binding sem SNI em {0}; o certificado vale para todo o IP:porta e a troca afeta tambem: {1}' -f $chave, ($sites -join ', '))
}
#endregion

#region ---------------------------------------------------------------- Leitura do HTTP.SYS
function Read-NetshSslCert {
    <#
    .SYNOPSIS
        Interpreta a saida de 'netsh http show sslcert' sem depender do idioma do Windows.
    .DESCRIPTION
        Os rotulos da saida sao traduzidos ("Hash do Certificado" em pt-BR), entao procurar por
        rotulo quebra fora do en-US. O que nao muda e o formato dos VALORES: o par
        endereco:porta e o thumbprint de 40 digitos hexadecimais. E por eles que este parser
        se guia.
    #>
    [CmdletBinding()]
    param([string]$Text)

    $saida = @()
    if ([string]::IsNullOrWhiteSpace($Text)) { return ,$saida }

    # blocos separados por linha em branco
    $blocos = [regex]::Split($Text, '(\r?\n){2,}')
    foreach ($bloco in $blocos) {
        if ([string]::IsNullOrWhiteSpace($bloco)) { continue }

        $hash = $null
        $m = [regex]::Match($bloco, '(?<![0-9A-Fa-f])([0-9A-Fa-f]{40})(?![0-9A-Fa-f])')
        if ($m.Success) { $hash = $m.Groups[1].Value.ToUpperInvariant() }

        # primeiro valor no formato <algo>:<porta> apos ':' de rotulo
        $endereco = $null
        foreach ($linha in ($bloco -split '\r?\n')) {
            $mm = [regex]::Match($linha, ':\s+(?<v>(\[[0-9A-Fa-f:]+\]|\d{1,3}(\.\d{1,3}){3}|[A-Za-z0-9\*\.\-_]+)):(?<p>\d{1,5})\s*$')
            if ($mm.Success) { $endereco = ('{0}:{1}' -f $mm.Groups['v'].Value, $mm.Groups['p'].Value); break }
        }

        if ($endereco -or $hash) {
            $saida += [pscustomobject]@{ Endereco = $endereco; Thumbprint = $hash }
        }
    }
    return ,$saida
}

function Get-ThumbprintFromBytes {
    [CmdletBinding()]
    param([byte[]]$Bytes)
    if (-not $Bytes -or $Bytes.Length -eq 0) { return '' }
    return (($Bytes | ForEach-Object { $_.ToString('X2') }) -join '')
}
#endregion

#region ---------------------------------------------------------------- Corpo remoto
# Executado dentro da sessao do servidor de destino. Recebe apenas dados; as funcoes auxiliares
# sao injetadas como texto por New-RemoteScriptBlock, para nao duplicar codigo.
$script:FuncoesRemotas = @(
    'Test-HostNameMatchesCertificate','ConvertFrom-SslFlags','Select-BindingAction',
    'Get-SharedBindingWarning','Read-NetshSslCert','Get-ThumbprintFromBytes',
    'Get-CertificateSubjectNames'
)

# O param NAO fica aqui: ele precisa ser a primeira instrucao do scriptblock, e
# New-RemoteScriptBlock o emite antes das definicoes de funcao.
$script:CorpoRemoto = @'

$resultado = [ordered]@{
    Servidor      = $env:COMPUTERNAME
    Status        = 'OK'
    Erro          = ''
    CertImportado = 'nao'
    Bindings      = @()
    Avisos        = @()
}

try {
    $dll = Join-Path $env:SystemRoot 'system32\inetsrv\Microsoft.Web.Administration.dll'
    if (-not (Test-Path -LiteralPath $dll)) {
        $resultado.Status = 'SEM IIS'
        $resultado.Erro   = 'Microsoft.Web.Administration.dll nao encontrado; o IIS nao parece instalado'
        return [pscustomobject]$resultado
    }
    Add-Type -Path $dll -ErrorAction Stop

    # ---------------- 1. importar o PFX (so quando for efetivar) ----------------
    $lojaMy = New-Object System.Security.Cryptography.X509Certificates.X509Store('My','LocalMachine')
    $lojaMy.Open('ReadOnly')
    $jaExiste = @($lojaMy.Certificates | Where-Object { $_.Thumbprint -ieq $Ctx.NewThumbprint }).Count -gt 0
    $lojaMy.Close()

    if ($jaExiste) {
        $resultado.CertImportado = 'ja estava instalado'
    } elseif ($Ctx.Apply) {
        $flags = [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::MachineKeySet -bor `
                 [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::PersistKeySet
        if ($Ctx.Exportable) {
            $flags = $flags -bor [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable
        }

        # A colecao traz a cadeia inteira do PFX. A folha vai para My; os intermediarios vao
        # para CA, senao o servidor serve cadeia incompleta e o cliente reclama.
        $colecao = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2Collection
        $colecao.Import($Ctx.PfxBytes, $Senha, $flags)

        $folha = $null
        foreach ($c in $colecao) { if ($c.HasPrivateKey) { $folha = $c; break } }
        if (-not $folha) { throw 'o PFX nao contem chave privada' }
        if ($folha.Thumbprint -ine $Ctx.NewThumbprint) {
            throw ('thumbprint divergente: a estacao calculou {0} e o servidor leu {1}' -f $Ctx.NewThumbprint, $folha.Thumbprint)
        }

        $st = New-Object System.Security.Cryptography.X509Certificates.X509Store('My','LocalMachine')
        $st.Open('ReadWrite'); $st.Add($folha); $st.Close()
        $resultado.CertImportado = 'importado'

        foreach ($c in $colecao) {
            if ($c.Thumbprint -ieq $folha.Thumbprint) { continue }
            if ($c.Subject -eq $c.Issuer) {
                # raiz autoassinada: instalar em Root e uma decisao de confianca, nao de deploy
                $resultado.Avisos += ('CA raiz "{0}" presente no PFX e NAO foi instalada; instale-a por processo proprio se necessario' -f $c.Subject)
                continue
            }
            $stCA = New-Object System.Security.Cryptography.X509Certificates.X509Store('CA','LocalMachine')
            $stCA.Open('ReadWrite')
            if (-not (@($stCA.Certificates | Where-Object { $_.Thumbprint -ieq $c.Thumbprint }).Count -gt 0)) {
                $stCA.Add($c)
                $resultado.Avisos += ('intermediaria "{0}" instalada em LocalMachine\CA' -f $c.Subject)
            }
            $stCA.Close()
        }
    }

    # ---------------- 2. enumerar bindings ----------------
    $sm = New-Object Microsoft.Web.Administration.ServerManager
    $todos = @()
    foreach ($site in $sm.Sites) {
        foreach ($b in $site.Bindings) {
            if ("$($b.Protocol)" -ne 'https') { continue }
            $partes = "$($b.BindingInformation)".Split(':')
            $sslFlags = 0
            try { $sslFlags = [int]$b['sslFlags'] } catch { $sslFlags = 0 }
            $todos += [pscustomobject]@{
                Site       = $site.Name
                Ip         = $partes[0]
                Porta      = if ($partes.Count -gt 1) { $partes[1] } else { '' }
                HostName   = if ($partes.Count -gt 2) { $partes[2] } else { '' }
                Thumbprint = (Get-ThumbprintFromBytes -Bytes $b.CertificateHash)
                Loja       = "$($b.CertificateStoreName)"
                SslFlags   = $sslFlags
                BindingInfo= "$($b.BindingInformation)"
                SiteEstado = "$($site.State)"
            }
        }
    }

    if ($todos.Count -eq 0) {
        $resultado.Avisos += 'nenhum binding https encontrado neste servidor'
    }

    # ---------------- 3. decidir e aplicar ----------------
    foreach ($bi in $todos) {
        $decisao = Select-BindingAction -Binding $bi -CertificateNames $Ctx.CertNames `
                        -NewThumbprint $Ctx.NewThumbprint -SiteName $Ctx.SiteName `
                        -HostNameFilter $Ctx.HostNameFilter -ReplaceThumbprint $Ctx.ReplaceThumbprint `
                        -IncludeEmptyHostName ([bool]$Ctx.IncludeEmptyHostName)

        $linha = [ordered]@{
            Servidor        = $env:COMPUTERNAME
            Site            = $bi.Site
            BindingInfo     = $bi.BindingInfo
            HostName        = if ($bi.HostName) { $bi.HostName } else { '(sem hostname)' }
            Ip              = $bi.Ip
            Porta           = $bi.Porta
            SslFlags        = $bi.SslFlags
            SslFlagsTexto   = (ConvertFrom-SslFlags -Value $bi.SslFlags)
            ThumbprintAntes = if ($bi.Thumbprint) { $bi.Thumbprint } else { '(sem certificado)' }
            LojaAntes       = if ($bi.Loja) { $bi.Loja } else { '(vazia)' }
            Acao            = ''
            Motivo          = $decisao.Motivo
            ThumbprintDepois= ''
            SslFlagsDepois  = ''
            Verificacao     = ''
            Aviso           = ''
        }

        $aviso = Get-SharedBindingWarning -Binding $bi -TodosOsBindings $todos
        if ($aviso) { $linha.Aviso = $aviso }

        if (-not $decisao.Trocar) {
            $linha.Acao = 'ignorado'
            $linha.ThumbprintDepois = $linha.ThumbprintAntes
            $linha.SslFlagsDepois   = $linha.SslFlagsTexto
            $linha.Verificacao      = 'nao aplicavel: binding nao alterado'
            $resultado.Bindings += [pscustomobject]$linha
            continue
        }

        if (-not $Ctx.Apply) {
            $linha.Acao = 'TROCARIA (ensaio)'
            $linha.ThumbprintDepois = $Ctx.NewThumbprint
            $linha.SslFlagsDepois   = $linha.SslFlagsTexto + ' (preservado)'
            $linha.Verificacao      = 'nao aplicavel: ensaio'
            $resultado.Bindings += [pscustomobject]$linha
            continue
        }

        try {
            $alvo = $null
            foreach ($site in $sm.Sites) {
                if ($site.Name -ne $bi.Site) { continue }
                foreach ($b in $site.Bindings) {
                    if ("$($b.BindingInformation)" -eq $bi.BindingInfo -and "$($b.Protocol)" -eq 'https') { $alvo = $b; break }
                }
            }
            if (-not $alvo) { throw 'binding nao encontrado na releitura' }

            $flagsAntes = 0
            try { $flagsAntes = [int]$alvo['sslFlags'] } catch { }

            # Unica escrita: o hash e a loja. sslFlags, IP, porta e hostname nao sao tocados.
            $bytesNovos = New-Object byte[] ($Ctx.NewThumbprint.Length / 2)
            for ($i = 0; $i -lt $bytesNovos.Length; $i++) {
                $bytesNovos[$i] = [Convert]::ToByte($Ctx.NewThumbprint.Substring($i * 2, 2), 16)
            }
            $alvo.CertificateHash      = $bytesNovos
            $alvo.CertificateStoreName = $Ctx.StoreName
            $sm.CommitChanges()

            $flagsDepois = 0
            $smV = New-Object Microsoft.Web.Administration.ServerManager
            $confHash = ''
            foreach ($site in $smV.Sites) {
                if ($site.Name -ne $bi.Site) { continue }
                foreach ($b in $site.Bindings) {
                    if ("$($b.BindingInformation)" -eq $bi.BindingInfo -and "$($b.Protocol)" -eq 'https') {
                        $confHash = Get-ThumbprintFromBytes -Bytes $b.CertificateHash
                        try { $flagsDepois = [int]$b['sslFlags'] } catch { }
                    }
                }
            }
            $smV.Dispose()

            $linha.ThumbprintDepois = $confHash
            $linha.SslFlagsDepois   = ConvertFrom-SslFlags -Value $flagsDepois

            if ($flagsDepois -ne $flagsAntes) {
                $linha.Aviso = (($linha.Aviso, ('sslFlags mudou de {0} para {1}' -f $flagsAntes, $flagsDepois)) | Where-Object { $_ }) -join ' | '
            }

            # Conferir no HTTP.SYS: a configuracao do IIS e o registro do HTTP.SYS podem
            # divergir, e quem atende o cliente e o HTTP.SYS.
            $chave = if (($bi.SslFlags -band 1) -ne 0 -and $bi.HostName) {
                '{0}:{1}' -f $bi.HostName, $bi.Porta
            } else {
                '{0}:{1}' -f $bi.Ip, $bi.Porta
            }
            $netsh = (& netsh http show sslcert 2>&1 | Out-String)
            $entradas = Read-NetshSslCert -Text $netsh
            $entrada = $entradas | Where-Object { $_.Endereco -ieq $chave } | Select-Object -First 1

            if ($confHash -ieq $Ctx.NewThumbprint -and $entrada -and $entrada.Thumbprint -ieq $Ctx.NewThumbprint) {
                $linha.Acao = 'trocado'
                $linha.Verificacao = ('confirmado na configuracao do IIS e no HTTP.SYS ({0})' -f $chave)
            } elseif ($confHash -ieq $Ctx.NewThumbprint -and -not $entrada) {
                $linha.Acao = 'trocado'
                $linha.Verificacao = ('confirmado no IIS; entrada {0} nao localizada no HTTP.SYS (normal quando o site esta parado)' -f $chave)
            } elseif ($confHash -ieq $Ctx.NewThumbprint) {
                $linha.Acao = 'trocado com divergencia'
                $linha.Verificacao = ('IIS atualizado, mas o HTTP.SYS em {0} ainda aponta para {1}' -f $chave, $entrada.Thumbprint)
            } else {
                $linha.Acao = 'FALHOU'
                $linha.Verificacao = ('apos o commit o binding ainda aponta para {0}' -f $confHash)
            }
        } catch {
            $ex = $_.Exception; while ($ex.InnerException) { $ex = $ex.InnerException }
            $linha.Acao = 'FALHOU'
            $linha.Verificacao = ($ex.Message -replace '\s+',' ')
        }
        $resultado.Bindings += [pscustomobject]$linha
    }

    $sm.Dispose()
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
        Monta o scriptblock remoto injetando as funcoes auxiliares como texto.
    .DESCRIPTION
        A sessao remota nao enxerga as funcoes desta estacao. Injetar as definicoes evita
        manter duas copias da mesma logica -- uma testavel aqui e outra colada la dentro.
    #>
    [CmdletBinding()]
    param()
    $defs = foreach ($n in $script:FuncoesRemotas) {
        $cmd = Get-Command -Name $n -CommandType Function -ErrorAction Stop
        "function $n {`r`n" + $cmd.Definition + "`r`n}"
    }

    # param() TEM de ser a primeira instrucao do scriptblock. Vindo depois de qualquer outra
    # coisa -- uma definicao de funcao, por exemplo -- o PowerShell o interpreta como chamada
    # de um comando chamado 'param', os argumentos nunca sao vinculados e o bloco remoto roda
    # inteiro com as variaveis nulas. A senha vai como parametro proprio, e nao dentro de
    # $Ctx, porque SecureString tem tratamento dedicado no serializador do PSRemoting.
    $texto = @(
        'param($Ctx, $Senha)'
        ''
        ($defs -join "`r`n`r`n")
        ''
        $script:CorpoRemoto
    ) -join "`r`n"

    $sb = [scriptblock]::Create($texto)
    if ($null -eq $sb.Ast.ParamBlock) {
        throw 'Falha ao montar o bloco remoto: o param() nao ficou como primeira instrucao.'
    }
    return $sb
}
#endregion

#region ---------------------------------------------------------------- Rollback remoto
$script:CorpoRollback = @'
param($Itens)

$resultado = [ordered]@{ Servidor = $env:COMPUTERNAME; Status = 'OK'; Erro = ''; Bindings = @() }
try {
    $dll = Join-Path $env:SystemRoot 'system32\inetsrv\Microsoft.Web.Administration.dll'
    Add-Type -Path $dll -ErrorAction Stop
    $sm = New-Object Microsoft.Web.Administration.ServerManager

    foreach ($it in $Itens) {
        $linha = [ordered]@{
            Servidor = $env:COMPUTERNAME; Site = $it.Site; BindingInfo = $it.BindingInfo
            Acao = ''; Detalhe = ''
        }
        try {
            if (-not $it.ThumbprintAntes -or $it.ThumbprintAntes -notmatch '^[0-9A-Fa-f]{40}$') {
                $linha.Acao = 'ignorado'
                $linha.Detalhe = ('estado anterior sem thumbprint utilizavel: {0}' -f $it.ThumbprintAntes)
                $resultado.Bindings += [pscustomobject]$linha
                continue
            }
            $alvo = $null
            foreach ($site in $sm.Sites) {
                if ($site.Name -ne $it.Site) { continue }
                foreach ($b in $site.Bindings) {
                    if ("$($b.BindingInformation)" -eq $it.BindingInfo -and "$($b.Protocol)" -eq 'https') { $alvo = $b; break }
                }
            }
            if (-not $alvo) { throw 'binding nao encontrado' }

            $bytes = New-Object byte[] 20
            for ($i = 0; $i -lt 20; $i++) { $bytes[$i] = [Convert]::ToByte($it.ThumbprintAntes.Substring($i * 2, 2), 16) }
            $alvo.CertificateHash = $bytes
            $loja = if ($it.LojaAntes -and $it.LojaAntes -ne '(vazia)') { $it.LojaAntes } else { 'My' }
            $alvo.CertificateStoreName = $loja
            $sm.CommitChanges()

            $linha.Acao = 'restaurado'
            $linha.Detalhe = ('voltou para {0} na loja {1}' -f $it.ThumbprintAntes, $loja)
        } catch {
            $ex = $_.Exception; while ($ex.InnerException) { $ex = $ex.InnerException }
            $linha.Acao = 'FALHOU'
            $linha.Detalhe = ($ex.Message -replace '\s+',' ')
        }
        $resultado.Bindings += [pscustomobject]$linha
    }
    $sm.Dispose()
} catch {
    $ex = $_.Exception; while ($ex.InnerException) { $ex = $ex.InnerException }
    $resultado.Status = 'ERRO'; $resultado.Erro = ($ex.Message -replace '\s+',' ')
}
return [pscustomobject]$resultado
'@
#endregion

#region ---------------------------------------------------------------- Saida
function Export-DeployCsv {
    [CmdletBinding()]
    param([object[]]$Linhas, [string]$Path)
    $texto = $Linhas | ConvertTo-Csv -NoTypeInformation -Delimiter ';'
    [System.IO.File]::WriteAllLines($Path, $texto, (New-Object System.Text.UTF8Encoding($true)))
}

function Show-DeployReport {
    [CmdletBinding()]
    param([object[]]$Linhas, [bool]$Ensaio)

    if (-not $Linhas -or $Linhas.Count -eq 0) {
        Write-Host 'Nenhum binding https nos servidores que RESPONDERAM (veja acima quais nao responderam).' -ForegroundColor Yellow
        return
    }

    function Cortar([object]$V, [int]$N) {
        $t = "$V"; if ($t.Length -le $N) { return $t }
        return $t.Substring(0, $N - 1) + [char]0x2026
    }

    $tab = $Linhas | ForEach-Object {
        [pscustomobject]@{
            Servidor = Cortar $_.Servidor 16
            Site     = Cortar $_.Site 22
            HostName = Cortar $_.HostName 30
            SslFlags = Cortar $_.SslFlagsTexto 22
            Antes    = if ("$($_.ThumbprintAntes)" -match '^[0-9A-Fa-f]{40}$') { "$($_.ThumbprintAntes)".Substring(0,8) } else { Cortar $_.ThumbprintAntes 16 }
            Depois   = if ("$($_.ThumbprintDepois)" -match '^[0-9A-Fa-f]{40}$') { "$($_.ThumbprintDepois)".Substring(0,8) } else { Cortar $_.ThumbprintDepois 16 }
            Acao     = Cortar $_.Acao 20
        }
    }
    ($tab | Format-Table -AutoSize | Out-String -Width 210).TrimEnd() | Write-Host

    Write-Host ''
    $grupos = $Linhas | Group-Object Acao | Sort-Object Count -Descending
    Write-Host 'Resumo' -ForegroundColor Cyan
    Write-Host ('-' * 52)
    foreach ($g in $grupos) { Write-Host ('  {0,-34} {1,4}' -f $g.Name, $g.Count) }

    # Sem o motivo a vista, um binding ignorado por engano passa despercebido.
    $ignorados = @($Linhas | Where-Object { "$($_.Acao)" -eq 'ignorado' -and $_.Motivo })
    if ($ignorados.Count -gt 0) {
        Write-Host ''
        Write-Host 'Por que cada binding foi ignorado' -ForegroundColor Cyan
        Write-Host ('-' * 52)
        foreach ($g in ($ignorados | Group-Object Motivo | Sort-Object Count -Descending)) {
            Write-Host ('  {0,3}x  {1}' -f $g.Count, $g.Name)
        }
    }

    $avisos = @($Linhas | Where-Object { $_.Aviso } )
    if ($avisos.Count -gt 0) {
        Write-Host ''
        Write-Host 'Avisos' -ForegroundColor Yellow
        foreach ($a in ($avisos | Select-Object -First 20)) {
            Write-Host ('  [{0}/{1}] {2}' -f $a.Servidor, $a.Site, $a.Aviso) -ForegroundColor Yellow
        }
    }

    $falhas = @($Linhas | Where-Object { "$($_.Acao)" -match 'FALHOU|divergencia' })
    if ($falhas.Count -gt 0) {
        Write-Host ''
        Write-Host ('{0} binding(s) nao ficaram no estado esperado:' -f $falhas.Count) -ForegroundColor Red
        foreach ($f in $falhas) {
            Write-Host ('  [{0}/{1}] {2} -> {3}' -f $f.Servidor, $f.Site, $f.HostName, $f.Verificacao) -ForegroundColor Red
        }
    }

    if ($Ensaio) {
        $trocaria = @($Linhas | Where-Object { "$($_.Acao)" -like 'TROCARIA*' }).Count
        Write-Host ''
        if ($trocaria -gt 0) {
            Write-Host ("ENSAIO: nada foi alterado. {0} binding(s) seriam trocados." -f $trocaria) -ForegroundColor Cyan
            Write-Host 'Revise a tabela acima e repita o comando com -Apply para efetivar.'  -ForegroundColor Cyan
        } else {
            Write-Host 'ENSAIO: nada foi alterado e nenhum binding seria trocado com os filtros atuais.' -ForegroundColor Cyan
        }
    }
}
#endregion

#region ---------------------------------------------------------------- Execucao
function Get-RemotingErrorHint {
    <#
    .SYNOPSIS
        Traduz o erro do PSRemoting para a causa provavel e o que conferir.
    .DESCRIPTION
        As mensagens do WinRM sao genericas: "Access is denied" cobre desde conta sem direito
        ate politica de UAC para conta local. Sem a traducao, o operador fica sem proximo passo.
    #>
    [CmdletBinding()]
    param([string]$Message)

    $m = "$Message"
    if (-not $m) { return 'erro sem mensagem' }

    # 'Acesso negado' e a traducao pt-BR de 'Access is denied'
    if ($m -match 'Access is denied|Acesso negado|5 - Acesso') {
        return @(
            'a conta usada nao tem direito de administracao remota NESTE servidor.'
            'Confira: (1) a conta e Administrador local ou membro de "Remote Management Users" no destino;'
            '(2) para conta LOCAL do destino, o UAC remoto bloqueia por padrao -- veja LocalAccountTokenFilterPolicy;'
            '(3) tente com -Credential de uma conta administrativa do dominio.'
        ) -join ' '
    }
    if ($m -match 'cannot be resolved|nao pode ser resolvido|No such host|not be resolved') {
        return 'o nome nao resolve em DNS a partir desta estacao. Confira o FQDN ou use o IP.'
    }
    if ($m -match 'TrustedHosts') {
        return 'autenticacao caiu para NTLM e o destino nao esta em TrustedHosts. Use o FQDN para que o Kerberos seja usado, ou inclua o host em TrustedHosts.'
    }
    if ($m -match 'Kerberos|authentication mechanism|mecanismo de autenticacao') {
        return 'falha de autenticacao Kerberos. Use o FQDN do servidor e informe -Credential.'
    }
    if ($m -match 'WinRM cannot complete|cannot connect to the destination|nao pode se conectar|actively refused|firewall') {
        return 'o WinRM nao respondeu: servico parado, nao configurado (Enable-PSRemoting) ou porta 5985/5986 bloqueada por firewall.'
    }
    if ($m -match 'timed out|tempo limite|timeout') {
        return 'tempo esgotado ao conectar. Host inacessivel ou porta do WinRM filtrada.'
    }
    if ($m -match 'certificate|certificado') {
        return 'problema no certificado do WinRM sobre HTTPS. Confira o certificado do listener no destino.'
    }
    return 'causa nao reconhecida; veja a mensagem original.'
}

function Test-RemotingReachability {
    <#
    .SYNOPSIS
        Diz se as portas do WinRM atendem, para separar problema de rede de problema de conta.
    #>
    [CmdletBinding()]
    param([string]$Computer, [int]$TimeoutMs = 3000)

    $portas = @{ 5985 = 'HTTP'; 5986 = 'HTTPS' }
    $abertas = @()
    foreach ($porta in ($portas.Keys | Sort-Object)) {
        $cli = New-Object System.Net.Sockets.TcpClient
        try {
            $iar = $cli.BeginConnect($Computer, $porta, $null, $null)
            if ($iar.AsyncWaitHandle.WaitOne($TimeoutMs)) {
                $cli.EndConnect($iar)
                $abertas += ('{0}/{1}' -f $porta, $portas[$porta])
            }
        } catch {
        } finally { try { $cli.Close() } catch { } }
    }
    if ($abertas.Count -gt 0) {
        return ('WinRM atende em {0}: a rede esta ok, o problema e de autenticacao ou autorizacao' -f ($abertas -join ' e '))
    }
    return 'nenhuma porta do WinRM (5985/5986) atendeu: servico parado, PSRemoting nao habilitado ou firewall'
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

function Invoke-OnServers {
    [CmdletBinding()]
    param(
        [string[]]$Servers, [scriptblock]$ScriptBlock, [object[]]$ArgumentList,
        [pscredential]$Credential, [bool]$UseSsl, [int]$ThrottleLimit, [string]$LogFile
    )
    $p = @{
        ComputerName  = $Servers
        ScriptBlock   = $ScriptBlock
        ArgumentList  = $ArgumentList
        ThrottleLimit = $ThrottleLimit
        ErrorAction   = 'SilentlyContinue'
        ErrorVariable = 'erroRemoto'
    }
    if ($Credential) { $p['Credential'] = $Credential }
    if ($UseSsl)     { $p['UseSSL'] = $true }

    $saida = Invoke-Command @p

    $falhas = @()
    foreach ($e in $erroRemoto) {
        $alvo = if ($e.TargetObject) { "$($e.TargetObject)" } else { '(servidor nao identificado)' }
        $msg  = ($e.Exception.Message -replace '\s+',' ').Trim()
        $dica = Get-RemotingErrorHint -Message $msg
        $rede = if ($alvo -ne '(servidor nao identificado)') { Test-RemotingReachability -Computer $alvo } else { '' }
        $falhas += [pscustomobject]@{ Servidor = $alvo; Mensagem = $msg; Dica = $dica; Rede = $rede }
        Write-DeployLog -Message ("Falha em {0}: {1} | {2} | {3}" -f $alvo, $msg, $dica, $rede) -Level 'ERRO' -Path $LogFile
    }

    return [pscustomobject]@{
        Respostas  = @($saida)
        Falhas     = $falhas
        Solicitados = @($Servers)
    }
}

function Show-ServerStatus {
    <#
    .SYNOPSIS
        Mostra quais servidores responderam e, para os que nao responderam, o que conferir.
    #>
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
        if ($f.Rede) { Write-Host ('    rede  : {0}' -f $f.Rede) }
    }
}

function Invoke-CertDeploy {
    [CmdletBinding()]
    param([hashtable]$Cfg)

    $log = $Cfg.LogFile
    Write-DeployLog -Message ('Inicio; PowerShell {0}' -f $PSVersionTable.PSVersion) -Path $log

    # ---- senha ----
    $senha = $null
    if ($Cfg.AskPfxPassword) {
        $senha = Read-Host -Prompt 'Senha do PFX' -AsSecureString
    } elseif ($Cfg.PfxPasswordFile) {
        if (-not (Test-Path -LiteralPath $Cfg.PfxPasswordFile)) {
            throw ("Arquivo de senha nao encontrado: {0}" -f $Cfg.PfxPasswordFile)
        }
        try {
            $senha = (Get-Content -LiteralPath $Cfg.PfxPasswordFile -Raw).Trim() | ConvertTo-SecureString
        } catch {
            throw ('Nao foi possivel ler a senha protegida. O DPAPI amarra o arquivo a conta e a maquina que o geraram; gere-o de novo nesta conta e nesta maquina. Detalhe: ' + ($_.Exception.Message -replace '\s+',' '))
        }
    } elseif ($Cfg.PfxPassword) {
        $senha = $Cfg.PfxPassword
    } else {
        $senha = Read-Host -Prompt 'Senha do PFX' -AsSecureString
    }
    if (-not $senha -or $senha.Length -eq 0) { throw 'Senha do PFX nao informada.' }

    # ---- PFX ----
    if (-not $Cfg.PfxPath) { throw 'Informe -PfxPath.' }
    if (-not (Test-Path -LiteralPath $Cfg.PfxPath)) { throw ("PFX nao encontrado: {0}" -f $Cfg.PfxPath) }
    $bytes = [System.IO.File]::ReadAllBytes((Resolve-Path -LiteralPath $Cfg.PfxPath).Path)

    try {
        $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 ($bytes, $senha)
    } catch {
        throw ('Nao foi possivel abrir o PFX (senha incorreta ou arquivo invalido): ' + ($_.Exception.Message -replace '\s+',' '))
    }
    if (-not $cert.HasPrivateKey) { throw 'O PFX nao contem chave privada; nao serve para binding de servidor.' }

    $nomes = Get-CertificateSubjectNames -Certificate $cert
    $thumb = $cert.Thumbprint.ToUpperInvariant()
    $dias  = [int][Math]::Floor(($cert.NotAfter - (Get-Date)).TotalDays)

    Write-Host ''
    Write-Host 'Certificado a instalar' -ForegroundColor Cyan
    Write-Host ('  Subject    : ' + $cert.Subject)
    Write-Host ('  Emissor    : ' + $cert.Issuer)
    Write-Host ('  Nomes      : ' + ($nomes -join ', '))
    Write-Host ('  Valido ate : {0}  ({1} dia(s))' -f $cert.NotAfter.ToString('yyyy-MM-dd HH:mm:ss'), $dias)
    Write-Host ('  Thumbprint : ' + $thumb)
    Write-Host ''

    if ($dias -lt 0)  { throw ('O certificado ja expirou em {0}. Abortando.' -f $cert.NotAfter.ToString('yyyy-MM-dd')) }
    if ($dias -lt 15) { Write-Warning ('O certificado vence em {0} dia(s). Confirme se e mesmo o arquivo certo.' -f $dias) }

    # ---- servidores ----
    $servidores = Get-ServerList -ComputerName $Cfg.ComputerName -ComputerListFile $Cfg.ComputerListFile
    if ($servidores.Count -eq 0) { throw 'Informe -ComputerName ou -ComputerListFile.' }
    Write-DeployLog -Message ('{0} servidor(es) alvo' -f $servidores.Count) -Path $log

    $ctx = @{
        NewThumbprint        = $thumb
        CertNames            = $nomes
        StoreName            = 'My'
        SiteName             = $Cfg.SiteName
        HostNameFilter       = $Cfg.HostNameFilter
        ReplaceThumbprint    = $Cfg.ReplaceThumbprint
        IncludeEmptyHostName = [bool]$Cfg.IncludeEmptyHostName
        Exportable           = [bool]$Cfg.Exportable
        PfxBytes             = $bytes
        Apply                = $false
    }

    $sb = New-RemoteScriptBlock

    # ---- passe 1: ensaio, que tambem e o backup ----
    Write-Host ('Consultando {0} servidor(es)...' -f $servidores.Count)
    $res1 = Invoke-OnServers -Servers $servidores -ScriptBlock $sb -ArgumentList @($ctx, $senha) `
                -Credential $Cfg.Credential -UseSsl ([bool]$Cfg.UseSsl) -ThrottleLimit $Cfg.ThrottleLimit -LogFile $log
    $ensaio = $res1.Respostas
    Show-ServerStatus -Resultado $res1

    foreach ($r in $ensaio) {
        if ($r.Status -ne 'OK') { Write-Warning ('{0}: {1} -- {2}' -f $r.Servidor, $r.Status, $r.Erro) }
        foreach ($a in $r.Avisos) { Write-Warning ('{0}: {1}' -f $r.Servidor, $a) }
    }

    if (@($ensaio).Count -eq 0) {
        Write-Host ''
        Write-Host 'Nenhum servidor respondeu; nada foi consultado nem alterado.' -ForegroundColor Red
        Write-Host 'Resolva o acesso remoto acima e repita o comando.' -ForegroundColor Red
        return @()
    }

    $linhasEnsaio = @($ensaio | ForEach-Object { $_.Bindings })
    $aTrocar = @($linhasEnsaio | Where-Object { "$($_.Acao)" -like 'TROCARIA*' })

    if (-not $Cfg.Apply) {
        Show-DeployReport -Linhas $linhasEnsaio -Ensaio $true
        return $linhasEnsaio
    }

    if ($aTrocar.Count -eq 0) {
        Write-Host 'Nenhum binding a trocar com os filtros atuais. Nada foi alterado.' -ForegroundColor Yellow
        Show-DeployReport -Linhas $linhasEnsaio -Ensaio $true
        return $linhasEnsaio
    }

    # ---- backup antes de qualquer escrita ----
    if (-not (Test-Path -LiteralPath $Cfg.BackupPath)) {
        [void](New-Item -ItemType Directory -Path $Cfg.BackupPath -Force)
    }
    $arqBackup = Join-Path $Cfg.BackupPath ('rollback-{0}.json' -f (Get-Date -Format 'yyyyMMdd-HHmmss'))
    $backup = $aTrocar | Select-Object Servidor, Site, BindingInfo, HostName, ThumbprintAntes, LojaAntes, SslFlags
    [System.IO.File]::WriteAllText($arqBackup, ($backup | ConvertTo-Json -Depth 5), (New-Object System.Text.UTF8Encoding($true)))
    Write-Host ('Rollback salvo em: {0}' -f $arqBackup) -ForegroundColor Green
    Write-DeployLog -Message ('Backup de {0} binding(s) em {1}' -f $backup.Count, $arqBackup) -Path $log

    # ---- confirmacao ----
    $porServidor = $aTrocar | Group-Object Servidor
    $descricao = ('trocar o certificado de {0} binding(s) em {1} servidor(es)' -f $aTrocar.Count, $porServidor.Count)
    if (-not $PSCmdlet.ShouldProcess(($porServidor.Name -join ', '), $descricao)) {
        Write-Host 'Cancelado pelo operador. Nada foi alterado.' -ForegroundColor Yellow
        return $linhasEnsaio
    }

    # ---- passe 2: aplicar ----
    $ctx.Apply = $true
    $servidoresComTroca = @($porServidor.Name)
    Write-Host ('Aplicando em {0} servidor(es)...' -f $servidoresComTroca.Count)
    $res2 = Invoke-OnServers -Servers $servidoresComTroca -ScriptBlock $sb -ArgumentList @($ctx, $senha) `
                -Credential $Cfg.Credential -UseSsl ([bool]$Cfg.UseSsl) -ThrottleLimit $Cfg.ThrottleLimit -LogFile $log
    $final = $res2.Respostas
    Show-ServerStatus -Resultado $res2

    foreach ($r in $final) {
        if ($r.Status -ne 'OK') { Write-Warning ('{0}: {1} -- {2}' -f $r.Servidor, $r.Status, $r.Erro) }
        foreach ($a in $r.Avisos) { Write-Host ('{0}: {1}' -f $r.Servidor, $a) -ForegroundColor Yellow }
        Write-DeployLog -Message ('{0}: certificado {1}' -f $r.Servidor, $r.CertImportado) -Path $log
    }

    $linhas = @($final | ForEach-Object { $_.Bindings })
    Show-DeployReport -Linhas $linhas -Ensaio $false
    Write-Host ''
    Write-Host ('Para desfazer:  .\Deploy-IISCertificate.ps1 -Rollback "{0}"' -f $arqBackup) -ForegroundColor Cyan
    Write-DeployLog -Message 'Fim' -Path $log
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
    foreach ($g in $porServidor) {
        Write-Host ('  {0}: {1} binding(s)' -f $g.Name, $g.Count)
    }

    if (-not $PSCmdlet.ShouldProcess(($porServidor.Name -join ', '), 'restaurar os certificados anteriores')) {
        Write-Host 'Cancelado. Nada foi alterado.' -ForegroundColor Yellow
        return @()
    }

    $sbRb = [scriptblock]::Create($script:CorpoRollback)
    $todas = @()
    foreach ($g in $porServidor) {
        $p = @{
            ComputerName = $g.Name
            ScriptBlock  = $sbRb
            ArgumentList = @(,@($g.Group))
            ErrorAction  = 'SilentlyContinue'
            ErrorVariable = 'errRb'
        }
        if ($Cfg.Credential) { $p['Credential'] = $Cfg.Credential }
        if ($Cfg.UseSsl)     { $p['UseSSL'] = $true }
        $r = Invoke-Command @p
        foreach ($e in $errRb) { Write-Warning ('{0}: {1}' -f $g.Name, ($e.Exception.Message -replace '\s+',' ')) }
        if ($r) {
            if ($r.Status -ne 'OK') { Write-Warning ('{0}: {1}' -f $r.Servidor, $r.Erro) }
            $todas += $r.Bindings
        }
    }

    if ($todas.Count -gt 0) {
        ($todas | Select-Object Servidor, Site, BindingInfo, Acao, Detalhe |
            Format-Table -AutoSize | Out-String -Width 200).TrimEnd() | Write-Host
    }
    return $todas
}

# Guarda de dot-source: carregado com '.', o script apenas define as funcoes, o que permite
# que os testes Pester exercitem a logica pura sem tocar em nenhum servidor.
if ($MyInvocation.InvocationName -ne '.') {
    $cfg = @{
        PfxPath = $PfxPath; PfxPassword = $PfxPassword; AskPfxPassword = $AskPfxPassword
        PfxPasswordFile = $PfxPasswordFile
        ComputerName = $ComputerName; ComputerListFile = $ComputerListFile
        Credential = $Credential; UseSsl = $UseSsl
        SiteName = $SiteName; HostNameFilter = $HostNameFilter
        ReplaceThumbprint = $ReplaceThumbprint; IncludeEmptyHostName = $IncludeEmptyHostName
        Apply = $Apply; Exportable = $Exportable; BackupPath = $BackupPath
        Rollback = $Rollback; ThrottleLimit = $ThrottleLimit; LogFile = $LogFile
    }

    $resultado = if ($PSCmdlet.ParameterSetName -eq 'Rollback') {
        Invoke-CertRollback -Cfg $cfg
    } else {
        Invoke-CertDeploy -Cfg $cfg
    }

    if ($ReportCsv -and $resultado) {
        Export-DeployCsv -Linhas $resultado -Path $ReportCsv
        Write-Host ('Relatorio salvo em: {0}' -f $ReportCsv) -ForegroundColor Green
    }
}
#endregion
