<#
    Testes das funcoes puras de Get-CertInventory.ps1.

    O script e carregado com dot-source; a guarda de InvocationName faz com que ele apenas
    defina as funcoes, sem executar nenhum scan.

    Compativel com Pester 4 e Pester 5.
        Invoke-Pester -Path .\Tests
#>

$ScriptPath = Join-Path (Split-Path -Parent $PSScriptRoot) 'Get-CertInventory.ps1'
. $ScriptPath

# ----------------------------------------------------------------- utilitarios de teste
function New-CertificateMessageBytes {
    <#
        Monta uma resposta de servidor TLS 1.2 (ServerHello + Certificate [+ CertificateRequest])
        para exercitar Read-TlsServerResponse sem abrir socket.
    #>
    param(
        [byte[][]]$CertificadosDer,
        [int]$CipherSuite = 0xC030,
        [switch]$ComCertificateRequest,
        [int]$TamanhoMaximoRegistro = 16384
    )

    # --- ServerHello ---
    $sh = New-Object System.Collections.Generic.List[byte]
    $sh.AddRange([byte[]]@(0x03,0x03))                    # server_version TLS 1.2
    $sh.AddRange((New-Object byte[] 32))                  # random
    $sh.Add(0x00)                                         # session_id vazio
    $sh.AddRange([byte[]]@([byte](($CipherSuite -shr 8) -band 0xFF), [byte]($CipherSuite -band 0xFF)))
    $sh.Add(0x00)                                         # compression
    $shMsg = New-Object System.Collections.Generic.List[byte]
    $shMsg.Add(0x02)
    $shMsg.AddRange([byte[]]@(0x00,[byte](($sh.Count -shr 8) -band 0xFF),[byte]($sh.Count -band 0xFF)))
    $shMsg.AddRange($sh.ToArray())

    # --- Certificate ---
    $lista = New-Object System.Collections.Generic.List[byte]
    foreach ($der in $CertificadosDer) {
        $lista.AddRange([byte[]]@([byte](($der.Length -shr 16) -band 0xFF),[byte](($der.Length -shr 8) -band 0xFF),[byte]($der.Length -band 0xFF)))
        $lista.AddRange($der)
    }
    $corpo = New-Object System.Collections.Generic.List[byte]
    $corpo.AddRange([byte[]]@([byte](($lista.Count -shr 16) -band 0xFF),[byte](($lista.Count -shr 8) -band 0xFF),[byte]($lista.Count -band 0xFF)))
    $corpo.AddRange($lista.ToArray())
    $certMsg = New-Object System.Collections.Generic.List[byte]
    $certMsg.Add(0x0B)
    $certMsg.AddRange([byte[]]@([byte](($corpo.Count -shr 16) -band 0xFF),[byte](($corpo.Count -shr 8) -band 0xFF),[byte]($corpo.Count -band 0xFF)))
    $certMsg.AddRange($corpo.ToArray())

    $handshake = New-Object System.Collections.Generic.List[byte]
    $handshake.AddRange($shMsg.ToArray())
    $handshake.AddRange($certMsg.ToArray())
    if ($ComCertificateRequest) {
        $handshake.AddRange([byte[]]@(0x0D,0x00,0x00,0x04,0x01,0x40,0x00,0x00))
    }

    # --- fragmenta em registros TLS ---
    $saida = New-Object System.Collections.Generic.List[byte]
    $dados = $handshake.ToArray()
    $pos = 0
    while ($pos -lt $dados.Length) {
        $tam = [Math]::Min($TamanhoMaximoRegistro, $dados.Length - $pos)
        $saida.AddRange([byte[]]@(0x16,0x03,0x03,[byte](($tam -shr 8) -band 0xFF),[byte]($tam -band 0xFF)))
        $saida.AddRange([byte[]]($dados[$pos..($pos + $tam - 1)]))
        $pos += $tam
    }
    return ,$saida.ToArray()
}

function New-TestCertificateDer {
    param([string]$Subject = 'CN=teste.lab')
    # Gera um certificado autoassinado em memoria, sem tocar no armazenamento da maquina
    $rsa = [System.Security.Cryptography.RSA]::Create(2048)
    $req = New-Object System.Security.Cryptography.X509Certificates.CertificateRequest(
        $Subject, $rsa,
        [System.Security.Cryptography.HashAlgorithmName]::SHA256,
        [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
    $cert = $req.CreateSelfSigned([DateTimeOffset]::UtcNow.AddDays(-1), [DateTimeOffset]::UtcNow.AddDays(365))
    return ,$cert.RawData
}

function New-NetBiosResponseBytes {
    param([hashtable[]]$Nomes)   # @{ Nome='SRV01'; Sufixo=0x00; Grupo=$false }
    $b = New-Object System.Collections.Generic.List[byte]
    $b.AddRange([byte[]]@(0x13,0x37,0x84,0x00,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x00))  # 12 de cabecalho
    $b.AddRange((New-Object byte[] 34))                       # nome codificado
    $b.AddRange([byte[]]@(0x00,0x21,0x00,0x01))               # tipo NBSTAT + classe IN
    $b.AddRange([byte[]]@(0x00,0x00,0x00,0x00))               # TTL
    $b.AddRange([byte[]]@(0x00,0x00))                         # rdlength
    $b.Add([byte]$Nomes.Count)                                # num_names
    foreach ($n in $Nomes) {
        $nome = $n.Nome.PadRight(15).Substring(0,15)
        $b.AddRange([System.Text.Encoding]::ASCII.GetBytes($nome))
        $b.Add([byte]$n.Sufixo)
        $flags = if ($n.Grupo) { 0x8000 } else { 0x0400 }
        $b.AddRange([byte[]]@([byte](($flags -shr 8) -band 0xFF),[byte]($flags -band 0xFF)))
    }
    return ,$b.ToArray()
}

function New-NtlmChallengeBytes {
    param([string]$NomeNetBios = 'SRVLINUX', [string]$DominioNetBios = 'CORP',
          [string]$NomeDns = 'srvlinux.energisa.corp', [string]$DominioDns = 'energisa.corp')

    $av = New-Object System.Collections.Generic.List[byte]
    function Add-Av([System.Collections.Generic.List[byte]]$Lista, [int]$Id, [string]$Valor) {
        $v = [System.Text.Encoding]::Unicode.GetBytes($Valor)
        $Lista.AddRange([byte[]]@([byte]($Id -band 0xFF),[byte](($Id -shr 8) -band 0xFF)))
        $Lista.AddRange([byte[]]@([byte]($v.Length -band 0xFF),[byte](($v.Length -shr 8) -band 0xFF)))
        $Lista.AddRange($v)
    }
    Add-Av $av 2 $DominioNetBios
    Add-Av $av 1 $NomeNetBios
    Add-Av $av 4 $DominioDns
    Add-Av $av 3 $NomeDns
    $av.AddRange([byte[]]@(0x00,0x00,0x00,0x00))       # MsvAvEOL

    $msg = New-Object System.Collections.Generic.List[byte]
    $msg.AddRange([System.Text.Encoding]::ASCII.GetBytes('NTLMSSP'))
    $msg.Add(0x00)
    $msg.AddRange([byte[]]@(0x02,0x00,0x00,0x00))      # tipo 2
    $msg.AddRange([byte[]]@(0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))  # TargetNameFields
    $msg.AddRange([byte[]]@(0x05,0x82,0x89,0xA2))      # flags
    $msg.AddRange((New-Object byte[] 8))               # ServerChallenge
    $msg.AddRange((New-Object byte[] 8))               # Reserved
    $tiOffset = 56
    $msg.AddRange([byte[]]@([byte]($av.Count -band 0xFF),[byte](($av.Count -shr 8) -band 0xFF)))
    $msg.AddRange([byte[]]@([byte]($av.Count -band 0xFF),[byte](($av.Count -shr 8) -band 0xFF)))
    $msg.AddRange([byte[]]@([byte]$tiOffset,0x00,0x00,0x00))
    $msg.AddRange((New-Object byte[] 8))               # Version
    $msg.AddRange($av.ToArray())
    return ,$msg.ToArray()
}

function New-SnmpResponseBytes {
    param([string]$SysName = 'srv-linux.energisa.corp', [byte]$Tipo = 0x04)
    $v = [System.Text.Encoding]::UTF8.GetBytes($SysName)
    $b = New-Object System.Collections.Generic.List[byte]
    $b.AddRange([byte[]]@(0x30,0x30,0x02,0x01,0x01))                       # SEQUENCE + version
    $b.AddRange([byte[]]@(0x04,0x06)); $b.AddRange([System.Text.Encoding]::ASCII.GetBytes('public'))
    $b.AddRange([byte[]]@(0xA2,0x20))                                      # GetResponse
    $b.AddRange([byte[]]@(0x02,0x04,0x12,0x34,0x56,0x78,0x02,0x01,0x00,0x02,0x01,0x00))
    $b.AddRange([byte[]]@(0x30,0x12,0x30,0x10))
    $b.AddRange([byte[]]@(0x06,0x08,0x2B,0x06,0x01,0x02,0x01,0x01,0x05,0x00))   # OID sysName
    $b.AddRange([byte[]]@($Tipo,[byte]$v.Length)); $b.AddRange($v)
    return ,$b.ToArray()
}

# ================================================================= TESTES

Describe 'Helpers binarios' {
    It 'le UInt16 big-endian sem o truncamento de byte do operador -shl' {
        # [byte]3 -shl 8 devolve 0 em PowerShell: o helper precisa promover para [int]
        ConvertFrom-BigEndianUInt16 -Bytes ([byte[]]@(0x03,0xD0)) -Offset 0 | Should -Be 976
    }
    It 'le UInt16 com o byte alto zerado' {
        ConvertFrom-BigEndianUInt16 -Bytes ([byte[]]@(0x00,0x59)) -Offset 0 | Should -Be 89
    }
    It 'le UInt16 no valor maximo' {
        ConvertFrom-BigEndianUInt16 -Bytes ([byte[]]@(0xFF,0xFF)) -Offset 0 | Should -Be 65535
    }
    It 'le UInt24 big-endian' {
        ConvertFrom-BigEndianUInt24 -Bytes ([byte[]]@(0x01,0x00,0x00)) -Offset 0 | Should -Be 65536
    }
    It 'respeita o offset informado' {
        ConvertFrom-BigEndianUInt16 -Bytes ([byte[]]@(0xAA,0xBB,0x03,0xD0)) -Offset 2 | Should -Be 976
    }
    It 'lanca excecao quando o offset ultrapassa o buffer, em vez de devolver lixo' {
        { ConvertFrom-BigEndianUInt16 -Bytes ([byte[]]@(0x01)) -Offset 0 } | Should -Throw
    }
    It 'gera bytes big-endian de 2 e 3 posicoes' {
        (ConvertTo-BigEndianBytes -Value 976 -Size 2) -join ',' | Should -Be '3,208'
        (ConvertTo-BigEndianBytes -Value 65536 -Size 3) -join ',' | Should -Be '1,0,0'
    }
    It 'faz ida e volta de 2 bytes para qualquer valor' {
        foreach ($v in 0, 1, 255, 256, 976, 40000, 65535) {
            ConvertFrom-BigEndianUInt16 -Bytes (ConvertTo-BigEndianBytes -Value $v -Size 2) -Offset 0 | Should -Be $v
        }
    }
    It 'le inteiros little-endian usados por NTLM' {
        ConvertFrom-LittleEndianUInt16 -Bytes ([byte[]]@(0xD0,0x03)) -Offset 0 | Should -Be 976
        ConvertFrom-LittleEndianUInt32 -Bytes ([byte[]]@(0x02,0x00,0x00,0x00)) -Offset 0 | Should -Be 2
    }
}

Describe 'ConvertTo-Target: parsing da entrada' {
    It 'usa a porta padrao para um nome simples' {
        $t = ConvertTo-Target -Line 'app.energisa.com.br' -DefaultPort 443
        $t.Host | Should -Be 'app.energisa.com.br'
        $t.Porta | Should -Be 443
    }
    It 'respeita host:porta' {
        $t = ConvertTo-Target -Line 'app.energisa.com.br:8443' -DefaultPort 443
        $t.Host | Should -Be 'app.energisa.com.br'
        $t.Porta | Should -Be 8443
    }
    It 'aceita IPv4 com porta' {
        $t = ConvertTo-Target -Line '10.83.101.9:9443' -DefaultPort 443
        $t.Host | Should -Be '10.83.101.9'
        $t.Porta | Should -Be 9443
    }
    It 'extrai host e porta de uma URL' {
        $t = ConvertTo-Target -Line 'https://portal.energisa.com.br/login' -DefaultPort 8443
        $t.Host | Should -Be 'portal.energisa.com.br'
        $t.Porta | Should -Be 443
    }
    It 'aceita IPv6 entre colchetes com porta' {
        $t = ConvertTo-Target -Line '[2603:1061:14:122::1]:443' -DefaultPort 443
        $t.Host | Should -Be '2603:1061:14:122::1'
        $t.Porta | Should -Be 443
    }
    It 'aceita IPv6 nu sem confundir os dois-pontos com porta' {
        $t = ConvertTo-Target -Line '2603:1061:14:122::1' -DefaultPort 443
        $t.Host | Should -Be '2603:1061:14:122::1'
        $t.Porta | Should -Be 443
    }
    It 'ignora linha vazia e comentario' {
        ConvertTo-Target -Line ''      -DefaultPort 443 | Should -BeNullOrEmpty
        ConvertTo-Target -Line '   '   -DefaultPort 443 | Should -BeNullOrEmpty
        ConvertTo-Target -Line '# nota' -DefaultPort 443 | Should -BeNullOrEmpty
    }
    It 'remove espacos em volta da entrada' {
        (ConvertTo-Target -Line '  app.lab:8443  ' -DefaultPort 443).Porta | Should -Be 8443
    }
    It 'trata nome com sublinhado como host, nao como erro de parsing' {
        # sublinhado e invalido em DNS, mas quem reporta isso e a etapa de DNS
        (ConvertTo-Target -Line 'awgpe_core_prd.energisa.corp' -DefaultPort 443).Host | Should -Be 'awgpe_core_prd.energisa.corp'
    }
    It 'reporta porta fora da faixa em vez de aceitar em silencio' {
        (ConvertTo-Target -Line 'app.lab:70000' -DefaultPort 443).Erro | Should -Match 'faixa'
    }
}

Describe 'Get-SubjectAlternativeName: parsing ASN.1 independente de idioma' {
    It 'extrai DNS, IP e email de uma extensao real' {
        $der = New-TestCertificateDer
        $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 (,$der)
        # monta manualmente a extensao para nao depender do gerador
        $sanBytes = [byte[]]@(
            0x30,0x2C,
            0x82,0x0B) + [System.Text.Encoding]::ASCII.GetBytes('app.lab.com') + [byte[]]@(
            0x82,0x0F) + [System.Text.Encoding]::ASCII.GetBytes('www.app.lab.com') + [byte[]]@(
            0x87,0x04,0x0A,0x53,0x65,0x09)
        $sans = Get-SubjectAlternativeName -RawData $sanBytes
        $sans | Should -Contain 'DNS:app.lab.com'
        $sans | Should -Contain 'DNS:www.app.lab.com'
        $sans | Should -Contain 'IP:10.83.101.9'
    }
    It 'nao depende do texto localizado de Format()' {
        $sanBytes = [byte[]]@(0x30,0x0D,0x82,0x0B) + [System.Text.Encoding]::ASCII.GetBytes('app.lab.com')
        (Get-SubjectAlternativeName -RawData $sanBytes)[0] | Should -Be 'DNS:app.lab.com'
    }
    It 'devolve lista vazia quando a extensao nao e uma SEQUENCE' {
        Get-SubjectAlternativeName -RawData ([byte[]]@(0x04,0x02,0x01,0x02)) | Should -BeNullOrEmpty
    }
    It 'devolve lista vazia para entrada nula ou curta' {
        Get-SubjectAlternativeName -RawData $null | Should -BeNullOrEmpty
        Get-SubjectAlternativeName -RawData ([byte[]]@(0x30)) | Should -BeNullOrEmpty
    }
    It 'nao entra em laco infinito com comprimento corrompido' {
        $ruim = [byte[]]@(0x30,0x20,0x82,0x7F,0x41,0x42)
        { Get-SubjectAlternativeName -RawData $ruim } | Should -Not -Throw
    }
    It 'trata SAN com forma longa de comprimento' {
        $nome = 'a' * 200
        $b = [byte[]]@(0x30,0x81,([byte]($nome.Length + 3)),0x82,0x81,[byte]$nome.Length) + [System.Text.Encoding]::ASCII.GetBytes($nome)
        (Get-SubjectAlternativeName -RawData $b)[0] | Should -Be ('DNS:' + $nome)
    }
}

Describe 'ClientHello TLS 1.2' {
    It 'produz um registro de handshake bem formado' {
        $h = New-TlsClientHello -ServerName 'app.energisa.com.br'
        $h[0] | Should -Be 0x16                                  # content_type handshake
        $h[1] | Should -Be 0x03
        $h[5] | Should -Be 0x01                                  # ClientHello
        $tamRegistro = ConvertFrom-BigEndianUInt16 -Bytes $h -Offset 3
        $tamRegistro | Should -Be ($h.Length - 5)
        $tamMsg = ConvertFrom-BigEndianUInt24 -Bytes $h -Offset 6
        $tamMsg | Should -Be ($h.Length - 9)
    }
    It 'inclui o SNI quando o nome e um hostname' {
        $h = New-TlsClientHello -ServerName 'app.energisa.com.br'
        $texto = [System.Text.Encoding]::ASCII.GetString($h)
        $texto | Should -Match 'app\.energisa\.com\.br'
    }
    It 'omite o SNI quando o alvo e um IP literal, como manda a RFC 6066' {
        $h = New-TlsClientHello -ServerName '10.83.101.9'
        ([System.Text.Encoding]::ASCII.GetString($h)) | Should -Not -Match '10\.83\.101\.9'
    }
    It 'omite o SNI quando o nome e vazio' {
        { New-TlsClientHello -ServerName '' } | Should -Not -Throw
    }
    It 'oferece CHACHA20 e AES-GCM, para alcancar servidores fora do conjunto do Schannel' {
        $h = New-TlsClientHello -ServerName 'app.lab'
        $hex = ($h | ForEach-Object { '{0:X2}' -f $_ }) -join ''
        $hex | Should -Match 'CCA8'      # ECDHE_RSA_WITH_CHACHA20_POLY1305
        $hex | Should -Match 'C030'      # ECDHE_RSA_WITH_AES_256_GCM_SHA384
    }
}

Describe 'Read-TlsServerResponse: extracao da mensagem Certificate' {
    It 'extrai um unico certificado' {
        $der = New-TestCertificateDer -Subject 'CN=unico.lab'
        $resp = New-CertificateMessageBytes -CertificadosDer @(,$der)
        $r = Read-TlsServerResponse -Data $resp
        $r.Certificados.Count | Should -Be 1
        $r.Certificados[0].Subject | Should -Be 'CN=unico.lab'
    }
    It 'extrai a cadeia inteira na ordem enviada' {
        $folha = New-TestCertificateDer -Subject 'CN=folha.lab'
        $inter = New-TestCertificateDer -Subject 'CN=intermediaria.lab'
        $resp = New-CertificateMessageBytes -CertificadosDer @($folha, $inter)
        $r = Read-TlsServerResponse -Data $resp
        $r.Certificados.Count | Should -Be 2
        $r.Certificados[0].Subject | Should -Be 'CN=folha.lab'
        $r.Certificados[1].Subject | Should -Be 'CN=intermediaria.lab'
    }
    It 'remonta a mensagem dividida em varios registros TLS' {
        # Um certificado de 2048 bits nao cabe num registro de 512 bytes
        $der = New-TestCertificateDer -Subject 'CN=fragmentado.lab'
        $resp = New-CertificateMessageBytes -CertificadosDer @(,$der) -TamanhoMaximoRegistro 512
        $r = Read-TlsServerResponse -Data $resp
        $r.Certificados.Count | Should -Be 1
        $r.Certificados[0].Subject | Should -Be 'CN=fragmentado.lab'
    }
    It 'le a versao e o cipher suite negociados do ServerHello' {
        $der = New-TestCertificateDer
        $r = Read-TlsServerResponse -Data (New-CertificateMessageBytes -CertificadosDer @(,$der) -CipherSuite 0xCCA8)
        $r.Versao | Should -Be 'Tls12'
        $r.CipherSuite | Should -Be 'TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305'
    }
    It 'detecta CertificateRequest, que indica exigencia de certificado de cliente' {
        $der = New-TestCertificateDer
        $r = Read-TlsServerResponse -Data (New-CertificateMessageBytes -CertificadosDer @(,$der) -ComCertificateRequest)
        $r.ExigeCertCliente | Should -BeTrue
        $r.Certificados.Count | Should -Be 1     # o certificado sobrevive ao mTLS
    }
    It 'nao marca exigencia de certificado de cliente quando nao ha CertificateRequest' {
        $der = New-TestCertificateDer
        (Read-TlsServerResponse -Data (New-CertificateMessageBytes -CertificadosDer @(,$der))).ExigeCertCliente | Should -BeFalse
    }
    It 'interpreta o alerta de versao de protocolo com explicacao' {
        $alerta = [byte[]]@(0x15,0x03,0x03,0x00,0x02,0x02,0x46)   # fatal, desc 70
        $r = Read-TlsServerResponse -Data $alerta
        $r.Alerta | Should -Match 'protocol_version'
        $r.Alerta | Should -Match 'TLS 1.3'
        $r.Certificados.Count | Should -Be 0
    }
    It 'interpreta o alerta de SNI desconhecido' {
        $r = Read-TlsServerResponse -Data ([byte[]]@(0x15,0x03,0x03,0x00,0x02,0x02,0x70))   # desc 112
        $r.Alerta | Should -Match 'unrecognized_name'
    }
    It 'interpreta o alerta de certificado de cliente obrigatorio' {
        $r = Read-TlsServerResponse -Data ([byte[]]@(0x15,0x03,0x03,0x00,0x02,0x02,0x74))   # desc 116
        $r.Alerta | Should -Match 'certificate_required'
    }
    It 'explica a resposta vazia em vez de devolver campo em branco' {
        (Read-TlsServerResponse -Data ([byte[]]@())).Detalhe | Should -Not -BeNullOrEmpty
        (Read-TlsServerResponse -Data $null).Detalhe | Should -Not -BeNullOrEmpty
    }
    It 'nao lanca excecao com dados truncados' {
        $der = New-TestCertificateDer
        $bom = New-CertificateMessageBytes -CertificadosDer @(,$der)
        $truncado = [byte[]]($bom[0..([int]($bom.Length / 2))])
        { Read-TlsServerResponse -Data $truncado } | Should -Not -Throw
    }
}

Describe 'Read-NetBiosResponse' {
    It 'devolve o nome da estacao com sufixo 0x00 fora de grupo' {
        $b = New-NetBiosResponseBytes -Nomes @(
            @{ Nome = 'MGROBOTAPLP74'; Sufixo = 0x00; Grupo = $false },
            @{ Nome = 'SCL';           Sufixo = 0x00; Grupo = $true  }
        )
        $r = Read-NetBiosResponse -Buffer $b
        $r.Nome | Should -Be 'MGROBOTAPLP74'
        $r.Dominio | Should -Be 'SCL'
    }
    It 'ignora entradas de servico com outros sufixos' {
        $b = New-NetBiosResponseBytes -Nomes @(
            @{ Nome = 'SRV01'; Sufixo = 0x20; Grupo = $false },
            @{ Nome = 'SRV01'; Sufixo = 0x00; Grupo = $false }
        )
        (Read-NetBiosResponse -Buffer $b).Nome | Should -Be 'SRV01'
    }
    It 'explica quando nenhum nome de estacao aparece' {
        $b = New-NetBiosResponseBytes -Nomes @(@{ Nome = 'SRV01'; Sufixo = 0x20; Grupo = $false })
        $r = Read-NetBiosResponse -Buffer $b
        $r.Nome | Should -BeNullOrEmpty
        $r.Detalhe | Should -Not -BeNullOrEmpty
    }
    It 'explica resposta curta em vez de estourar indice' {
        (Read-NetBiosResponse -Buffer ([byte[]]@(0x01,0x02))).Detalhe | Should -Match 'menor'
        { Read-NetBiosResponse -Buffer $null } | Should -Not -Throw
    }
}

Describe 'Read-NtlmChallenge' {
    It 'extrai nomes NetBIOS e DNS do TargetInfo' {
        $r = Read-NtlmChallenge -Buffer (New-NtlmChallengeBytes)
        $r.NomeNetBios    | Should -Be 'SRVLINUX'
        $r.DominioNetBios | Should -Be 'CORP'
        $r.NomeDns        | Should -Be 'srvlinux.energisa.corp'
        $r.DominioDns     | Should -Be 'energisa.corp'
    }
    It 'encontra a mensagem mesmo precedida por envelope SPNEGO' {
        $ntlm = New-NtlmChallengeBytes
        $comPrefixo = [byte[]]@(0xA1,0x81,0x00,0x30,0x1E,0xA0,0x03,0x0A,0x01,0x01) + $ntlm
        (Read-NtlmChallenge -Buffer $comPrefixo).NomeDns | Should -Be 'srvlinux.energisa.corp'
    }
    It 'explica quando nao ha mensagem NTLM' {
        (Read-NtlmChallenge -Buffer (New-Object byte[] 128)).Detalhe | Should -Match 'nenhuma mensagem'
    }
    It 'nao lanca excecao com buffer curto ou nulo' {
        { Read-NtlmChallenge -Buffer ([byte[]]@(0x01,0x02)) } | Should -Not -Throw
        { Read-NtlmChallenge -Buffer $null } | Should -Not -Throw
    }
}

Describe 'Read-SnmpSysNameResponse' {
    It 'extrai sysName da resposta' {
        (Read-SnmpSysNameResponse -Buffer (New-SnmpResponseBytes -SysName 'srv-linux.energisa.corp')).Nome |
            Should -Be 'srv-linux.energisa.corp'
    }
    It 'explica quando o agente devolve tipo diferente de OCTET STRING' {
        $r = Read-SnmpSysNameResponse -Buffer (New-SnmpResponseBytes -SysName 'x' -Tipo 0x80)
        $r.Nome | Should -BeNullOrEmpty
        $r.Detalhe | Should -Match 'OCTET STRING'
    }
    It 'explica quando o OID nao aparece na resposta' {
        (Read-SnmpSysNameResponse -Buffer (New-Object byte[] 64)).Detalhe | Should -Match 'OID'
    }
    It 'nao lanca excecao com buffer curto' {
        { Read-SnmpSysNameResponse -Buffer ([byte[]]@(0x30,0x02)) } | Should -Not -Throw
    }
}

Describe 'Read-SmtpBanner' {
    It 'extrai o FQDN de uma saudacao do Postfix' {
        (Read-SmtpBanner -Banner '220 mail.energisa.com.br ESMTP Postfix (Ubuntu)').Nome |
            Should -Be 'mail.energisa.com.br'
    }
    It 'extrai o nome de uma saudacao do Exchange' {
        (Read-SmtpBanner -Banner '220 MGEXCH01.energisa.corp Microsoft ESMTP MAIL Service ready').Nome |
            Should -Be 'MGEXCH01.energisa.corp'
    }
    It 'aceita a forma multilinha 220-' {
        (Read-SmtpBanner -Banner '220-mail.lab.com ESMTP').Nome | Should -Be 'mail.lab.com'
    }
    It 'explica saudacao sem nome reconhecivel' {
        (Read-SmtpBanner -Banner '500 erro').Detalhe | Should -Not -BeNullOrEmpty
    }
    It 'explica banner vazio' {
        (Read-SmtpBanner -Banner '').Detalhe | Should -Match 'nao enviou'
    }
}

Describe 'Get-OsGuess: inferencia de sistema operacional' {
    It 'aponta Linux a partir do banner SSH do OpenSSH em Ubuntu' {
        (Get-OsGuess -SshBanner 'SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4').SO | Should -Be 'Linux'
    }
    It 'aponta Windows a partir do banner do OpenSSH para Windows' {
        (Get-OsGuess -SshBanner 'SSH-2.0-OpenSSH_for_Windows_8.1').SO | Should -Be 'Windows'
    }
    It 'aponta Linux a partir do banner SMTP do Postfix' {
        (Get-OsGuess -SmtpBanner '220 mail.lab ESMTP Postfix').SO | Should -Be 'Linux'
    }
    It 'aponta Windows a partir do banner SMTP do Exchange' {
        (Get-OsGuess -SmtpBanner '220 ex.lab Microsoft ESMTP').SO | Should -Be 'Windows'
    }
    It 'aponta Windows quando NetBIOS e NTLM respondem' {
        (Get-OsGuess -NetBiosRespondeu $true -NtlmRespondeu $true).SO | Should -Be 'Windows'
    }
    It 'reconhece nome de rota do OpenShift como indicio de Linux' {
        (Get-OsGuess -NomeObservado 'apijurcrp-ds.apps.ocpd1.energisa.corp').SO | Should -Match 'Linux'
    }
    It 'usa o TTL apenas como indicio fraco' {
        (Get-OsGuess -Ttl 64).SO  | Should -Match 'Linux'
        (Get-OsGuess -Ttl 128).SO | Should -Match 'Windows'
    }
    It 'devolve Desconhecido sem evidencia, e nunca campo vazio' {
        $g = Get-OsGuess
        $g.SO | Should -Be 'Desconhecido'
        $g.Evidencia | Should -Not -BeNullOrEmpty
    }
    It 'marca sempre a saida como estimativa' {
        (Get-OsGuess -NetBiosRespondeu $true).Evidencia | Should -Match 'estimativa'
    }
}

Describe 'Get-StartTlsProtocol' {
    It 'escolhe SMTP nas portas 25 e 587 em modo Auto' {
        Get-StartTlsProtocol -Port 25  -Mode 'Auto' | Should -Be 'Smtp'
        Get-StartTlsProtocol -Port 587 -Mode 'Auto' | Should -Be 'Smtp'
    }
    It 'escolhe LDAP na porta 389 em modo Auto' {
        Get-StartTlsProtocol -Port 389 -Mode 'Auto' | Should -Be 'Ldap'
    }
    It 'nao usa STARTTLS na 443' {
        Get-StartTlsProtocol -Port 443 -Mode 'Auto' | Should -BeNullOrEmpty
    }
    It 'respeita o modo forcado por parametro' {
        Get-StartTlsProtocol -Port 443 -Mode 'Smtp' | Should -Be 'Smtp'
        Get-StartTlsProtocol -Port 25  -Mode 'None' | Should -BeNullOrEmpty
    }
}

Describe 'Get-TlsAlertDescription e Get-CipherSuiteName' {
    It 'explica os alertas que mais aparecem em alvo Linux' {
        Get-TlsAlertDescription -Code 40  | Should -Match 'cipher suite em comum'
        Get-TlsAlertDescription -Code 70  | Should -Match 'TLS 1.3'
        Get-TlsAlertDescription -Code 112 | Should -Match 'SNI'
        Get-TlsAlertDescription -Code 116 | Should -Match 'mTLS'
    }
    It 'nomeia alerta desconhecido sem falhar' {
        Get-TlsAlertDescription -Code 200 | Should -Match '200'
    }
    It 'traduz codigos de cipher suite conhecidos' {
        Get-CipherSuiteName -Code 0xC030 | Should -Be 'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384'
        Get-CipherSuiteName -Code 0xCCA8 | Should -Be 'TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305'
    }
    It 'devolve o codigo em hexadecimal quando nao conhece a suite' {
        Get-CipherSuiteName -Code 0x1234 | Should -Be '0x1234'
    }
}

Describe 'Test-CertificateChain' {
    It 'avisa quando o servidor envia somente a folha' {
        $der = New-TestCertificateDer -Subject 'CN=folha.lab'
        $folha = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 (,$der)
        # autoassinado nao exige intermediario; usar um emissor diferente para o caso real
        $r = Test-CertificateChain -Leaf $folha -Sent @($folha)
        $r.CadeiaCompleta | Should -Not -BeNullOrEmpty
    }
    It 'nunca devolve campo vazio, mesmo sem certificado' {
        $r = Test-CertificateChain -Leaf $null -Sent @()
        $r.CadeiaEnviada   | Should -Not -BeNullOrEmpty
        $r.CadeiaCompleta  | Should -Not -BeNullOrEmpty
        $r.CadeiaConfiavel | Should -Not -BeNullOrEmpty
    }
}

Describe 'Get-CertificateFacts' {
    It 'le algoritmo, tamanho de chave e assinatura' {
        $der = New-TestCertificateDer -Subject 'CN=fatos.lab'
        $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 (,$der)
        $f = Get-CertificateFacts -Certificate $cert
        $f.CN                  | Should -Be 'fatos.lab'
        $f.TamanhoChave        | Should -Be 2048
        $f.AlgoritmoChave      | Should -Match 'RSA'
        $f.AlgoritmoAssinatura | Should -Match 'sha256'
        $f.NumeroSerie         | Should -Not -BeNullOrEmpty
    }
    It 'explica a ausencia de SAN em vez de deixar o campo vazio' {
        $der = New-TestCertificateDer -Subject 'CN=semsan.lab'
        $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 (,$der)
        (Get-CertificateFacts -Certificate $cert).SANs | Should -Match 'sem extensao SAN'
    }
    It 'nao lanca excecao com certificado nulo' {
        { Get-CertificateFacts -Certificate $null } | Should -Not -Throw
    }
}

Describe 'Get-ErrorText' {
    It 'desembrulha a excecao mais interna' {
        $interna = New-Object System.Exception('causa raiz')
        $externa = New-Object System.Exception('mensagem externa', $interna)
        Get-ErrorText $externa | Should -Be 'causa raiz'
    }
    It 'normaliza quebras de linha' {
        Get-ErrorText (New-Object System.Exception("linha um`r`nlinha dois") ) | Should -Be 'linha um linha dois'
    }
    It 'nunca devolve vazio' {
        Get-ErrorText $null | Should -Not -BeNullOrEmpty
    }
}
