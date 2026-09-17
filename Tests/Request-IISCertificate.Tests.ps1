<#
    Testes das funcoes puras de Request-IISCertificate.ps1.

    O script e carregado com dot-source; a guarda de InvocationName faz com que ele apenas
    defina as funcoes, sem tocar em servidor, AD ou CA.

        Invoke-Pester -Path .\Tests
#>

$ScriptPath = Join-Path (Split-Path -Parent $PSScriptRoot) 'Request-IISCertificate.ps1'
. $ScriptPath

# ----------------------------------------------------------------- utilitarios
function New-DerLen([int]$n) {
    if ($n -lt 0x80) { return ,([byte[]]@([byte]$n)) }
    $b = [System.Collections.Generic.List[byte]]::new()
    $v = $n
    while ($v -gt 0) { $b.Insert(0, [byte]($v -band 0xFF)); $v = $v -shr 8 }
    return ,([byte[]](@([byte](0x80 -bor $b.Count)) + $b.ToArray()))
}

function New-TemplateNameExtension {
    <# Monta o valor DER da extensao 1.3.6.1.4.1.311.20.2: BMPString com o nome do template. #>
    param([string]$Nome)
    $v = [System.Text.Encoding]::BigEndianUnicode.GetBytes($Nome)
    return ,([byte[]](@([byte]0x1E) + (New-DerLen $v.Length) + $v))
}

function New-TestCertificate {
    param(
        [string]$Subject = 'CN=wsccp-ho.energisa.com.br',
        [string[]]$Dns = @('wsccp-ho.energisa.com.br','wsccp.energisa.com.br'),
        [string]$TemplateName = 'WebServerEnergisaV4'
    )
    $rsa = [System.Security.Cryptography.RSA]::Create(2048)
    $req = New-Object System.Security.Cryptography.X509Certificates.CertificateRequest(
        $Subject, $rsa,
        [System.Security.Cryptography.HashAlgorithmName]::SHA256,
        [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)

    if ($Dns -and $Dns.Count -gt 0) {
        $san = New-Object System.Security.Cryptography.X509Certificates.SubjectAlternativeNameBuilder
        foreach ($d in $Dns) { $san.AddDnsName($d) }
        $req.CertificateExtensions.Add($san.Build())
    }
    if ($TemplateName) {
        $ext = New-Object System.Security.Cryptography.X509Certificates.X509Extension(
            (New-Object System.Security.Cryptography.Oid('1.3.6.1.4.1.311.20.2')),
            (New-TemplateNameExtension -Nome $TemplateName), $false)
        $req.CertificateExtensions.Add($ext)
    }
    return $req.CreateSelfSigned([DateTimeOffset]::UtcNow.AddDays(-30), [DateTimeOffset]::UtcNow.AddDays(60))
}

# ================================================================= TESTES

Describe 'ConvertFrom-DerOid' {
    It 'converte o conteudo DER de um OID para notacao pontuada' {
        # 2b 06 01 04 01 82 37 15 07 = 1.3.6.1.4.1.311.21.7
        ConvertFrom-DerOid -Bytes ([byte[]]@(0x2B,0x06,0x01,0x04,0x01,0x82,0x37,0x15,0x07)) |
            Should -Be '1.3.6.1.4.1.311.21.7'
    }
    It 'trata o primeiro byte composto (40*x + y)' {
        ConvertFrom-DerOid -Bytes ([byte[]]@(0x2A,0x86,0x48)) | Should -BeLike '1.2.840*'
    }
    It 'trata componentes grandes, em varios bytes' {
        # 1.3.6.1.4.1.311.21.8.1234567
        $b = [byte[]]@(0x2B,0x06,0x01,0x04,0x01,0x82,0x37,0x15,0x08,0xCB,0xAD,0x07)
        ConvertFrom-DerOid -Bytes $b | Should -Be '1.3.6.1.4.1.311.21.8.1234567'
    }
    It 'devolve vazio para entrada nula ou vazia' {
        ConvertFrom-DerOid -Bytes $null         | Should -BeNullOrEmpty
        ConvertFrom-DerOid -Bytes ([byte[]]@()) | Should -BeNullOrEmpty
    }
}

Describe 'Get-CertificateTemplateInfo' {
    It 'le o nome do template da extensao 1.3.6.1.4.1.311.20.2' {
        $c = New-TestCertificate -TemplateName 'WebServerEnergisaV4'
        $t = Get-CertificateTemplateInfo -Certificate $c
        $t.Nome | Should -Be 'WebServerEnergisaV4'
        $t.Origem | Should -Match '311\.20\.2'
    }
    It 'decodifica BMPString, que e UTF-16 BIG endian' {
        # Lendo como UTF-16 little endian sairiam caracteres chineses em vez do nome.
        $c = New-TestCertificate -TemplateName 'WOKSTATION SCCM-ENERGISA V1'
        (Get-CertificateTemplateInfo -Certificate $c).Nome | Should -Be 'WOKSTATION SCCM-ENERGISA V1'
    }
    It 'reporta ausencia de template em vez de devolver campo vazio sem explicacao' {
        $c = New-TestCertificate -TemplateName $null
        $t = Get-CertificateTemplateInfo -Certificate $c
        $t.Nome | Should -BeNullOrEmpty
        $t.Origem | Should -Match 'sem extensao'
    }
    It 'nao lanca excecao com certificado nulo' {
        { Get-CertificateTemplateInfo -Certificate $null } | Should -Not -Throw
    }
}

Describe 'Get-CertificateNames: o que a renovacao precisa repetir' {
    It 'devolve o Common Name' {
        $c = New-TestCertificate
        (Get-CertificateNames -Certificate $c).CommonName | Should -Be 'wsccp-ho.energisa.com.br'
    }
    It 'devolve todas as SANs de DNS' {
        $n = Get-CertificateNames -Certificate (New-TestCertificate)
        $n.DnsNames | Should -Contain 'wsccp-ho.energisa.com.br'
        $n.DnsNames | Should -Contain 'wsccp.energisa.com.br'
    }
    It 'inclui o CN nas SANs quando ele nao estava la' {
        # Emissores modernos recusam certificado cujo CN nao aparece no SAN.
        $c = New-TestCertificate -Subject 'CN=so-no-cn.energisa.com.br' -Dns @('outro.energisa.com.br')
        $n = Get-CertificateNames -Certificate $c
        $n.DnsNames | Should -Contain 'so-no-cn.energisa.com.br'
        $n.DnsNames | Should -Contain 'outro.energisa.com.br'
    }
    It 'nao duplica o CN quando ele ja esta nas SANs' {
        $n = Get-CertificateNames -Certificate (New-TestCertificate)
        @($n.DnsNames | Where-Object { $_ -eq 'wsccp-ho.energisa.com.br' }).Count | Should -Be 1
    }
    It 'funciona em certificado sem extensao SAN, usando o CN' {
        $c = New-TestCertificate -Dns @()
        (Get-CertificateNames -Certificate $c).DnsNames | Should -Contain 'wsccp-ho.energisa.com.br'
    }
    It 'nao lanca excecao com certificado nulo' {
        { Get-CertificateNames -Certificate $null } | Should -Not -Throw
    }
}

Describe 'Test-TemplateMatch' {
    $info = [pscustomobject]@{ Nome = 'WebServerEnergisaV4'; Oid = '1.3.6.1.4.1.311.21.8.1.2.3' }

    It 'casa pelo nome interno' {
        Test-TemplateMatch -TemplateInfo $info -Procurado 'WebServerEnergisaV4' | Should -BeTrue
    }
    It 'casa pelo nome de exibicao, ignorando os espacos' {
        # O certlm mostra "Web Server Energisa V4"; o certificado guarda "WebServerEnergisaV4".
        Test-TemplateMatch -TemplateInfo $info -Procurado 'Web Server Energisa V4' | Should -BeTrue
    }
    It 'ignora diferenca de caixa' {
        Test-TemplateMatch -TemplateInfo $info -Procurado 'webserverenergisav4' | Should -BeTrue
    }
    It 'casa pelo OID' {
        Test-TemplateMatch -TemplateInfo $info -Procurado '1.3.6.1.4.1.311.21.8.1.2.3' | Should -BeTrue
    }
    It 'nao casa com outro template' {
        Test-TemplateMatch -TemplateInfo $info -Procurado 'WOKSTATIONSCCMENERGISAV1' | Should -BeFalse
    }
    It 'nao casa com template vazio ou info nula' {
        Test-TemplateMatch -TemplateInfo $info -Procurado ''    | Should -BeFalse
        Test-TemplateMatch -TemplateInfo $null  -Procurado 'X'  | Should -BeFalse
    }
    It 'trabalha sobre um certificado real, de ponta a ponta' {
        $t = Get-CertificateTemplateInfo -Certificate (New-TestCertificate -TemplateName 'WebServerEnergisaV4')
        Test-TemplateMatch -TemplateInfo $t -Procurado 'Web Server Energisa V4' | Should -BeTrue
        Test-TemplateMatch -TemplateInfo $t -Procurado 'Outro Template'         | Should -BeFalse
    }
}

Describe 'Resolve-SelectionInput' {
    It 'aceita um numero' { (Resolve-SelectionInput -Entrada '2' -Total 5).Indices | Should -Be @(1) }
    It 'aceita lista'     { (Resolve-SelectionInput -Entrada '1,3' -Total 5).Indices | Should -Be @(0,2) }
    It 'aceita faixa'     { (Resolve-SelectionInput -Entrada '1-3' -Total 5).Indices | Should -Be @(0,1,2) }
    It 'aceita lista com faixa' { (Resolve-SelectionInput -Entrada '1,4-5' -Total 5).Indices | Should -Be @(0,3,4) }
    It 'aceita faixa invertida' { (Resolve-SelectionInput -Entrada '3-1' -Total 5).Indices | Should -Be @(0,1,2) }
    It 'remove repeticoes'      { (Resolve-SelectionInput -Entrada '2,2,2' -Total 5).Indices | Should -Be @(1) }
    It 'aceita "t" e "todos"' {
        (Resolve-SelectionInput -Entrada 't' -Total 3).Indices     | Should -Be @(0,1,2)
        (Resolve-SelectionInput -Entrada 'todos' -Total 3).Indices | Should -Be @(0,1,2)
    }
    It 'trata vazio como cancelamento' {
        (Resolve-SelectionInput -Entrada ''    -Total 5).Cancelado | Should -BeTrue
        (Resolve-SelectionInput -Entrada '   ' -Total 5).Cancelado | Should -BeTrue
    }
    It 'recusa numero fora da faixa em vez de ignorar em silencio' {
        # Escolher o indice errado aqui significa renovar o site errado.
        (Resolve-SelectionInput -Entrada '9'    -Total 5).Erro | Should -Match 'fora da faixa'
        (Resolve-SelectionInput -Entrada '0'    -Total 5).Erro | Should -Match 'fora da faixa'
        (Resolve-SelectionInput -Entrada '1-99' -Total 5).Erro | Should -Match 'fora da faixa'
    }
    It 'recusa entrada nao numerica' {
        (Resolve-SelectionInput -Entrada 'abc' -Total 5).Erro | Should -Not -BeNullOrEmpty
        (Resolve-SelectionInput -Entrada '2,x' -Total 5).Erro | Should -Not -BeNullOrEmpty
    }
}

Describe 'New-CertReqInf' {
    $inf = New-CertReqInf -CommonName 'wsccp-ho.energisa.com.br' `
                          -DnsNames @('wsccp-ho.energisa.com.br','wsccp.energisa.com.br') `
                          -TemplateName 'WebServerEnergisaV4'

    It 'declara o Subject com o Common Name' { $inf | Should -Match 'Subject = "CN=wsccp-ho\.energisa\.com\.br"' }
    It 'declara o template na secao correta' {
        $inf | Should -Match '\[RequestAttributes\]'
        $inf | Should -Match 'CertificateTemplate = WebServerEnergisaV4'
    }
    It 'gera a chave no contexto de maquina' { $inf | Should -Match 'MachineKeySet = True' }
    It 'monta as SANs com & entre os nomes e sem & no ultimo' {
        $inf | Should -Match '_continue_ = "dns=wsccp-ho\.energisa\.com\.br&"'
        $inf | Should -Match '_continue_ = "dns=wsccp\.energisa\.com\.br"'
    }
    It 'nao deixa a chave exportavel por padrao' { $inf | Should -Match 'Exportable = FALSE' }
    It 'marca exportavel quando pedido' {
        (New-CertReqInf -CommonName 'a.b' -DnsNames @('a.b') -TemplateName 'T' -Exportable) | Should -Match 'Exportable = TRUE'
    }
    It 'omite a secao de extensoes quando nao ha SAN' {
        (New-CertReqInf -CommonName 'a.b' -DnsNames @() -TemplateName 'T') | Should -Not -Match '\[Extensions\]'
    }
    It 'remove SANs repetidas' {
        $x = New-CertReqInf -CommonName 'a.b' -DnsNames @('a.b','a.b','c.d') -TemplateName 'T'
        @([regex]::Matches($x, '_continue_')).Count | Should -Be 2
    }
    It 'exige Common Name e template' {
        { New-CertReqInf -CommonName ''  -TemplateName 'T' } | Should -Throw
        { New-CertReqInf -CommonName 'a' -TemplateName ''  } | Should -Throw
    }
}

Describe 'Resolve-TemplateName' {
    $tpls = @(
        [pscustomobject]@{ Nome = 'WebServerEnergisaV4';      Exibicao = 'Web Server Energisa V4';      Oid = '1.3.6.1.4.1.311.21.8.1.1' }
        [pscustomobject]@{ Nome = 'WOKSTATIONSCCMENERGISAV1'; Exibicao = 'WOKSTATION SCCM-ENERGISA V1'; Oid = '1.3.6.1.4.1.311.21.8.1.2' }
    )
    It 'resolve o nome de exibicao para o nome interno' {
        $r = Resolve-TemplateName -Informado 'Web Server Energisa V4' -Templates $tpls
        $r.Nome | Should -Be 'WebServerEnergisaV4'
        $r.Resolvido | Should -BeTrue
    }
    It 'aceita o nome interno diretamente' {
        (Resolve-TemplateName -Informado 'WebServerEnergisaV4' -Templates $tpls).Nome | Should -Be 'WebServerEnergisaV4'
    }
    It 'resolve pelo OID' {
        (Resolve-TemplateName -Informado '1.3.6.1.4.1.311.21.8.1.2' -Templates $tpls).Nome | Should -Be 'WOKSTATIONSCCMENERGISAV1'
    }
    It 'sinaliza quando nao resolve, mas segue com o informado' {
        $r = Resolve-TemplateName -Informado 'Inexistente' -Templates $tpls
        $r.Resolvido | Should -BeFalse
        $r.Nome | Should -Be 'Inexistente'
    }
    It 'segue com o informado quando o AD nao respondeu' {
        (Resolve-TemplateName -Informado 'Qualquer' -Templates @()).Nome | Should -Be 'Qualquer'
    }
}

Describe 'ConvertFrom-SslFlags' {
    It 'traduz cada bit pelo nome certo' {
        ConvertFrom-SslFlags -Value 0 | Should -Be 'nenhuma'
        ConvertFrom-SslFlags -Value 1 | Should -Be 'SNI'
        ConvertFrom-SslFlags -Value 9 | Should -Be 'SNI+DisableOCSPStapling'
    }
    It 'sinaliza bit desconhecido' { ConvertFrom-SslFlags -Value 128 | Should -Match 'desconhecido' }
}

Describe 'New-RemoteScriptBlock' {
    It 'monta codigo valido para as duas fases' {
        foreach ($tipo in 'Scan','Aplicar') {
            $erros = $null
            [void][System.Management.Automation.Language.Parser]::ParseInput(
                (New-RemoteScriptBlock -Tipo $tipo).ToString(), [ref]$null, [ref]$erros)
            $erros | Should -BeNullOrEmpty
        }
    }
    It 'tem bloco de parametros REAL nas duas fases' {
        # Procurar o texto 'param(' nao basta: vindo depois de outra instrucao, o PowerShell o
        # trata como chamada de comando, nao vincula nada e o corpo roda com variaveis nulas.
        foreach ($tipo in 'Scan','Aplicar') {
            $ast = (New-RemoteScriptBlock -Tipo $tipo).Ast
            $ast.ParamBlock | Should -Not -BeNullOrEmpty
            $ast.ParamBlock.Parameters.Count | Should -Be 1
            $ast.ParamBlock.Parameters[0].Name.VariablePath.UserPath | Should -Be 'Ctx'
        }
    }
    It 'coloca o param antes da primeira funcao' {
        foreach ($tipo in 'Scan','Aplicar') {
            $txt = (New-RemoteScriptBlock -Tipo $tipo).ToString()
            $txt.IndexOf('param(') | Should -BeLessThan $txt.IndexOf('function ')
        }
    }
    It 'injeta as funcoes que os corpos remotos usam' {
        $txt = (New-RemoteScriptBlock -Tipo 'Scan').ToString()
        foreach ($f in 'Get-CertificateTemplateInfo','Test-TemplateMatch','Get-CertificateNames','ConvertFrom-SslFlags') {
            $txt | Should -Match ('function\s+' + [regex]::Escape($f))
        }
    }
}

Describe 'Get-ServerList' {
    It 'aceita lista e remove duplicatas' {
        (Get-ServerList -ComputerName @('WEB01','WEB01','WEB02')).Count | Should -Be 2
    }
    It 'falha de forma explicita com arquivo inexistente' {
        { Get-ServerList -ComputerListFile 'Z:\nao\existe.txt' } | Should -Throw
    }
}
