<#
    Testes das funcoes puras de Deploy-IISCertificate.ps1.

    O script e carregado com dot-source; a guarda de InvocationName faz com que ele apenas
    defina as funcoes, sem conectar em servidor nenhum.

        Invoke-Pester -Path .\Tests
#>

$ScriptPath = Join-Path (Split-Path -Parent $PSScriptRoot) 'Deploy-IISCertificate.ps1'
. $ScriptPath

function New-TestCert {
    param([string]$Subject = 'CN=*.energisa.com.br', [string[]]$Dns = @('*.energisa.com.br','energisa.com.br'))
    $rsa = [System.Security.Cryptography.RSA]::Create(2048)
    $req = New-Object System.Security.Cryptography.X509Certificates.CertificateRequest(
        $Subject, $rsa,
        [System.Security.Cryptography.HashAlgorithmName]::SHA256,
        [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
    if ($Dns) {
        $san = New-Object System.Security.Cryptography.X509Certificates.SubjectAlternativeNameBuilder
        foreach ($d in $Dns) { $san.AddDnsName($d) }
        $req.CertificateExtensions.Add($san.Build())
    }
    return $req.CreateSelfSigned([DateTimeOffset]::UtcNow.AddDays(-1), [DateTimeOffset]::UtcNow.AddDays(365))
}

function New-Binding {
    param(
        [string]$Site = 'Default Web Site', [string]$HostName = 'app.energisa.com.br',
        [string]$Ip = '*', [string]$Porta = '443', [string]$Thumbprint = 'A' * 40, [int]$SslFlags = 1
    )
    [pscustomobject]@{
        Site = $Site; HostName = $HostName; Ip = $Ip; Porta = $Porta
        Thumbprint = $Thumbprint; SslFlags = $SslFlags
        BindingInfo = ('{0}:{1}:{2}' -f $Ip, $Porta, $HostName)
    }
}

$NovoThumb = 'B' * 40

# ================================================================= TESTES

Describe 'Test-HostNameMatchesCertificate: regras da RFC 6125' {
    $nomes = @('*.energisa.com.br', 'energisa.com.br')

    It 'o curinga cobre um rotulo a esquerda' {
        Test-HostNameMatchesCertificate -HostName 'app.energisa.com.br' -CertificateNames $nomes | Should -BeTrue
    }
    It 'o curinga NAO cobre o dominio sem rotulo, mas a SAN exata cobre' {
        Test-HostNameMatchesCertificate -HostName 'energisa.com.br' -CertificateNames @('*.energisa.com.br') | Should -BeFalse
        Test-HostNameMatchesCertificate -HostName 'energisa.com.br' -CertificateNames $nomes | Should -BeTrue
    }
    It 'o curinga NAO cobre dois niveis de subdominio' {
        Test-HostNameMatchesCertificate -HostName 'a.b.energisa.com.br' -CertificateNames $nomes | Should -BeFalse
    }
    It 'nao cobre outro dominio' {
        Test-HostNameMatchesCertificate -HostName 'app.energisa.corp' -CertificateNames $nomes | Should -BeFalse
    }
    It 'ignora diferenca de maiusculas e minusculas' {
        Test-HostNameMatchesCertificate -HostName 'APP.Energisa.Com.BR' -CertificateNames $nomes | Should -BeTrue
    }
    It 'tolera o ponto final do FQDN absoluto' {
        Test-HostNameMatchesCertificate -HostName 'app.energisa.com.br.' -CertificateNames $nomes | Should -BeTrue
    }
    It 'recusa hostname vazio ou nulo' {
        Test-HostNameMatchesCertificate -HostName ''    -CertificateNames $nomes | Should -BeFalse
        Test-HostNameMatchesCertificate -HostName $null -CertificateNames $nomes | Should -BeFalse
        Test-HostNameMatchesCertificate -HostName '   ' -CertificateNames $nomes | Should -BeFalse
    }
    It 'recusa lista de nomes vazia' {
        Test-HostNameMatchesCertificate -HostName 'app.energisa.com.br' -CertificateNames @() | Should -BeFalse
    }
    It 'recusa curinga que nao esteja no rotulo mais a esquerda' {
        Test-HostNameMatchesCertificate -HostName 'app.energisa.com.br' -CertificateNames @('energisa.*.br') | Should -BeFalse
        Test-HostNameMatchesCertificate -HostName 'app.energisa.com.br' -CertificateNames @('app.*.com.br')  | Should -BeFalse
    }
    It 'recusa curinga colado em texto, como ap*.energisa.com.br' {
        Test-HostNameMatchesCertificate -HostName 'app.energisa.com.br' -CertificateNames @('ap*.energisa.com.br') | Should -BeFalse
    }
    It 'recusa curinga amplo demais, como *.br' {
        Test-HostNameMatchesCertificate -HostName 'energisa.br' -CertificateNames @('*.br') | Should -BeFalse
    }
    It 'aceita nome exato sem curinga' {
        Test-HostNameMatchesCertificate -HostName 'portal.energisa.com.br' -CertificateNames @('portal.energisa.com.br') | Should -BeTrue
    }
}

Describe 'ConvertFrom-SslFlags' {
    It 'traduz cada bit isolado pelo nome correto' {
        ConvertFrom-SslFlags -Value 0  | Should -Be 'nenhuma'
        ConvertFrom-SslFlags -Value 1  | Should -Be 'SNI'
        ConvertFrom-SslFlags -Value 2  | Should -Be 'CentralCertStore'
        ConvertFrom-SslFlags -Value 4  | Should -Be 'DisableHTTP2'
        ConvertFrom-SslFlags -Value 8  | Should -Be 'DisableOCSPStapling'
        ConvertFrom-SslFlags -Value 16 | Should -Be 'DisableQUIC'
        ConvertFrom-SslFlags -Value 32 | Should -Be 'DisableTLS13'
        ConvertFrom-SslFlags -Value 64 | Should -Be 'DisableLegacyTLS'
    }
    It 'nao desloca os nomes ao combinar bits' {
        # Com [ordered]@{} o indexador [int] resolve por POSICAO e devolvia o nome vizinho.
        ConvertFrom-SslFlags -Value 9 | Should -Be 'SNI+DisableOCSPStapling'
        ConvertFrom-SslFlags -Value 3 | Should -Be 'SNI+CentralCertStore'
    }
    It 'sinaliza bit desconhecido em vez de ignorar' {
        ConvertFrom-SslFlags -Value 128 | Should -Match 'desconhecido'
    }
    It 'combina conhecido com desconhecido' {
        ConvertFrom-SslFlags -Value (1 -bor 128) | Should -Match 'SNI'
        ConvertFrom-SslFlags -Value (1 -bor 128) | Should -Match 'desconhecido'
    }
}

Describe 'Select-BindingAction: politica conservadora de selecao' {
    $nomes = @('*.energisa.com.br')

    It 'troca binding cujo hostname o certificado cobre' {
        $d = Select-BindingAction -Binding (New-Binding) -CertificateNames $nomes -NewThumbprint $NovoThumb
        $d.Trocar | Should -BeTrue
    }
    It 'NAO troca binding que o certificado nao cobre' {
        $b = New-Binding -HostName 'app.energisa.corp'
        $d = Select-BindingAction -Binding $b -CertificateNames $nomes -NewThumbprint $NovoThumb
        $d.Trocar | Should -BeFalse
        $d.Motivo | Should -Match 'nao cobre'
    }
    It 'NAO troca binding que ja usa o certificado novo' {
        $b = New-Binding -Thumbprint $NovoThumb
        $d = Select-BindingAction -Binding $b -CertificateNames $nomes -NewThumbprint $NovoThumb
        $d.Trocar | Should -BeFalse
        $d.Motivo | Should -Match 'ja usa'
    }
    It 'NAO troca binding de Central Certificate Store' {
        $b = New-Binding -SslFlags 3
        $d = Select-BindingAction -Binding $b -CertificateNames $nomes -NewThumbprint $NovoThumb
        $d.Trocar | Should -BeFalse
        $d.Motivo | Should -Match 'Central Certificate Store'
    }
    It 'NAO troca binding sem hostname por padrao' {
        $b = New-Binding -HostName ''
        $d = Select-BindingAction -Binding $b -CertificateNames $nomes -NewThumbprint $NovoThumb
        $d.Trocar | Should -BeFalse
        $d.Motivo | Should -Match 'IncludeEmptyHostName'
    }
    It 'troca binding sem hostname quando explicitamente autorizado' {
        $b = New-Binding -HostName ''
        $d = Select-BindingAction -Binding $b -CertificateNames $nomes -NewThumbprint $NovoThumb -IncludeEmptyHostName $true
        $d.Trocar | Should -BeTrue
    }
    It 'respeita o filtro de site' {
        $b = New-Binding -Site 'Outro Site'
        (Select-BindingAction -Binding $b -CertificateNames $nomes -NewThumbprint $NovoThumb -SiteName @('Default Web Site')).Trocar | Should -BeFalse
        (Select-BindingAction -Binding $b -CertificateNames $nomes -NewThumbprint $NovoThumb -SiteName @('Outro Site')).Trocar | Should -BeTrue
    }
    It 'respeita o filtro de hostname' {
        $b = New-Binding -HostName 'app.energisa.com.br'
        (Select-BindingAction -Binding $b -CertificateNames $nomes -NewThumbprint $NovoThumb -HostNameFilter 'portal.*').Trocar | Should -BeFalse
        (Select-BindingAction -Binding $b -CertificateNames $nomes -NewThumbprint $NovoThumb -HostNameFilter 'app.*').Trocar   | Should -BeTrue
    }
    It 'com -ReplaceThumbprint casa pelo thumbprint e ignora o hostname' {
        $antigo = 'C' * 40
        $b = New-Binding -HostName 'nada.a.ver.com' -Thumbprint $antigo
        $d = Select-BindingAction -Binding $b -CertificateNames $nomes -NewThumbprint $NovoThumb -ReplaceThumbprint $antigo
        $d.Trocar | Should -BeTrue
        $d.Motivo | Should -Match 'ReplaceThumbprint'
    }
    It 'com -ReplaceThumbprint nao toca em binding de outro certificado' {
        $b = New-Binding -Thumbprint ('D' * 40)
        (Select-BindingAction -Binding $b -CertificateNames $nomes -NewThumbprint $NovoThumb -ReplaceThumbprint ('C' * 40)).Trocar | Should -BeFalse
    }
    It 'compara thumbprint ignorando caixa e espacos' {
        $antigo = 'abcdef0123456789abcdef0123456789abcdef01'
        $b = New-Binding -Thumbprint $antigo.ToUpper()
        (Select-BindingAction -Binding $b -CertificateNames $nomes -NewThumbprint $NovoThumb -ReplaceThumbprint "$antigo ").Trocar | Should -BeTrue
    }
    It 'sempre devolve um motivo, inclusive quando troca' {
        (Select-BindingAction -Binding (New-Binding) -CertificateNames $nomes -NewThumbprint $NovoThumb).Motivo | Should -Not -BeNullOrEmpty
    }
}

Describe 'Get-SharedBindingWarning' {
    It 'avisa quando bindings sem SNI dividem o mesmo IP:porta' {
        $a = New-Binding -Site 'Site A' -HostName 'a.energisa.com.br' -SslFlags 0
        $b = New-Binding -Site 'Site B' -HostName 'b.energisa.com.br' -SslFlags 0
        Get-SharedBindingWarning -Binding $a -TodosOsBindings @($a, $b) | Should -Match 'Site B'
    }
    It 'nao avisa quando o binding usa SNI' {
        $a = New-Binding -Site 'Site A' -HostName 'a.energisa.com.br' -SslFlags 1
        $b = New-Binding -Site 'Site B' -HostName 'b.energisa.com.br' -SslFlags 1
        Get-SharedBindingWarning -Binding $a -TodosOsBindings @($a, $b) | Should -BeNullOrEmpty
    }
    It 'nao avisa quando o binding esta sozinho no IP:porta' {
        $a = New-Binding -Site 'Site A' -SslFlags 0
        Get-SharedBindingWarning -Binding $a -TodosOsBindings @($a) | Should -BeNullOrEmpty
    }
    It 'nao avisa quando as portas diferem' {
        $a = New-Binding -Site 'Site A' -Porta '443' -SslFlags 0
        $b = New-Binding -Site 'Site B' -Porta '8443' -SslFlags 0
        Get-SharedBindingWarning -Binding $a -TodosOsBindings @($a, $b) | Should -BeNullOrEmpty
    }
}

Describe 'Read-NetshSslCert: independente do idioma do Windows' {
    $enUS = @"
SSL Certificate bindings:
-------------------------

    IP:port                      : 0.0.0.0:443
    Certificate Hash             : 1A2B3C4D5E6F708192A3B4C5D6E7F8091A2B3C4D
    Application ID               : {4dc3e181-e14b-4a21-b022-59fc669b0914}
    Certificate Store Name       : My

    Hostname:port                : app.energisa.com.br:443
    Certificate Hash             : 99887766554433221100FFEEDDCCBBAA99887766
    Certificate Store Name       : My
"@

    $ptBR = @"
Ligacoes do Certificado SSL:
----------------------------

    IP:porta                            : 0.0.0.0:443
    Hash do Certificado                 : 1A2B3C4D5E6F708192A3B4C5D6E7F8091A2B3C4D
    ID do Aplicativo                    : {4dc3e181-e14b-4a21-b022-59fc669b0914}
    Nome do Repositorio de Certificados : My

    Nome do host:porta                  : app.energisa.com.br:443
    Hash do Certificado                 : 99887766554433221100FFEEDDCCBBAA99887766
"@

    It 'le as entradas na saida em ingles' {
        $r = Read-NetshSslCert -Text $enUS
        $r.Count | Should -Be 2
        ($r | Where-Object Endereco -eq '0.0.0.0:443').Thumbprint | Should -Be '1A2B3C4D5E6F708192A3B4C5D6E7F8091A2B3C4D'
    }
    It 'le exatamente as mesmas entradas na saida em portugues' {
        $r = Read-NetshSslCert -Text $ptBR
        $r.Count | Should -Be 2
        ($r | Where-Object Endereco -eq 'app.energisa.com.br:443').Thumbprint | Should -Be '99887766554433221100FFEEDDCCBBAA99887766'
    }
    It 'nao confunde o Application ID com um thumbprint' {
        (Read-NetshSslCert -Text $enUS | Where-Object Endereco -eq '0.0.0.0:443').Thumbprint | Should -Not -Match '4dc3e181'
    }
    It 'entende endereco IPv6 entre colchetes' {
        $t = "    IP:port    : [::]:443`r`n    Certificate Hash : AABBCCDDEEFF00112233445566778899AABBCCDD`r`n"
        (Read-NetshSslCert -Text $t)[0].Endereco | Should -Be '[::]:443'
    }
    It 'devolve colecao vazia para texto vazio ou sem bindings' {
        # atribuir a variavel, e nao re-embrulhar com @(): o valor devolvido ja e a colecao
        $vazio = Read-NetshSslCert -Text ''
        $vazio.Count | Should -Be 0
        $solto = Read-NetshSslCert -Text 'Nenhum binding de certificado SSL.'
        $solto.Count | Should -Be 0
    }
    It 'nao lanca excecao com entrada nula' {
        { Read-NetshSslCert -Text $null } | Should -Not -Throw
    }
}

Describe 'Get-ThumbprintFromBytes' {
    It 'converte bytes para hexadecimal maiusculo sem separador' {
        Get-ThumbprintFromBytes -Bytes ([byte[]]@(0x0A, 0xFF, 0x00, 0x1B)) | Should -Be '0AFF001B'
    }
    It 'preserva o zero a esquerda de cada byte' {
        Get-ThumbprintFromBytes -Bytes ([byte[]]@(0x01, 0x02)) | Should -Be '0102'
    }
    It 'devolve vazio para entrada nula ou vazia' {
        Get-ThumbprintFromBytes -Bytes $null        | Should -BeNullOrEmpty
        Get-ThumbprintFromBytes -Bytes ([byte[]]@()) | Should -BeNullOrEmpty
    }
    It 'faz ida e volta com o thumbprint de um certificado real' {
        $c = New-TestCert
        Get-ThumbprintFromBytes -Bytes $c.GetCertHash() | Should -Be $c.Thumbprint.ToUpperInvariant()
    }
}

Describe 'Get-CertificateSubjectNames' {
    It 'devolve o CN e as SANs de DNS' {
        $c = New-TestCert
        $n = Get-CertificateSubjectNames -Certificate $c
        $n | Should -Contain '*.energisa.com.br'
        $n | Should -Contain 'energisa.com.br'
    }
    It 'funciona em certificado sem extensao SAN, usando so o CN' {
        $c = New-TestCert -Subject 'CN=legado.energisa.com.br' -Dns @()
        (Get-CertificateSubjectNames -Certificate $c) | Should -Contain 'legado.energisa.com.br'
    }
    It 'nao repete nomes presentes no CN e na SAN' {
        $c = New-TestCert -Subject 'CN=app.energisa.com.br' -Dns @('app.energisa.com.br')
        $n = Get-CertificateSubjectNames -Certificate $c
        @($n | Where-Object { $_ -eq 'app.energisa.com.br' }).Count | Should -Be 1
    }
    It 'devolve colecao vazia para certificado nulo' {
        $n = Get-CertificateSubjectNames -Certificate $null
        $n.Count | Should -Be 0
    }
    It 'alimenta corretamente o casamento de hostname' {
        $c = New-TestCert
        $n = Get-CertificateSubjectNames -Certificate $c
        Test-HostNameMatchesCertificate -HostName 'enova.energisa.com.br' -CertificateNames $n | Should -BeTrue
        Test-HostNameMatchesCertificate -HostName 'enova.energisa.corp'   -CertificateNames $n | Should -BeFalse
    }
}

Describe 'Get-ServerList' {
    It 'aceita lista por parametro' {
        (Get-ServerList -ComputerName @('WEB01','WEB02')).Count | Should -Be 2
    }
    It 'remove duplicatas' {
        (Get-ServerList -ComputerName @('WEB01','web01','WEB02')).Count | Should -BeLessOrEqual 3
        (Get-ServerList -ComputerName @('WEB01','WEB01')).Count | Should -Be 1
    }
    It 'le arquivo ignorando comentarios e linhas vazias' {
        $tmp = Join-Path ([System.IO.Path]::GetTempPath()) ('srv-{0}.txt' -f ([guid]::NewGuid()))
        @('# comentario', '', 'WEB01', '   ', 'WEB02  ') | Set-Content -LiteralPath $tmp
        try {
            $l = Get-ServerList -ComputerListFile $tmp
            $l.Count | Should -Be 2
            $l | Should -Contain 'WEB01'
            $l | Should -Contain 'WEB02'
        } finally { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue }
    }
    It 'falha de forma explicita quando o arquivo nao existe' {
        { Get-ServerList -ComputerListFile 'Z:\nao\existe.txt' } | Should -Throw
    }
}

Describe 'New-RemoteScriptBlock' {
    It 'monta codigo sintaticamente valido' {
        # O bloco remoto e montado por injecao de texto; um erro de sintaxe aqui so apareceria
        # no servidor de destino, no meio de um deploy.
        $sb = New-RemoteScriptBlock
        $erros = $null
        [void][System.Management.Automation.Language.Parser]::ParseInput($sb.ToString(), [ref]$null, [ref]$erros)
        $erros | Should -BeNullOrEmpty
    }
    It 'injeta todas as funcoes auxiliares que o corpo remoto usa' {
        $txt = (New-RemoteScriptBlock).ToString()
        foreach ($f in @('Test-HostNameMatchesCertificate','ConvertFrom-SslFlags','Select-BindingAction',
                         'Get-SharedBindingWarning','Read-NetshSslCert','Get-ThumbprintFromBytes')) {
            $txt | Should -Match ("function\s+" + [regex]::Escape($f))
        }
    }
    It 'tem um bloco de parametros REAL, reconhecido pelo parser' {
        # Procurar o texto 'param(...)' nao basta: se ele vier depois de qualquer outra
        # instrucao, o PowerShell o trata como chamada de um comando chamado 'param', nao
        # vincula argumento nenhum e o bloco remoto roda inteiro com as variaveis nulas --
        # relatando "ignorado" para bindings que deveriam ser trocados. O parser e quem diz.
        $ast = (New-RemoteScriptBlock).Ast
        $ast.ParamBlock | Should -Not -BeNullOrEmpty
        $ast.ParamBlock.Parameters.Count | Should -Be 2
        @($ast.ParamBlock.Parameters | ForEach-Object { $_.Name.VariablePath.UserPath }) | Should -Be @('Ctx','Senha')
    }
    It 'coloca o param antes de qualquer definicao de funcao' {
        $txt = (New-RemoteScriptBlock).ToString()
        $posParam = $txt.IndexOf('param(')
        $posFunc  = $txt.IndexOf('function ')
        $posParam | Should -BeGreaterThan -1
        $posParam | Should -BeLessThan $posFunc
    }
}

Describe 'Get-RemotingErrorHint: traducao do erro do WinRM' {
    It 'reconhece "Access is denied" como problema de autorizacao, nao de rede' {
        $h = Get-RemotingErrorHint -Message 'Connecting to remote server SRV01 failed with the following error message : Access is denied.'
        $h | Should -Match 'direito de administracao remota'
        $h | Should -Match 'Remote Management Users'
    }
    It 'reconhece a mesma falha em portugues' {
        Get-RemotingErrorHint -Message 'Acesso negado.' | Should -Match 'direito de administracao remota'
    }
    It 'lembra do UAC remoto para conta local' {
        Get-RemotingErrorHint -Message 'Access is denied.' | Should -Match 'LocalAccountTokenFilterPolicy'
    }
    It 'separa falha de DNS' {
        Get-RemotingErrorHint -Message 'The name cannot be resolved' | Should -Match 'DNS'
    }
    It 'separa TrustedHosts de Kerberos' {
        Get-RemotingErrorHint -Message 'the destination machine must be added to the TrustedHosts configuration setting' | Should -Match 'TrustedHosts'
    }
    It 'separa WinRM indisponivel de problema de conta' {
        $h = Get-RemotingErrorHint -Message 'WinRM cannot complete the operation. Verify that the specified computer name is valid'
        $h | Should -Match 'WinRM nao respondeu'
        $h | Should -Match '5985'
    }
    It 'reconhece tempo esgotado' {
        Get-RemotingErrorHint -Message 'The operation has timed out.' | Should -Match 'Tempo esgotado|tempo esgotado'
    }
    It 'nunca devolve vazio' {
        Get-RemotingErrorHint -Message ''    | Should -Not -BeNullOrEmpty
        Get-RemotingErrorHint -Message $null | Should -Not -BeNullOrEmpty
        Get-RemotingErrorHint -Message 'mensagem completamente nova' | Should -Not -BeNullOrEmpty
    }
}

Describe 'Test-RemotingReachability' {
    It 'relata que nenhuma porta do WinRM atendeu quando o host nao escuta' {
        Test-RemotingReachability -Computer '127.0.0.1' -TimeoutMs 500 | Should -Match 'nenhuma porta'
    }
    It 'nao lanca excecao com host inexistente' {
        { Test-RemotingReachability -Computer 'host.que.nao.existe.invalido' -TimeoutMs 500 } | Should -Not -Throw
    }
}

Describe 'ConvertFrom-SecureStringPlain' {
    It 'devolve o texto original' {
        $sec = ConvertTo-SecureString 'SenhaDeTeste123' -AsPlainText -Force
        ConvertFrom-SecureStringPlain -Secure $sec | Should -BeExactly 'SenhaDeTeste123'
    }
    It 'preserva acentos e simbolos' {
        $sec = ConvertTo-SecureString 'Senh@ com ACENTO e #$%' -AsPlainText -Force
        ConvertFrom-SecureStringPlain -Secure $sec | Should -BeExactly 'Senh@ com ACENTO e #$%'
    }
    It 'devolve nulo para entrada nula, sem lancar excecao' {
        ConvertFrom-SecureStringPlain -Secure $null | Should -BeNullOrEmpty
    }
    It 'nunca devolve a literal do tipo, que era o bug' {
        # Passar o SecureString direto para uma API sem essa sobrecarga faz o PowerShell
        # converter por ToString(), e a senha vira "System.Security.SecureString".
        $sec = ConvertTo-SecureString 'abc' -AsPlainText -Force
        ConvertFrom-SecureStringPlain -Secure $sec | Should -Not -Be 'System.Security.SecureString'
        [string]$sec | Should -Be 'System.Security.SecureString'   # comportamento que causou o bug
    }
    It 'abre de fato um PFX, que e o uso real' {
        $rsa = [System.Security.Cryptography.RSA]::Create(2048)
        $req = New-Object System.Security.Cryptography.X509Certificates.CertificateRequest(
            'CN=pfx.teste', $rsa,
            [System.Security.Cryptography.HashAlgorithmName]::SHA256,
            [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
        $cert = $req.CreateSelfSigned([DateTimeOffset]::UtcNow.AddDays(-1), [DateTimeOffset]::UtcNow.AddDays(30))
        $sec  = ConvertTo-SecureString 'p@ss123' -AsPlainText -Force
        $pfx  = $cert.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Pfx, 'p@ss123')

        $col = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2Collection
        { $col.Import($pfx, (ConvertFrom-SecureStringPlain -Secure $sec),
            [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::DefaultKeySet) } | Should -Not -Throw
        $col.Count | Should -BeGreaterThan 0
    }
}

Describe 'Bloco remoto: uso da senha' {
    It 'nao entrega o SecureString direto ao Import, que nao tem essa sobrecarga' {
        $txt = (New-RemoteScriptBlock).ToString()
        # -cmatch/-match no PowerShell ignora caixa, entao delimitar o fim da variavel:
        # sem isso, '$senhaTexto' (a correcao) casaria com '$Senha' e o teste falharia sozinho.
        $txt | Should -Not -Match '\.Import\(\$Ctx\.PfxBytes,\s*\$Senha\s*[,)]'
        $txt | Should -Match 'ConvertFrom-SecureStringPlain'
    }
}
