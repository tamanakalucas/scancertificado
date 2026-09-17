# Deploy-IISCertificate

Instala um PFX em servidores Windows remotos e refaz os bindings HTTPS do IIS **preservando as
configurações existentes**. Executa de uma estação central, via PSRemoting.

Complementa o `Get-CertInventory.ps1`: um descobre o que está vencendo, o outro troca.

## O que é preservado

O script escreve **dois campos** de cada binding — `CertificateHash` e `CertificateStoreName`
— e mais nada. Sobrevivem intactos:

| | |
|---|---|
| `sslFlags` | SNI, Central Certificate Store, DisableHTTP2, DisableOCSPStapling, DisableQUIC, DisableTLS13, DisableLegacyTLS |
| Endereçamento | IP, porta, hostname, a string de binding inteira |
| Estrutura | a ordem dos bindings, os demais bindings do site, o site em si |

O `sslFlags` é lido antes e relido depois de cada troca; qualquer diferença vira aviso no
relatório.

## Ensaio obrigatório na primeira vez

Sem `-Apply`, o script **não altera nada**: conecta, lê os bindings e mostra exatamente o que
mudaria, em quais servidores.

```powershell
# 1. ensaio — rode sempre assim primeiro
.\Deploy-IISCertificate.ps1 -PfxPath .\wildcard.pfx -AskPfxPassword `
    -ComputerListFile .\servidores.txt

# 2. efetivar, depois de conferir a tabela
.\Deploy-IISCertificate.ps1 -PfxPath .\wildcard.pfx -AskPfxPassword `
    -ComputerListFile .\servidores.txt -Apply -ReportCsv .\deploy.csv
```

Mesmo com `-Apply`, o script faz **dois passes**: o primeiro lê o estado atual (e é o backup),
o segundo aplica. Se algo falhar no meio, o backup já está gravado.

## Seleção conservadora dos bindings

Sem filtro explícito, o script só mexe em binding que atenda a **todas** estas condições:

- o hostname é coberto pelos nomes do certificado novo, com casamento de curinga correto;
- não aponta já para o certificado novo;
- não usa Central Certificate Store.

E **não toca** em binding sem hostname, a menos que você passe `-IncludeEmptyHostName`. Num
binding sem hostname e sem SNI o certificado vale para todo o IP:porta, então a troca atinge
todos os sites que dividem aquele IP:porta — inclusive os que o curinga não cobre. O script
detecta essa situação e avisa antes.

O casamento de curinga segue a RFC 6125, e isso importa:

| Certificado | Hostname | Resultado |
|---|---|---|
| `*.energisa.com.br` | `app.energisa.com.br` | **cobre** |
| `*.energisa.com.br` | `energisa.com.br` | não cobre (falta o rótulo) |
| `*.energisa.com.br` | `a.b.energisa.com.br` | não cobre (sobra rótulo) |
| `*.energisa.com.br` | `app.energisa.corp` | não cobre |

Errar isso significaria trocar o certificado de um site que o curinga não cobre e derrubá-lo
com erro de nome. Para o caso previsível, prefira `-ReplaceThumbprint <thumb-antigo>`: troca
exatamente os bindings que hoje usam o certificado que está vencendo, sem depender de nome.

## Senha do PFX

Três formas, em ordem de preferência:

```powershell
# interativo: sem eco, sem passar pela linha de comando
-AskPfxPassword

# desatendido (tarefa agendada, SCCM): senha protegida por DPAPI
# gere UMA VEZ, na mesma conta e máquina que rodarão o deploy:
Read-Host 'Senha do PFX' -AsSecureString | ConvertFrom-SecureString | Set-Content .\senha-pfx.txt
-PfxPasswordFile .\senha-pfx.txt

# de dentro de um script PowerShell, com a senha já em SecureString
-PfxPassword $minhaSenha
```

**`-PfxPassword` não funciona com `powershell.exe -File`**: a linha de comando entrega texto e
nada se converte em `SecureString`. Para automação, use `-PfxPasswordFile`.

Nunca digite a senha direto na linha de comando. O filtro do PSReadLine não conhece esses
parâmetros e gravaria a linha inteira em texto puro no `ConsoleHost_history.txt`.

A senha trafega como `SecureString` pela sessão do PSRemoting, criptografada por Kerberos ou
HTTPS. **Não use autenticação Basic sobre HTTP**, onde ela iria em claro.

### Uma armadilha do PowerShell que vale conhecer

`X509Certificate2Collection.Import` **não tem sobrecarga para `SecureString`** — só para
`string`. Entregando o `SecureString` direto, o PowerShell o converte por `ToString()` e a senha
vira a literal `System.Security.SecureString`, que o Windows reporta como
*"The specified network password is not correct"* — indistinguível de senha errada de verdade.

O construtor de `X509Certificate2`, usado na leitura local, **tem** essa sobrecarga. Por isso o
sintoma só aparece na importação remota, depois de a fase local ter exibido o certificado
corretamente. O script converte em memória via BSTR e zera o buffer em seguida.

## Cadeia e chave privada

O PFX costuma trazer a cadeia. O script instala a folha em `LocalMachine\My` e as
**intermediárias em `LocalMachine\CA`** — sem isso o servidor serve cadeia incompleta e o
cliente reclama, que é o mesmo problema que o `Get-CertInventory` reporta como
`CadeiaCompleta: INCOMPLETA`.

Uma CA **raiz** presente no PFX **não** é instalada: colocar algo em `Root` é decisão de
confiança, não de deploy. O script avisa e segue.

A chave é importada como **não exportável** por padrão. Um curinga replicado em dezenas de
servidores não deveria poder ser reexportado de cada um deles. Use `-Exportable` se precisar.

**ACL da chave privada:** não é alterada, e para binding de IIS isso está correto — quem
apresenta o certificado é o HTTP.SYS, que roda como SYSTEM. Só é preciso conceder leitura da
chave ao application pool se a *aplicação* usar o certificado diretamente (autenticação por
certificado de cliente, assinatura). Nesse caso, faça à parte.

## Verificação em duas camadas

Depois do commit, o script confere o thumbprint em dois lugares:

1. na configuração do IIS, relendo o binding;
2. no **HTTP.SYS**, via `netsh http show sslcert` — porque quem atende o cliente é o HTTP.SYS,
   e os dois podem divergir.

O parser do `netsh` se guia pelos **valores** (o par `endereço:porta` e o thumbprint de 40
hexadecimais), não pelos rótulos, que são traduzidos em Windows pt-BR.

## Rollback

Antes de qualquer escrita, o estado de cada binding vai para um JSON:

```powershell
.\Deploy-IISCertificate.ps1 -Rollback .\rollback-20260916-140233.json
```

O certificado antigo **não é removido**, justamente para o rollback funcionar. Remova-o depois,
por processo próprio, quando tiver confiança.

## Parâmetros principais

| Parâmetro | Efeito |
|---|---|
| `-PfxPath` | o .pfx na estação onde o script roda |
| `-AskPfxPassword` / `-PfxPasswordFile` / `-PfxPassword` | senha, em ordem de preferência |
| `-ComputerName` / `-ComputerListFile` | servidores de destino |
| `-Credential`, `-UseSsl` | credencial administrativa e WinRM sobre HTTPS |
| `-Apply` | efetiva; sem ele, é ensaio |
| `-ReplaceThumbprint` | troca por thumbprint em vez de por hostname |
| `-SiteName`, `-HostNameFilter` | restringem o alcance |
| `-IncludeEmptyHostName` | autoriza bindings sem hostname |
| `-Exportable` | importa a chave como exportável |
| `-BackupPath`, `-Rollback` | backup e desfazer |
| `-ThrottleLimit` | servidores em paralelo (padrão 8) |
| `-ReportCsv`, `-LogFile` | relatório e log |

`Get-Help .\Deploy-IISCertificate.ps1 -Full` traz todos.

## Por que cada binding foi ignorado

O relatório lista os motivos agrupados, não só a contagem:

```
Resumo
----------------------------------------------------
  TROCARIA (ensaio)                        3
  ignorado                                 2

Por que cada binding foi ignorado
----------------------------------------------------
    1x  ja usa o certificado novo
    1x  o certificado novo nao cobre intranet.energisa.corp (nomes: *.energisa.com.br, energisa.com.br)
```

Sem isso, um binding ignorado por engano passa despercebido — foi exatamente assim que um bug
de montagem do bloco remoto sobreviveu a um ensaio inteiro.

## Quando o servidor não responde

O script separa **"não consegui chegar lá"** de **"cheguei e não achei bindings"**, e traduz o
erro do WinRM para a causa provável:

```
Servidores: 0 de 1 responderam

  ACSISGMAPLH1.energisa.corp: NAO RESPONDEU
    erro  : Connecting to remote server ... failed ... Access is denied.
    causa : a conta usada nao tem direito de administracao remota NESTE servidor.
            Confira: (1) a conta e Administrador local ou membro de "Remote Management
            Users" no destino; (2) para conta LOCAL do destino, o UAC remoto bloqueia por
            padrao -- veja LocalAccountTokenFilterPolicy; (3) tente com -Credential de uma
            conta administrativa do dominio.
    rede  : WinRM atende em 5985/HTTP: a rede esta ok, o problema e de autenticacao ou
            autorizacao
```

A linha `rede` testa as portas 5985/5986 e é o que separa problema de firewall de problema de
conta. Se a porta atende e o erro é `Access is denied`, **não é rede** — é autorização.

Erros reconhecidos: acesso negado (en e pt-BR), DNS, TrustedHosts, Kerberos, WinRM
indisponível, tempo esgotado e certificado do listener HTTPS.

## Requisitos

PSRemoting habilitado nos destinos, conta administrativa, IIS 7.5+. Usa
`Microsoft.Web.Administration`, que acompanha o IIS — não exige o módulo `WebAdministration`
nem nada da PSGallery.

## Testes

```powershell
Invoke-Pester -Path .\Tests
```

54 testes das funções puras: casamento de curinga pela RFC 6125, decodificação de `sslFlags`,
política de seleção de bindings, aviso de binding compartilhado, parser do `netsh` em en-US e
pt-BR, conversão de thumbprint, leitura de nomes do certificado e montagem do bloco remoto.

O teste de montagem do bloco remoto existe por um motivo prático: o código que roda no servidor
é montado por injeção de texto, e um erro de sintaxe ali só apareceria no meio de um deploy.

## Limitação conhecida

A lógica pura foi testada; **a parte que conversa com o IIS não pôde ser exercitada no ambiente
de desenvolvimento**, que não tem Windows. Valide em um servidor de homologação antes de usar
em produção — o modo ensaio existe exatamente para isso.
