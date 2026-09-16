# Get-CertInventory

Inventário de certificados TLS para parque misto Windows/Linux, em Windows PowerShell 5.1 e
PowerShell 7. Sem RSAT, sem módulos da PSGallery, sem privilégio administrativo.

## Por que a versão anterior deixava campos em branco

Quatro causas, verificadas contra servidores de teste e contra o `resultado.csv` real:

| Causa | Onde | Efeito |
|---|---|---|
| Certificado lido só **depois** de `AuthenticateAsClient` | l. 226‑228 da versão antiga | qualquer falha de handshake apagava 9 colunas |
| TLS 1.3 liberado por `PSEdition -eq 'Core'` | l. 217 | no 5.1 o TLS 1.3 **nunca** era oferecido, mesmo em Windows 11/Server 2022 |
| SANs por `Format($false)` | l. 234 | texto localizado (`Nome DNS=` em pt‑BR) quebra o parsing |
| `catch {}` vazios | l. 92, 149, 176 | erro de DNS e de PTR desapareciam sem registro |

A medição mais importante: **capturar o certificado no callback não basta**. Em servidor que
exige certificado de cliente, o .NET aborta antes da etapa de validação e o callback **não
dispara** — verificado com instrumentação. Por isso a leitura por ClientHello cru (M3) é o
mecanismo principal quando o `SslStream` falha, não um último recurso.

### O que os seus dados reais mostraram

Das 93 linhas de `resultado.csv`, a distribuição da causa raiz é:

| Causa | Linhas | % |
|---|---|---|
| TCP expirou (filtrado/firewall) | 33 | 35,5 % |
| TCP recusado — **porta 443 fechada** | 28 | 30,1 % |
| DNS não resolve | 15 | 16,1 % |
| RST durante o handshake TLS | 8 | 8,6 % |
| Certificado lido | 8 | 8,6 % |

**Dois terços dos brancos não são problema de TLS: são alvos que não atendem na 443.** As
melhorias de leitura de certificado atacam diretamente as 8 linhas de falha no handshake —
concentradas nos VIPs `10.83.101.9` e `10.83.103.33`, com cara de recusa por SNI. Para o
restante, o ganho é o diagnóstico: cada linha passa a dizer *por que* está vazia. Para
recuperar de fato esse inventário, use `-AlternatePorts` (ver abaixo) ou corrija as portas no
`endereco.txt`.

## Uso

```powershell
# básico: só métodos que não abrem portas extras
.\Get-CertInventory.ps1 -InputFile .\endereco.txt -OutputCsv .\resultado.csv

# hostname de servidor Linux: SNMP é o que mais resolve
.\Get-CertInventory.ps1 -InputFile .\endereco.txt -OutputCsv .\resultado.csv `
    -SnmpCommunity 'sua-community' -UseSshBanner -Verbose -LogFile .\scan.log

# hostname de servidor Windows: NTLM via SMB
.\Get-CertInventory.ps1 -InputFile .\endereco.txt -OutputCsv .\resultado.csv -UseSmb

# aplicações em porta não padrão (recomendado para o seu parque)
.\Get-CertInventory.ps1 -InputFile .\endereco.txt -OutputCsv .\resultado.csv `
    -AlternatePorts 8443,9443,8080

# investigar só o que falhou
.\Get-CertInventory.ps1 -InputFile .\endereco.txt -PassThru |
    Where-Object Situacao -ne 'OK' | Format-Table Entrada,IP,StatusTLS,DetalheTLS
```

`Get-Help .\Get-CertInventory.ps1 -Full` traz todos os parâmetros.

## Estratégia de leitura do certificado

Executada em sequência, parando na primeira que entregar o certificado. A coluna
`MetodoLeitura` registra qual funcionou.

| | Método | Serve para |
|---|---|---|
| **M1** | `SslStream` com todos os protocolos suportados | caso normal |
| **M2** | `SslStream` variando o SNI (CNAME, sem SNI) | virtual host por SNI |
| **M3** | ClientHello TLS 1.2 em socket bruto | mTLS, cipher fora do Schannel — **não depende do Schannel** |
| **M4** | `openssl s_client -showcerts` | servidor só TLS 1.3 no PowerShell 5.1 |

### Matriz por tipo de alvo

| Alvo | M1 | M2 | M3 | M4 |
|---|---|---|---|---|
| Windows IIS / AD | sim | sim | sim | sim |
| Linux nginx/Apache TLS 1.2+1.3 | sim | sim | sim | sim |
| **Linux só TLS 1.3** | PS7 sim / **PS5.1 não** | idem | **não** | **sim — único caminho** |
| **Linux exigindo mTLS** | **não** | não | **sim (com a cadeia)** | sim |
| **Linux cipher exótico (CHACHA20)** | PS5.1 não | não | **sim** | sim |
| Balanceador com vhost por SNI | devolve o cert padrão, em silêncio | **detecta** | sim | sim |
| STARTTLS SMTP/LDAP | sim | sim | sim | sim |

No **PowerShell 5.1** não existe `NegotiatedCipherSuite`; a coluna `CipherSuite` cai para
`CipherAlgorithm`/`KeyExchangeAlgorithm`/`HashAlgorithm`, e o conjunto de ciphers é o que o
Schannel da máquina permite (registro/GPO). O **M3 é idêntico nas duas versões** — essa é a
razão de ele existir.

## Identificação do hostname

Ordem de preferência, do mais autoritativo para o menos. O princípio: *o nome que o próprio
host informa sobre si* vence *o nome que o DNS informa sobre ele*, porque em VIP de balanceador
o PTR aponta para o balanceador. A coluna `OrigemHostname` sempre registra de onde veio o nome.

| # | Método | Porta | Windows | Linux + Samba | Linux puro | Ativação |
|---|---|---|---|---|---|---|
| 1 | SSH `hostname -f` | 22 | não | sim | **sim (autoritativo)** | `-SshUser`/`-SshKeyPath` |
| 2 | SNMP `sysName` | UDP 161 | se houver serviço | sim | **sim (melhor sem login)** | `-SnmpCommunity` |
| 3 | NTLM via SMB | 445 | **sim** | sim | não | `-UseSmb` |
| 4 | rootDSE LDAP | 389 | só DC | não | não | `-UseLdap` |
| 5 | NetBIOS | UDP 137 | sim | sim | não | padrão |
| 6 | Banner SMTP | 25 | parcial | sim | sim | `-UseSmtpBanner` |
| 7 | Certificado RDP | 3389 | sim | xrdp, genérico | não | `-UseRdp` |
| 8 | PTR | DNS | sim | sim | se houver zona reversa | padrão |
| 9 | CN/SAN do certificado | — | pista | pista | pista | padrão, marcado como pista |

Os métodos 3, 4, 6 e 7 abrem conexão em porta extra e podem gerar alerta no SOC, por isso cada
um tem o seu próprio switch e vem desligado.

## Colunas do CSV

Delimitador `;`, UTF‑8 **com BOM** nas duas versões do PowerShell (o `Export-Csv -Encoding UTF8`
grava BOM no 5.1 e **não** grava no PS 7; o script escreve o arquivo por conta própria para o
Excel pt‑BR ler igual nos dois). Datas em ISO 8601, independentes de cultura.

### Identificação
| Coluna | Conteúdo |
|---|---|
| `Entrada` | a linha original do arquivo |
| `Host`, `Porta` | host e porta após o parsing |
| `PortaUsada` | porta em que o certificado foi lido (difere de `Porta` se `-AlternatePorts` agiu) |
| `CNAME` | cadeia de CNAME, ou `sem CNAME` |
| `IP` | endereço da linha; uma linha por IP resolvido |
| `EntradasNoMesmoIP` | quantas entradas da lista compartilham este IP — **> 1 sugere VIP de balanceador** |

### Hostname e SO
| Coluna | Conteúdo |
|---|---|
| `Hostname` | nome descoberto, ou `nao identificado` |
| `OrigemHostname` | qual método devolveu o nome; `PISTA: CN/SAN…` quando veio do certificado |
| `SOProvavel` | `Windows`, `Linux`, `… (fraco)` ou `Desconhecido` — **estimativa** |
| `EvidenciaSO` | as evidências que sustentam a estimativa |

### Status por etapa
| Coluna | Conteúdo |
|---|---|
| `StatusDNS` / `DetalheDNS` | `OK` ou `FALHA`; o detalhe traz o erro do resolvedor e a contagem de registros por tipo (`Ax2`, `CNAMEx1`), o que separa "o resolvedor falhou" de "vieram registros sem A/AAAA" |
| `StatusHostname` / `DetalheHostname` | `OK`, `PISTA` ou `NAO IDENTIFICADO`; o detalhe lista **cada** método e seu resultado |
| `StatusTLS` / `DetalheTLS` | `OK`, `PARCIAL` (certificado lido sem handshake completo) ou `FALHA` |

### TLS
| Coluna | Conteúdo |
|---|---|
| `MetodoLeitura` | M1/M2/M3/M4 ou `nenhum metodo obteve o certificado` |
| `TlsVersao`, `CipherSuite` | negociados, quando houve handshake completo |
| `ExigeCertCliente` | `sim (servidor enviou CertificateRequest)` quando detectado |
| `SniUsado` | SNI que funcionou, ou `(sem SNI)` |
| `SniDivergente` | avisa quando SNIs diferentes devolvem certificados diferentes |
| `ErrosValidacao` | `SslPolicyErrors`, ou o motivo de não ter sido avaliado |

### Certificado
| Coluna | Conteúdo |
|---|---|
| `Subject`, `CN`, `Emissor` | identificação |
| `SANs` | por parsing ASN.1 da extensão `2.5.29.17`, independente de idioma |
| `ValidoDe`, `ValidoAte`, `DiasRestantes` | validade |
| `Situacao` | `OK`, `EXPIRA EM BREVE`, `EXPIRADO`, `FALHA TLS`, `FALHA DNS` |
| `AlgoritmoChave`, `TamanhoChave`, `AlgoritmoAssinatura`, `NumeroSerie`, `Thumbprint` | atributos |
| `CadeiaEnviada` | cadeia que o servidor enviou |
| `CadeiaCompleta` | avisa `INCOMPLETA` quando falta intermediário — erro comum de nginx/Apache |
| `CadeiaConfiavel` | se a cadeia valida na máquina que executou o script |

**Nenhuma coluna fica vazia sem motivo.** Sem valor, o campo traz a explicação
(`timeout TCP apos 5000 ms`, `porta fechada: nenhum servico escutando`, `sem PTR: …`,
`alerta TLS 70 (protocol_version): … tipicamente exige TLS 1.3`).

## Resumo por causa raiz

Ao fim da execução o script agrupa as linhas pela etapa em que pararam. Numa lista grande é o
que mostra o padrão — a tabela linha a linha, não:

```
Resumo por causa raiz
--------------------------------------------------------------
  TCP expirou: porta filtrada ou host inacessivel    33   35 %
  TCP recusado: nada escutando na porta              28   30 %
  DNS nao resolve o nome                             15   16 %
  conexao derrubada durante o handshake TLS           8    9 %
  certificado lido (OK)                               8    9 %

  61 linha(s) (65%) nem chegaram ao TLS: o alvo nao atende na porta consultada.
```

## Desempenho e IPv6

Runspaces compatíveis com o 5.1, `-ThrottleLimit` (padrão 16), cache por IP de hostname e de
inferência de SO, e timeouts separados: `-TcpTimeoutMs`, `-TlsTimeoutMs`, `-HostnameTimeoutMs`.

**O DNS roda no runspace principal, de propósito.** `Resolve-DnsName` é um cmdlet CDXML e
falha de forma intermitente sob vários runspaces concorrentes — os nomes com múltiplos
registros A são os primeiros a quebrar, porque devolvem mais objetos. O DNS é barato
(respostas locais ou em cache) e há um cache por nome, então nomes repetidos no `endereco.txt`
custam uma consulta só. Os runspaces ficam para o I/O de rede lento, que é onde rendem.

**IPv6 é decidido pela rota real da estação.** Sem `-PreferIPv4` explícito, o script verifica se
há endereço IPv6 global ativo; não havendo, ignora os registros AAAA e diz isso em
`DetalheDNS`. Numa estação sem IPv6, cada AAAA vira uma linha de falha que não acrescenta nada
ao inventário. Para forçar a tentativa, use `-PreferIPv4:$false`.

## Testes

```powershell
Install-Module Pester -Scope CurrentUser
Invoke-Pester -Path .\Tests
```

83 testes das funções puras: parsing de entrada, SAN ASN.1, ClientHello/Certificate TLS 1.2
(incluindo mensagem fragmentada em vários registros), NetBIOS, NTLM, SNMP, banner SMTP,
inferência de SO e os helpers binários.

Os helpers binários têm teste próprio por um motivo concreto: em PowerShell os operadores de
deslocamento **preservam o tipo do operando da esquerda**, então `[byte]3 -shl 8` devolve `0`,
não `768`, e trunca em silêncio. Durante o desenvolvimento isso fez um registro TLS de 976
bytes ser lido como 208, devolvendo zero certificados sem erro nenhum.

## Limitações conhecidas

- `SOProvavel` é **estimativa**, nunca fato. Samba faz um Linux responder como Windows no
  NetBIOS e no NTLM; xrdp faz o mesmo no RDP.
- Sem `openssl.exe`, servidor exclusivamente TLS 1.3 fica sem leitura no PowerShell 5.1. O
  script funciona sem ele, só com menos informação.
- O script **não varre portas**: usa a porta da entrada, as de `-AlternatePorts` (e só quando a
  principal recusa ou expira) e as dos métodos de hostname que você habilitar.
- A não-chamada do callback em handshake abortado foi medida no backend OpenSSL do .NET. No
  Schannel o comportamento pode diferir; o M3 cobre o caso de qualquer forma.
