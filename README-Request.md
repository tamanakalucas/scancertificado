# Request-IISCertificate

Renova certificados emitidos pela **CA interna (AD CS)** em servidores Windows remotos,
reaproveitando o Common Name e as SANs do certificado atual, e refaz os bindings do IIS
preservando as configurações existentes.

Automatiza o que hoje se faz na mão pelo `certlm.msc`: *Todas as Tarefas → Solicitar Novo
Certificado → política de inscrição do AD → preencher Nome Comum e Nome Alternativo → Inscrever*,
e depois refazer o binding.

Pressupõe que o servidor **já está na OU** que concede Inscrição no template. O script não mexe
em AD, em OU nem em permissão de template.

## A chave privada nunca sai do servidor

Diferente do deploy por PFX (`Deploy-IISCertificate.ps1`), aqui o par de chaves é gerado no
próprio servidor e só a solicitação vai até a CA. **Não há arquivo, não há senha e não há nada
para transportar** — o que elimina de uma vez a classe de problema que o outro script precisa
tratar.

## Três fases

```powershell
# 1. Não sabe o nome do template? Rode sem -Template:
.\Request-IISCertificate.ps1 -ComputerName WSCCP-HO
#    lista os templates do AD com nome interno E nome de exibição, e encerra.

# 2. Varredura (somente leitura)
.\Request-IISCertificate.ps1 -ComputerName WSCCP-HO -Template 'Web Server Energisa V4'

# 3. Renovar
.\Request-IISCertificate.ps1 -ComputerName WSCCP-HO -Template 'Web Server Energisa V4' -Apply
```

A varredura mostra:

```
# Servidor CommonName               SANs                            ValidoAte  Dias Loja  Bindings
- -------- ----------               ----                            ---------  ---- ----  --------
1 WSCCP-HO wsccp-ho.energisa.com.br wsccp-ho.energisa.com.br, wsc…  2026-10-04   17 My    1x: Default Web Site [*:443:wsccp-ho…]
2 WSCCP-HO intranet.energisa.com.br intranet.energisa.com.br        2027-02-11  147 My    1x: Intranet [*:443:intranet…]

Quais renovar? Numeros (2), lista (1,3), faixa (1-3), "t" para todos, vazio para cancelar.
Escolha:
```

Sem `-Apply`, nada é solicitado nem alterado. Para pular o prompt: `-Thumbprint <hash>` ou `-All`.

## Nome interno × nome de exibição

Esta é a confusão mais comum do fluxo:

| Onde | O que aparece |
|---|---|
| Assistente do `certlm` | **Web Server Energisa V4** (nome de exibição) |
| Extensão do certificado | **WebServerEnergisaV4** (nome interno) |
| `Get-Certificate -Template` | espera o **nome interno** |

O script aceita os três (interno, exibição, OID), resolve um pelo outro consultando o AD, e
mostra qual usou. Rodar sem `-Template` lista os dois lado a lado.

## Como o script sabe de qual template veio cada certificado

Por duas extensões da Microsoft, que ele interpreta diretamente do DER:

| OID | Conteúdo |
|---|---|
| `1.3.6.1.4.1.311.20.2` | Nome do template, como **BMPString** (UTF‑16 **big** endian) |
| `1.3.6.1.4.1.311.21.7` | OID do template + versões maior e menor |

O detalhe do big endian não é cosmético: lendo como little endian o nome sai como caracteres
chineses. Há teste cobrindo exatamente isso.

## O que é repetido na renovação

O certificado novo sai com **o mesmo Common Name e as mesmas SANs** do antigo, lidos por parsing
ASN.1 da extensão `2.5.29.17` — não por `Format()`, cujo texto é localizado em Windows pt‑BR.

Se o CN não estiver entre as SANs do certificado antigo, ele é **acrescentado**: emissores
modernos recusam certificado cujo CN não aparece no SAN. E não é duplicado quando já está lá.

## O que é preservado no binding

Como no outro script: apenas `CertificateHash` e `CertificateStoreName` são escritos. Sobrevivem
`sslFlags` (SNI, CCS, HTTP/2, OCSP stapling, QUIC, TLS 1.3), IP, porta, hostname e a ordem dos
bindings. O `sslFlags` é relido depois e qualquer diferença vira aviso.

## Caminho da emissão

1. **`Get-Certificate`** (módulo PKI, Windows 8 / Server 2012+) — usa a política de inscrição do
   AD e encontra a CA sozinho. É o caminho principal.
2. **`certreq.exe`** com INF gerado — contingência para servidores mais antigos. Aqui é preciso
   `-CAConfig "servidor\nome-da-CA"`: sem isso o `certreq` tenta abrir a janela de escolha da CA,
   que não existe numa sessão remota. O script diz isso no erro.

Se a CA colocar a solicitação em **aprovação pendente**, o script reporta e não altera binding
nenhum — você emite manualmente e roda de novo.

## Identidade da inscrição

A inscrição de um template de **computador** autentica na CA com a **conta de máquina** do
servidor, não com a sua credencial. É por isso que funciona por PSRemoting sem CredSSP: não há
segundo salto de credencial de usuário.

Se o template exigir direito de Inscrição do **usuário**, esse caminho falha — e o erro vem com
essa explicação, para não mandar você procurar no lugar errado.

## Rollback

Antes de qualquer alteração de binding, o estado atual vai para um JSON:

```powershell
.\Request-IISCertificate.ps1 -Rollback .\rollback-req-20260917-101500.json
```

O rollback devolve o **binding** ao certificado anterior. O certificado antigo não é removido, e
o novo, uma vez emitido pela CA, continua emitido — revogar, se for o caso, é decisão separada.

## Parâmetros principais

| Parâmetro | Efeito |
|---|---|
| `-ComputerName` / `-ComputerListFile` | servidores de destino |
| `-Template` | nome interno, de exibição ou OID; sem ele, lista os disponíveis |
| `-Apply` | efetiva; sem ele, é ensaio |
| `-Thumbprint` / `-All` | escolhe sem prompt |
| `-ExpiringInDays` | só os que vencem nesse prazo |
| `-IncludeUnbound` | inclui certificados sem binding no IIS |
| `-CertificateStoreName` | `My`, `WebHosting` ou `Mesma` (padrão: a mesma do certificado renovado) |
| `-CAConfig` | `servidor\nome-da-CA`, só para o caminho `certreq` |
| `-Credential`, `-UseSsl` | credencial e WinRM sobre HTTPS |
| `-BackupPath`, `-Rollback` | backup e desfazer |
| `-ReportCsv`, `-LogFile` | relatório e log |

## Testes

```powershell
Invoke-Pester -Path .\Tests
```

53 testes das funções puras: parsing de OID em DER, extensões de template (incluindo o big
endian do BMPString), extração de CN e SANs, casamento de template por nome interno/exibição/OID,
interpretação da escolha do operador, geração do INF do `certreq`, resolução de nome de template
e montagem dos blocos remotos.

## Limitação conhecida

**A emissão em si não pôde ser exercitada no ambiente de desenvolvimento**, que não tem Windows,
AD nem CA. A lógica pura foi testada contra certificados construídos com as extensões reais da
Microsoft; o `Get-Certificate`, o `certreq` e o commit no IIS só você pode validar.

Por isso a varredura é somente leitura e o `-Apply` é obrigatório para qualquer escrita: rode a
varredura primeiro, confira a tabela, e teste o `-Apply` num servidor de homologação.
