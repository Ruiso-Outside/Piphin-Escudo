# Piphin Escudo

Verifica se o PC tem **sinais de invasão** ou **brechas de segurança**, explica cada coisa em palavras simples e corrige com um clique (com Desfazer). Módulo do [Piphin Hub](https://github.com/Ruiso-Outside/Piphin-Hub) (cerca de 120 KB).

A verificação **só olha**: nada muda no PC sem você mandar.

- A **rápida** leva uns 10 segundos.
- A **completa** pede permissão de administrador para ver também as exceções do antivírus, o registro de segurança, o BitLocker e o TPM.

## O que ele procura

**Sinais de invasão**
- Itens que abrem sozinhos com o Windows (Run, pasta Inicializar, tarefas agendadas) quando:
  - rodam comandos escondidos (PowerShell codificado, mshta, scripts);
  - não têm assinatura e ficam em pastas comuns.
- Serviços sem assinatura ou rodando da pasta Temp, e serviços novos nos últimos 30 dias.
- Truques conhecidos de invasores:
  - **teclas de acessibilidade trocadas** (porta dos fundos na tela de login);
  - programas desviados (IFEO "Debugger");
  - login do Windows alterado (Shell/Userinit);
  - AppInit_DLLs;
  - **gatilhos WMI escondidos**.
- Programas **fingindo ser do Windows** (svchost.exe fora da pasta do Windows) e programas rodando de pastas estranhas.
- Executáveis e scripts novos, sem assinatura, soltos em AppData, Temp e ProgramData.
- **Arquivo hosts** desviando bancos e sites importantes, ou bloqueando sites de antivírus.
- **Proxy** e **DNS colocado à mão** desconhecidos.
- **Programas de acesso remoto** (AnyDesk, TeamViewer, RustDesk e mais 30), os preferidos dos golpistas.
- Ameaças já encontradas pelo antivírus e o antivírus desligado recentemente.
- **Registros do Windows apagados**.
- Na verificação completa:
  - **exceções do antivírus**;
  - contas criadas;
  - contas que viraram administradoras;
  - **tentativas de senha pela rede** (força bruta).
- Contas escondidas (terminadas em `$`) e outras contas de administrador.
- Extensões de navegador instaladas de fora da loja.

**Brechas e proteção do Windows**
- Antivírus, proteção contra adulteração e definições de vírus.
- Firewall, Windows Update e Windows 10 sem suporte.
- UAC, SmartScreen, SMBv1, Área de Trabalho Remota, Assistência Remota e SSH.
- Login automático com a senha guardada.
- Portas perigosas abertas para a rede e pastas compartilhadas.
- Wi-Fi sem senha ou WEP.
- Secure Boot, Integridade de Memória e BitLocker.

Resultado: **nota de 0 a 100**, um veredito de invasão e os **pontos fortes** do PC.

## Mais

- **Correções** com um clique, cada uma com **Desfazer**. Exemplos:
  - tirar da inicialização;
  - desativar tarefa ou serviço;
  - limpar o hosts;
  - desligar o proxy;
  - retirar exceções do antivírus;
  - desligar a Área de Trabalho Remota e o SMBv1;
  - ligar o firewall e o UAC.

  O que precisa de administrador vai junto, num pedido só do Windows.
- **Vigia**: a cada 15 minutos, com o Hub aberto, confere se algo novo passou a abrir com o Windows, se apareceu conta, se o hosts ou o proxy mudaram, etc. Avisa com uma notificação.
- **Minha senha vazou?**: confere em mais de 900 milhões de senhas vazadas (Have I Been Pwned). Só 5 caracteres do código SHA-1 saem do PC; a senha não.
- **Gerador de senhas**: aleatórias ou fáceis de lembrar, com palavras em português.
- **Antivírus**: verificação rápida, completa e **offline** (antes do Windows abrir), mais atualizar e verificar arquivos suspeitos.
- **Modo emergência**: o passo a passo para quem acha que foi invadido ou caiu num golpe.
- **IA**: com o Piphin LLM, a IA lê a última verificação e explica os problemas.

## Estrutura

`module/`:

| Arquivo | O que faz |
|---|---|
| `collect.ps1` | coleta, só leitura |
| `analyze.js` | as regras: achados, gravidade, nota |
| `fixes.js` | correções e desfazer, por um `.ps1` temporário; o que precisa de administrador vai num pedido só |
| `backend.js` | junta tudo, mais o Vigia |

`web/` é a tela.

```
npm run icons    # ícones (Lucide) em web/icons.css
npm run icon     # icons/escudo.png
npm run module   # dist/piphin-module-escudo-<versão>.zip
```
