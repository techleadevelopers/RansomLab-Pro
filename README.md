💀 RANSOMLAB-PRO v1.5 — MELHORIAS AVANÇADAS BRUTAIS
🔐 1. Encryptor.cs (Core Avançado)
 AES-256 CBC com geração de chave + IV únicos por arquivo

 RSA-Public Key Hybrid (criptografa a AES key)

 Filtro de extensões dinâmico

 SHA256 Hash Original + Hash do Encrypted

 Log JSON por arquivo: path, hash, tempo, UID

 Compressão opcional antes da criptografia (zlib)

 Verificação de arquivos já criptografados via extensão ou magic bytes

🔓 2. Decryptor.cs
 Validação de decrypt_<uid>.key

 UID obrigatório para execução (verifica integridade)

 Testa a chave no primeiro arquivo antes do lote

 Exporta log_recover_<uid>.json

 Modo CLI + GUI futura para clientes

🎭 3. AntiVM.cs + AntiDebug.cs
 Detecta: VirtualBox, VMWare, QEMU, Sandboxie, Hyper-V

 Verifica serviços, drivers e MAC address de VMs

 Monitora processos de debug (x64dbg, OllyDbg, IDA, Wireshark, etc.)

 Detecta DLLs hookadas (via ntdll.dll)

 Kill instantâneo ou simula falha crítica

🔁 4. StartupManager.cs
 Copia para %APPDATA%\Microsoft\OneDriveService\ (ou %LOCALAPPDATA%)

 Criação de entrada de registro em HKCU\Software\Microsoft\Windows\CurrentVersion\Run

 Renomeia para nome inofensivo (OneDriveSync, UpdateHost, etc.)

 Suporte a ícone spoof (PDF, Excel, Chrome)

 Self-replication + ocultar atributos do arquivo (+h +s +r)

🧾 5. RansomNoteGenerator.cs
 Template em HTML, TXT e modo fullscreen (WinForms)

 UID no corpo e QR Code Bitcoin dinâmico

 Timer de expiração (JavaScript visual)

 Texto multilíngue com LANG detectado via cultura .NET

 Link para painel falso (localhost ou web fake)

📤 6. EmailSender.cs + WebhookSender.cs
 Suporte a SMTP: Gmail, Outlook, ProtonMail

 Envio via Discord Webhook ou Telegram Bot

 Upload para Anonfiles e AnonPaste

 Payload: UID, AES Key, IP, sistema, hora, status do ataque

 Retry automático e fallback em caso de erro de rede

🕵️‍♂️ 7. UIDGenerator.cs + FileLogger.cs
 UID = SHA256(HWID + MAC + Timestamp UTC)

 Coleta: Username, Hostname, IP local/público

 Formatação de log JSON estruturado

 Exportação opcional para painel web (futuro)

⚙️ BuilderCLI.cs — CLI Profissional com Configs Dinâmicas
 CLI com estilo Terminal Hacker Brutal (Orbitron + neon)

 Opções interativas: nome do payload, extensões alvo, mensagem, modo forense, spoof

 Geração de:

Encryptor_<uid>.exe

Decryptor_<uid>.exe

ransom.html + ransom.txt

 ConfuserEx integrado no build final

 Compactação UPX opcional

 Exportação para pasta builds/

🧪 Modos Forenses
 --lab-mode: Mantém os arquivos originais, apenas gera logs

 --simulate-only: Coleta dados, UID, mostra ransom note sem afetar arquivos

 --dry-run: Apenas parse de diretórios, sem ação

 --stealth: Minimiza interface, oculta console, modo shadow

🧰 Ferramentas Forenses
📁 /forensic/:

✅ volatility/: Plugin para detectar padrões da criptografia

✅ procmon-filters/: Arquivos .pmf para rastrear operações no registro e disco

✅ detect-signature-hashes/: Lista com SHA256 de amostras

✅ forensic-manual.md: Manual completo de análise reversa

🧠 Integrações Avançadas
 ConfuserEx Neo como ofuscador final (crproj dentro do builder)

 Integração futura com Avalonia UI para GUI Win/Linux brutal

 Scripts de automação em PowerShell (bootlab.ps1, snap-create.ps1, etc.)

 snapshot-revert.bat: simulação reversível completa

💻 Interface HUD Futurista (Sugerida para GUI Builder)
Estilo terminal verde neon Sci-Fi

WinForms ou Avalonia UI com grid de opções

Painel de logs, visual de chaves geradas, preview da ransom note

Feedback visual: loading HUD, animações de “codificação”, efeito typing

