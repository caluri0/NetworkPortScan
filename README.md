# Network Port Scanner - Cybersecurity Portfolio

> A multi-threaded network port scanner written in pure Python,
> built as a portfolio project to demonstrate cybersecurity skills for the Japanese market.

---

## English

### Description

A network port scanner built entirely on Python's standard library (no external dependencies).
It reproduces the core functionality of **Nmap** to illustrate how security professionals map exposed services on a target system.

### Cybersecurity Concepts Covered

| Concept | File | Description |
|---|---|---|
| **TCP/UDP Sockets** | `scanner.py` | Low-level connections, 3-way handshake |
| **Threading / Queue** | `scanner.py` | High-performance parallel scanning |
| **Banner Grabbing** | `utils.py` | Service fingerprinting |
| **DNS Resolution** | `utils.py` | Forward and reverse lookup |
| **CVE Analysis** | `utils.py` | Vulnerable version detection |
| **Audit Report** | `report.py` | JSON / plain-text documentation |

### Project Structure

```
ScannerPortReseau/
├── scanner.py       # Main program — TCP/UDP scan logic
├── utils.py         # Network utility functions
├── report.py        # Report generation (TXT / JSON)
├── docs/            # Learning guide PDF + generator script
├── requirements.txt # Dependencies (standard library only)
└── reports/         # Auto-generated scan reports
```

### Learning Guide (PDF)

A detailed French learning document explains the full codebase, library choices, and network concepts:

- **File:** `docs/Network_Port_Scanner_Learning_Guide.pdf`
- **Regenerate:** `pip install fpdf2` then `python docs/generate_learning_pdf.py`

### Requirements

- Python 3.10+
- No external packages required

### Usage

The scanner supports two modes:

| Mode | Command | Best for |
|---|---|---|
| **Interactive** | `python scanner.py` | Learning, step-by-step guidance |
| **CLI** | `python scanner.py --target HOST [options]` | Scripting, automation, pipelines |

#### CLI Reference

```
python scanner.py [-h] [-t HOST] [-p PORTS] [--protocol {TCP,UDP}]
                  [--threads N] [--timeout SEC] [-o FORMAT]
                  [--output-file PATH] [--no-banner]
```

| Argument | Short | Default | Description |
|---|---|---|---|
| `--target` | `-t` | — | Target IP or hostname (**required in CLI mode**) |
| `--ports` | `-p` | `common` | Port spec: `common`, `all`, `1-1024`, `80,443,8080` |
| `--protocol` | | `TCP` | Transport protocol: `TCP` or `UDP` |
| `--threads` | | `200` | Number of parallel workers (1–1000) |
| `--timeout` | | `0.8` | Socket timeout per port in seconds |
| `--output` | `-o` | — | Auto-save report: `txt` or `json` |
| `--output-file` | | — | Custom file path for the report |
| `--no-banner` | | `false` | Skip banner grabbing |

#### CLI Examples

```bash
# Scan common ports (fast reconnaissance)
python scanner.py -t scanme.nmap.org

# Standard audit: ports 1-1024, save as JSON
python scanner.py -t 192.168.1.1 --ports 1-1024 --output json

# Custom port list with 100 threads
python scanner.py -t 10.0.0.5 --ports 80,443,8080,3306 --threads 100

# Full scan with increased timeout, save as text report
python scanner.py -t 10.0.0.1 --ports all --timeout 1.5 --output txt

# UDP scan on DNS and SNMP ports
python scanner.py -t 192.168.1.1 --ports 53,161,123 --protocol UDP

# Get help
python scanner.py --help
```

#### Interactive Mode Session

```
  Enter target IP address or hostname: scanme.nmap.org

  Scan type:
   [1] Common ports only  (fast, ~20 ports)   → --ports common
   [2] Ports 1-1024       (standard)          → --ports 1-1024
   [3] Ports 1-65535      (full scan, slow)   → --ports all
   [4] Custom ports                           → --ports 80,443,8080

  Your choice [1-4]: 1
```

### Example Output

```
PORT     PROTO  STATE        SERVICE         RISK     BANNER
---------------------------------------------------------------------
22       TCP    open         SSH             [MED] MEDIUM SSH-2.0-OpenSSH_6.6.1
80       TCP    open         HTTP            [MED] MEDIUM Apache/2.4.7
```

### Port Specification Formats

| Format | Example | Description |
|---|---|---|
| `common` | `--ports common` | ~20 well-known ports (default) |
| Range | `--ports 1-1024` | All ports from 1 to 1024 |
| List | `--ports 80,443,8080` | Specific comma-separated ports |
| Full | `--ports all` | All 65535 ports (slow) |

### Reports

Reports are saved in `reports/`:

**TXT format** - human-readable, ideal for communication:
```
[ RISK SUMMARY ]
  Total open ports : 3
  HIGH risk        : 0 port(s)
  MEDIUM risk      : 2 port(s)
  LOW risk         : 1 port(s)
  Overall level    : MEDIUM
```

**JSON format** - structured, suitable for integration with other tools:
```json
{
  "target": { "ip": "45.33.32.156", "hostname": "scanme.nmap.org" },
  "risk_summary": { "HIGH": 0, "MEDIUM": 2, "LOW": 1, "global_risk": "MEDIUM" },
  "open_ports": [ ... ],
  "recommendations": [ ... ]
}
```

### Legal Disclaimer

> **Only scan systems for which you have explicit written authorization.**
>
> - Japan: [不正アクセス禁止法](https://laws.e-gov.go.jp/law/411AC0000000128) (Act No. 128 of 1999)
> - France: Article 323-1 of the Penal Code
> - International: Computer Fraud and Abuse Act (USA), NIS2 (EU)
>
> **Legal practice targets:**
> - `scanme.nmap.org` — official Nmap test server
> - `127.0.0.1` — your own machine
> - Your local network (with the owner's permission)

### Future Improvements

- [x] CLI interface with `argparse` (command-line arguments)
- [ ] Stealth SYN scan (raw sockets, requires root/admin)
- [ ] Live CVE lookup via the NVD API
- [ ] OS detection via TTL fingerprinting
- [ ] HTML report export with risk charts
- [ ] IPv6 support

### Resources to Go Further

- [Nmap Book](https://nmap.org/book/) - The reference for network scanning
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/) - Audit methodology
- [CVE Database (NVD)](https://nvd.nist.gov/) - Vulnerability database
- [TryHackMe](https://tryhackme.com/) / [HackTheBox](https://hackthebox.com/) - Legal hands-on practice
- 情報処理安全確保支援士 (RISS) - Recommended Japanese cybersecurity certification

---

## Japanese

### 概要

このプロジェクトは、Pythonの標準ライブラリのみを使用して構築したネットワークポートスキャナーです（外部ライブラリ不要）。**Nmap**の中核機能を再現し、セキュリティ専門家がターゲットシステムの公開サービスをどのようにマッピングするかを示します。

### 扱うサイバーセキュリティの概念

| 概念 | ファイル | 説明 |
|---|---|---|
| **TCP/UDPソケット** | `scanner.py` | 低レベル接続、3ウェイハンドシェイク |
| **スレッド / キュー** | `scanner.py` | 並列スキャンによる高パフォーマンス |
| **バナーグラビング** | `utils.py` | サービスのフィンガープリント |
| **DNS解決** | `utils.py` | 正引き・逆引き |
| **CVE分析** | `utils.py` | 脆弱バージョンの検出 |
| **監査レポート** | `report.py` | JSON / テキスト形式でのドキュメント化 |

### プロジェクト構成

```
ScannerPortReseau/
├── scanner.py       # メインプログラム — TCP/UDPスキャンロジック
├── utils.py         # ネットワークユーティリティ関数
├── report.py        # レポート生成（TXT / JSON）
├── docs/            # 学習ガイドPDF + 生成スクリプト
├── requirements.txt # 依存関係（標準ライブラリのみ）
└── reports/         # 自動生成されるスキャンレポート
```

### 学習ガイド（PDF）

コード全体、ライブラリの選択、ネットワーク概念を説明するフランス語の学習ドキュメント：

- **ファイル:** `docs/Network_Port_Scanner_Learning_Guide.pdf`
- **再生成:** `pip install fpdf2` の後 `python docs/generate_learning_pdf.py`

### 動作要件

- Python 3.10以上
- 外部パッケージ不要

### 使い方

スキャナーは2つのモードに対応しています：

| モード | コマンド | 用途 |
|---|---|---|
| **インタラクティブ** | `python scanner.py` | 学習・ステップバイステップ |
| **CLI** | `python scanner.py --target HOST [オプション]` | スクリプト・自動化・パイプライン |

#### CLIリファレンス

```
python scanner.py [-h] [-t HOST] [-p PORTS] [--protocol {TCP,UDP}]
                  [--threads N] [--timeout SEC] [-o FORMAT]
                  [--output-file PATH] [--no-banner]
```

| 引数 | 短縮形 | デフォルト | 説明 |
|---|---|---|---|
| `--target` | `-t` | — | ターゲットIPまたはホスト名（**CLIモードでは必須**） |
| `--ports` | `-p` | `common` | ポート指定：`common`、`all`、`1-1024`、`80,443,8080` |
| `--protocol` | | `TCP` | プロトコル：`TCP` または `UDP` |
| `--threads` | | `200` | 並列ワーカースレッド数（1〜1000） |
| `--timeout` | | `0.8` | ポートごとのソケットタイムアウト（秒） |
| `--output` | `-o` | — | レポートの自動保存：`txt` または `json` |
| `--output-file` | | — | レポートのカスタムファイルパス |
| `--no-banner` | | `false` | バナーグラビングをスキップ |

#### CLIの使用例

```bash
# 主要ポートのスキャン（素早い偵察）
python scanner.py -t scanme.nmap.org

# 標準監査：ポート 1-1024、JSON形式で保存
python scanner.py -t 192.168.1.1 --ports 1-1024 --output json

# カスタムポートリスト、100スレッド
python scanner.py -t 10.0.0.5 --ports 80,443,8080,3306 --threads 100

# 全ポートスキャン、タイムアウト延長、テキストレポート保存
python scanner.py -t 10.0.0.1 --ports all --timeout 1.5 --output txt

# UDPスキャン（DNS・SNMPポート）
python scanner.py -t 192.168.1.1 --ports 53,161,123 --protocol UDP

# ヘルプの表示
python scanner.py --help
```

#### インタラクティブモードの例

```
  ターゲットのIPアドレスまたはホスト名を入力: scanme.nmap.org

  スキャン種別:
   [1] 主要ポートのみ（高速、約20ポート）  → --ports common
   [2] ポート 1-1024（標準）               → --ports 1-1024
   [3] ポート 1-65535（全スキャン、低速）  → --ports all
   [4] カスタムポート                      → --ports 80,443,8080

  選択 [1-4]: 1
```

### スキャン結果の例

```
PORT     PROTO  STATE        SERVICE         RISK     BANNER
---------------------------------------------------------------------
22       TCP    open         SSH             [MED] MEDIUM SSH-2.0-OpenSSH_6.6.1
80       TCP    open         HTTP            [MED] MEDIUM Apache/2.4.7
```

### ポート指定フォーマット

| フォーマット | 例 | 説明 |
|---|---|---|
| `common` | `--ports common` | 主要な約20ポート（デフォルト） |
| 範囲指定 | `--ports 1-1024` | 1〜1024の全ポート |
| リスト指定 | `--ports 80,443,8080` | カンマ区切りの特定ポート |
| 全ポート | `--ports all` | 全65535ポート（低速） |

### レポート形式

レポートは `reports/` ディレクトリに保存されます：

**TXTフォーマット** - 人が読みやすい形式：
```
[ リスクサマリー ]
  オープンポート合計 : 3
  高リスク           : 0 ポート
  中リスク           : 2 ポート
  低リスク           : 1 ポート
  総合リスクレベル   : MEDIUM
```

**JSONフォーマット** - 他ツールとの連携に適した構造化形式：
```json
{
  "target": { "ip": "45.33.32.156", "hostname": "scanme.nmap.org" },
  "risk_summary": { "HIGH": 0, "MEDIUM": 2, "LOW": 1, "global_risk": "MEDIUM" },
  "open_ports": [ ... ],
  "recommendations": [ ... ]
}
```

### 法的免責事項

> **明示的な書面による許可を得たシステムのみをスキャンしてください。**
>
> - 日本：[不正アクセス禁止法](https://laws.e-gov.go.jp/law/411AC0000000128)（1999年法律第128号）
> - フランス：刑法第323-1条
> - 国際：コンピュータ詐欺・悪用禁止法（米国）、NIS2指令（EU）
>
> **合法的な練習ターゲット：**
> - `scanme.nmap.org` — Nmap公式テストサーバー
> - `127.0.0.1` — 自分自身のマシン（ローカルホスト）
> - 自分のローカルネットワーク（所有者の許可を得た上で）

### 今後の改善予定

- [x] `argparse` を使ったCLIインターフェース（コマンドライン引数）
- [ ] ステルスSYNスキャン（rawソケット、root/管理者権限が必要）
- [ ] NVD APIを使ったリアルタイムCVE照合
- [ ] TTLフィンガープリントによるOS検出
- [ ] リスクチャート付きHTMLレポートの出力
- [ ] IPv6対応

### 学習リソース

- [Nmap Book](https://nmap.org/book/) - ネットワークスキャンのリファレンス
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/) - 監査方法論
- [CVEデータベース (NVD)](https://nvd.nist.gov/) - 脆弱性データベース
- [TryHackMe](https://tryhackme.com/) / [HackTheBox](https://hackthebox.com/) - 合法的なハンズオン演習
- [情報処理安全確保支援士（RISS）](https://www.ipa.go.jp/shiken/kubun/sc.html) - 推奨する日本のサイバーセキュリティ資格

---

*Built as a cybersecurity portfolio project targeting a career in Japan.*
*日本でのサイバーセキュリティキャリアを目指したポートフォリオプロジェクトとして開発。*
