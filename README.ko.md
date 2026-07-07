# klaws

[![CI](https://github.com/rostradamus/klaws/actions/workflows/ci.yml/badge.svg)](https://github.com/rostradamus/klaws/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/rostradamus/klaws)](https://github.com/rostradamus/klaws/releases/latest)
[![Container](https://img.shields.io/badge/ghcr.io-rostradamus%2Fklaws-blue?logo=docker)](https://github.com/rostradamus/klaws/pkgs/container/klaws)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

[English](README.md)

코드베이스를 스캔하여 한국 법률 준수 관련 위험 요소를 탐지하고, 발견 사항을 구체적인 법률 조항에 매핑하는 도구입니다. [MCP](https://modelcontextprotocol.io/) 서버(AI 코딩 어시스턴트가 요청 시 스캔 가능)와 독립 실행형 CLI로 동작합니다.

현재 [개인정보 보호법(PIPA)](https://www.law.go.kr/법령/개인정보보호법), [정보통신망법](https://www.law.go.kr/법령/정보통신망이용촉진및정보보호등에관한법률), [신용정보법](https://www.law.go.kr/법령/신용정보의이용및보호에관한법률), [전자상거래법](https://www.law.go.kr/법령/전자상거래등에서의소비자보호에관한법률)을 지원합니다.

> **면책 조항:** klaws는 검토가 필요할 수 있는 준수 위험 요소를 식별합니다. 법률 자문에 해당하지 않으며, 확정적인 판단은 자격을 갖춘 법률 전문가와 상담하시기 바랍니다.

> **개인정보 보호:** klaws는 코드를 **로컬에서만** 분석하며 어떤 데이터도 외부로 전송하지 않습니다. 유일한 외부 네트워크 요청은 선택 사항인 `--live` 법령 조회([law.go.kr](https://www.law.go.kr))뿐이며, 이 플래그를 사용하지 않으면 완전히 오프라인으로 동작합니다. [개인정보 보호 및 보안](#개인정보-보호-및-보안)을 참고하세요.

## 빠른 시작

```bash
# 설치 없이 Docker로 현재 디렉토리 스캔
docker run --rm -v "$PWD":/src:ro ghcr.io/rostradamus/klaws scan /src

# ...또는 바이너리를 설치한 경우:
klaws scan ./my-project        # 디렉토리 스캔
klaws scan ./MyService.java    # 단일 파일 스캔
```

## 설치

### Docker (권장)

별도의 개발 도구가 필요 없습니다. 이미지는 GitHub Container Registry에 게시되어 있으며 macOS, Linux, Windows에서 동일하게 동작합니다:

```bash
# 현재 디렉토리를 읽기 전용(/src)으로 마운트하여 스캔
docker run --rm -v "$PWD":/src:ro ghcr.io/rostradamus/klaws scan /src

# floating latest 태그 대신 특정 버전 고정
docker run --rm -v "$PWD":/src:ro ghcr.io/rostradamus/klaws:0.1.5 scan /src
```

### 사전 빌드된 바이너리

[최신 릴리스](https://github.com/rostradamus/klaws/releases/latest)에서 플랫폼에 맞는 아카이브를 내려받아 압축을 풀고 `klaws`를 `PATH`에 추가합니다.

### go install

```bash
go install github.com/rostradamus/klaws/cmd/klaws@latest
```

### 소스에서 빌드

**요구사항:** Go 1.23+

```bash
git clone https://github.com/rostradamus/klaws.git
cd klaws
go build -o klaws ./cmd/klaws/
```

설치 확인:

```bash
klaws --version
```

## 사용법

### 스캔

```bash
# 디렉토리 스캔 (기본: *.java 파일)
klaws scan ./src

# 특정 파일 유형 스캔
klaws scan ./src --pattern "*.kt"

# 텍스트 출력 (기본값은 JSON)
klaws scan ./src --format text

# SARIF 출력 (GitHub 코드 스캐닝 등 외부 도구용)
klaws scan ./src --format sarif > klaws.sarif

# 지정한 심각도 이상의 발견 사항이 있으면 종료 코드 1로 실패 처리
klaws scan ./src --fail-on HIGH

# 사용자 정의 법률 파일 사용
klaws scan ./src --laws ./my-laws.yaml
```

### 출력 예시

```
klaws scan report
Target:  ./testdata
Files:   4
Findings: 7

--- Finding 1 ---
  Detector:  PIPA-CST-001
  Risk:      HIGH
  Location:  testdata/MemberController.java:10
  Snippet:   @PostMapping("/register")
  Message:   Endpoint accepts possible personal data without apparent consent
             mechanism — may require review under PIPA Article 15
  Laws:      PIPA-15

--- Finding 2 ---
  Detector:  PIPA-ENC-001
  Risk:      HIGH
  Location:  testdata/MemberEntity.java:11
  Snippet:   private String residentNumber;
  Message:   Possible unencrypted personal identifier (residentNumber) — may
             require review under PIPA Article 24-2
  Laws:      PIPA-24-2, PIPA-29

--- Finding 3 ---
  Detector:  PIPA-LOG-001
  Risk:      MEDIUM
  Location:  testdata/UserService.java:11
  Snippet:   log.info("User registered: " + email);
  Message:   Possible personal data (email) in log output — may require review
             under PIPA Article 29
  Laws:      PIPA-29
```

### 법률 조항 조회

```bash
# 내장 데이터베이스에서 조회
klaws law PIPA-15

# law.go.kr에서 최신 원문 가져오기
klaws law PIPA-15 --live
```

### 탐지기 목록

```bash
klaws detectors
```

```json
[
  {
    "id": "PIPA-LOG-001",
    "name": "Personal Data Logging Risk",
    "description": "Detects log statements that may contain personal data fields",
    "related_laws": ["PIPA-29"]
  },
  {
    "id": "PIPA-ENC-001",
    "name": "Unencrypted Personal Data Risk",
    "description": "Detects personal identifier fields stored without apparent encryption",
    "related_laws": ["PIPA-24-2", "PIPA-29"]
  },
  {
    "id": "PIPA-CST-001",
    "name": "Missing Consent Check Risk",
    "description": "Detects endpoints accepting personal data without apparent consent verification",
    "related_laws": ["PIPA-15"]
  }
]
```

## 탐지기

| ID | 이름 | 탐지 대상 | 위험도 | 관련 법률 |
|----|------|-----------|--------|-----------|
| `PIPA-LOG-001` | 개인정보 로깅 위험 | `log.*()` 호출에 개인정보 필드명(email, phone, SSN, password 등) 포함 여부 | MEDIUM | 개인정보보호법 제29조 |
| `PIPA-ENC-001` | 미암호화 개인정보 위험 | 민감 식별자 필드(주민번호, SSN 등)에 암호화 어노테이션 또는 호출 누락 여부 | HIGH | 개인정보보호법 제24조의2, 제29조 |
| `PIPA-CST-001` | 동의 확인 누락 위험 | `@PostMapping`/`@PutMapping` 엔드포인트에서 개인정보 수집 시 동의 확인 누락 여부 | HIGH | 개인정보보호법 제15조 |
| `NIA-MKT-001` | 광고성 정보 수신동의 위험 | 광고/마케팅 메시지 발송(`send`/`push`) 시 수신동의(opt-in) 확인 누락 여부 | MEDIUM | 정보통신망법 제50조 |
| `CIA-ENC-001` | 신용정보 미보호 위험 | 신용/금융 식별자 필드(카드번호, 계좌번호, 신용등급 등)에 암호화 또는 마스킹 누락 여부 | HIGH | 신용정보법 제19조 |
| `ECA-RET-001` | 거래기록 보존 위험 | 거래기록 필드(주문/결제 ID 등)에 보존 또는 보관 처리 누락 여부 | MEDIUM | 전자상거래법 제6조 |
| `PIPA-RET-001` | 개인정보 파기 위험 | 개인정보 필드(이메일, 전화번호, 주민번호 등)에 파기 또는 보관기간 처리 누락 여부 | MEDIUM | 개인정보보호법 제21조 |
| `PIPA-XBR-001` | 제3자 제공 위험 | 개인정보를 외부 URL·제휴사 등 제3자에게 전송(외부 호출) 시 동의 확인 누락 여부 | HIGH | 개인정보보호법 제17조 |

탐지기는 정규식 기반 패턴 매칭을 사용합니다. 영문과 한글 필드명을 모두 지원합니다 (예: `email`/`이메일`, `residentNumber`/`주민번호`, `consent`/`동의`).

## MCP 서버

klaws는 [MCP](https://modelcontextprotocol.io/) 서버로 실행하여 AI 코딩 어시스턴트에서 스캔 기능을 사용할 수 있습니다.

```bash
klaws serve
```

### 제공 도구

| 도구 | 설명 |
|------|------|
| `scan_directory` | 디렉토리의 준수 위험 요소 스캔 |
| `scan_file` | 단일 파일 스캔 |
| `list_detectors` | 사용 가능한 탐지기 목록 조회 |
| `get_law_reference` | ID로 한국 법률 조항 조회 |

### 설정

모든 클라이언트는 동일한 실행 명령(`klaws serve`, stdio 전송)을 사용합니다. 바이너리의 절대 경로(`which klaws`로 확인)를 쓰거나, `PATH`에 있다면 `klaws`만 지정하면 됩니다. 아무것도 설치하고 싶지 않다면 아래의 [Docker 방식](#mcp-서버를-docker로-실행)을 사용하세요. stdio MCP 서버를 지원하는 모든 클라이언트에서 동작합니다.

**Claude Code** — `~/.claude/settings.json`:

```json
{
  "mcpServers": {
    "klaws": {
      "command": "klaws",
      "args": ["serve"]
    }
  }
}
```

또는 한 줄 명령으로 추가:

```bash
claude mcp add klaws -- klaws serve
```

**Claude Desktop** — `claude_desktop_config.json` (Settings → Developer → Edit Config):

```json
{
  "mcpServers": {
    "klaws": {
      "command": "klaws",
      "args": ["serve"]
    }
  }
}
```

**Cursor** — `~/.cursor/mcp.json` (또는 프로젝트 내 `.cursor/mcp.json`):

```json
{
  "mcpServers": {
    "klaws": {
      "command": "klaws",
      "args": ["serve"]
    }
  }
}
```

**VS Code** — `.vscode/mcp.json`:

```json
{
  "servers": {
    "klaws": {
      "command": "klaws",
      "args": ["serve"]
    }
  }
}
```

연결 후에는 어시스턴트에게 *"klaws로 이 디렉토리의 한국 법률 준수 위험을 스캔해줘"* 와 같이 요청하면 됩니다.

#### MCP 서버를 Docker로 실행

바이너리 설치가 필요 없습니다. `command`/`args`를, 스캔 대상 코드를 마운트하는 `docker run` 명령으로 교체하세요. `-i` 플래그는 stdio 전송을 위해 stdin을 열어 두며, `--scan-root /src`는 스캔 범위를 마운트한 디렉토리로 제한합니다:

```json
{
  "mcpServers": {
    "klaws": {
      "command": "docker",
      "args": [
        "run", "--rm", "-i",
        "-v", "/absolute/path/to/your/project:/src:ro",
        "ghcr.io/rostradamus/klaws:0.1.5",
        "serve", "--scan-root", "/src"
      ]
    }
  }
}
```

어시스턴트에게는 컨테이너 내부 마운트 경로인 `/src` 하위 경로를 지정하세요. 예: *"/src의 한국 법률 준수 위험을 스캔해줘."*

### 원격 실행 (Streamable HTTP)

기본적으로 `klaws serve`는 stdio(로컬)를 사용합니다. HTTP 기반 원격 MCP 서버로 실행하려면 `--http`를 지정합니다:

```bash
klaws serve --http :8080
# 또는 게시된 컨테이너 이미지로 실행:
docker run --rm -p 8080:8080 ghcr.io/rostradamus/klaws serve --http :8080
```

MCP 엔드포인트는 `http://<host>:8080/mcp` (Streamable HTTP 전송)에서 사용할 수 있습니다. HTTP를 지원하는 MCP 클라이언트를 이 URL로 연결하세요.

#### 원격 서버 보안

```bash
klaws serve --http :8080 \
  --auth-token "$(openssl rand -hex 32)" \
  --scan-root /workspace
```

- `--auth-token <token>` — 모든 HTTP 요청에 `Authorization: Bearer <token>` 헤더를 요구합니다. 인증되지 않은 요청은 `401`을 받습니다. `KLAWS_AUTH_TOKEN` 환경 변수로도 지정할 수 있으며, `--http`에만 적용됩니다.
- `--scan-root <dir>` — `scan_directory`/`scan_file`을 `<dir>` 내부 경로로 제한합니다. 범위를 벗어난 경로 요청은 거부됩니다. (stdio 모드에서도 적용됩니다.)

> **참고:**
> - `--auth-token`은 Bearer 인증을 제공하지만 **TLS는 제공하지 않습니다.** 신뢰할 수 없는 네트워크에서는 klaws 앞단의 리버스 프록시/게이트웨이에서 TLS를 종료하세요.
> - `scan_directory`와 `scan_file` 도구는 **서버의** 파일 시스템을 읽습니다(전달한 경로는 klaws가 실행되는 호스트에서 해석됩니다). 원격 스캔의 경우 코드가 있는 위치(예: 리포지토리가 체크아웃된 CI 러너)에서 klaws를 실행하고 `--scan-root`를 해당 체크아웃 경로로 설정하세요. `get_law_reference`와 `list_detectors` 도구는 파일 시스템 의존성이 없습니다.

## 개인정보 보호 및 보안

klaws는 비공개 코드에 안전하게 사용할 수 있도록 설계되었습니다:

- **로컬 전용 분석.** 스캔은 전달한 파일에 대한 순수한 정적 패턴 매칭입니다. 소스 코드는 기기를 벗어나지 않으며, 업로드·원격 로깅·외부 전송이 전혀 없습니다.
- **선택적 외부 호출 1건.** klaws가 수행하는 유일한 네트워크 요청은 `--live` 법령 조회(CLI) / 라이브 조회를 사용한 `get_law_reference`(MCP)이며, 이는 [law.go.kr](https://www.law.go.kr)에서 공개 법령 원문을 가져옵니다. 법령 ID만 전송하며 코드는 전송하지 않습니다. `--live`를 생략하면 완전히 오프라인으로 동작합니다.
- **읽기 전용 설계.** klaws는 스캔 대상 파일을 읽기만 하며 코드를 수정하지 않습니다. MCP 도구는 읽기 전용(read-only)으로 표시됩니다.
- **접근 가능한 파일 시스템 제한.** MCP 서버를 노출할 때는 `--scan-root <dir>`로 `scan_directory`/`scan_file`을 단일 트리로 제한하고, `--http`로 제공할 때는 `--auth-token`을 사용하세요. [원격 서버 보안](#원격-서버-보안)을 참고하세요.

취약점 신고는 [SECURITY.md](SECURITY.md)를 참고하세요.

## 내장 법률 조항

klaws는 4개 법률의 40개 조항을 바이너리에 내장하고 있습니다 (외부 파일 불필요):

### 개인정보 보호법 (PIPA) — 10개 조항

| ID | 조항 | 내용 |
|----|------|------|
| `PIPA-15` | 제15조 | 개인정보의 수집 및 이용 |
| `PIPA-17` | 제17조 | 개인정보의 제3자 제공 |
| `PIPA-18` | 제18조 | 개인정보의 목적 외 이용ㆍ제공 제한 |
| `PIPA-21` | 제21조 | 개인정보의 파기 |
| `PIPA-23` | 제23조 | 민감정보의 처리 제한 |
| `PIPA-24` | 제24조 | 고유식별정보의 처리 제한 |
| `PIPA-24-2` | 제24조의2 | 주민등록번호 처리의 제한 |
| `PIPA-29` | 제29조 | 안전조치의무 |
| `PIPA-30` | 제30조 | 개인정보 처리방침 |
| `PIPA-34` | 제34조 | 개인정보 유출 등의 통지ㆍ신고 |

### 정보통신망법 (Network Act) — 11개 조항

| ID | 조항 | 내용 |
|----|------|------|
| `NIA-22` | 제22조 | 개인정보의 수집ㆍ이용 동의 |
| `NIA-23` | 제23조 | 개인정보의 수집 제한 |
| `NIA-23-2` | 제23조의2 | 주민등록번호의 사용 제한 |
| `NIA-24` | 제24조 | 개인정보의 이용 제한 |
| `NIA-24-2` | 제24조의2 | 개인정보의 제3자 제공 |
| `NIA-27` | 제27조 | 개인정보의 보호조치 |
| `NIA-28` | 제28조 | 개인정보의 위탁 |
| `NIA-28-2` | 제28조의2 | 개인정보 유출 등의 통지 |
| `NIA-44` | 제44조 | 이용자의 권익 보호 |
| `NIA-44-7` | 제44조의7 | 불법정보의 유통 금지 |
| `NIA-50` | 제50조 | 영리목적 광고성 정보 전송 제한 |

### 신용정보법 (Credit Information Act) — 10개 조항

| ID | 조항 | 내용 |
|----|------|------|
| `CIA-15` | 제15조 | 수집의 원칙 |
| `CIA-17` | 제17조 | 목적 외 누설 금지 |
| `CIA-19` | 제19조 | 신용정보전산시스템의 안전보호 |
| `CIA-20` | 제20조 | 신용정보의 정확성 및 최신성 |
| `CIA-32` | 제32조 | 개인신용정보의 제공ㆍ이용 동의 |
| `CIA-33` | 제33조 | 개인신용정보의 이용 |
| `CIA-34` | 제34조 | 개인신용정보의 제공ㆍ이용 |
| `CIA-38` | 제38조 | 신용정보의 보호 |
| `CIA-39` | 제39조 | 신용정보 유출 등의 통지 |
| `CIA-40` | 제40조 | 신용정보주체의 권리 |

### 전자상거래법 (E-Commerce Act) — 9개 조항

| ID | 조항 | 내용 |
|----|------|------|
| `ECA-6` | 제6조 | 거래기록의 보존 |
| `ECA-7` | 제7조 | 조작실수의 방지 |
| `ECA-11` | 제11조 | 전자적 대금지급의 신뢰 확보 |
| `ECA-13` | 제13조 | 신원 및 거래조건에 대한 정보의 제공 |
| `ECA-14` | 제14조 | 청약의 확인 |
| `ECA-17` | 제17조 | 청약철회 등 |
| `ECA-21` | 제21조 | 소비자정보의 이용 |
| `ECA-24` | 제24조 | 사이버몰의 안전성 |
| `ECA-26` | 제26조 | 소비자정보의 보호 |

한글 조문 전문이 포함되어 있습니다. `--live` 플래그를 사용하면 [law.go.kr](https://www.law.go.kr)에서 최신 버전을 가져옵니다.

## 아키텍처

```
klaws scan ./src
       │
       ▼
   FileWalker ──► 디렉토리 탐색, glob 패턴 매칭
       │
       ▼
  ScannerService ──► 각 파일 읽기
       │
       ▼
  DetectorRegistry ──► 소스 코드에 모든 탐지기 실행
       │
       ▼
    Findings ──► 법률 조항에 매핑
       │
       ▼
   Report ──► JSON 또는 텍스트 출력
```

## GitHub Action (CI)

klaws는 코드를 스캔하여 SARIF 리포트를 생성하는 composite action을 제공합니다. 이를 GitHub 코드 스캐닝에 업로드하면 발견 사항이 풀 리퀘스트와 **Security** 탭에 인라인으로 표시됩니다.

```yaml
# .github/workflows/klaws.yml
name: klaws compliance scan
on: [pull_request]

permissions:
  contents: read
  security-events: write   # SARIF 업로드에 필요

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - id: klaws
        uses: rostradamus/klaws@v0.1.5
        with:
          path: ./src
          pattern: "*.java"
          fail-on: none      # PR을 게이트하려면 MEDIUM / HIGH
          version: v0.1.5

      - name: Upload SARIF
        if: always()          # fail-on으로 실패해도 업로드
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: ${{ steps.klaws.outputs.sarif }}
```

`fail-on: HIGH`(또는 `MEDIUM`)로 설정하면 해당 심각도 이상의 발견 사항이 있을 때 검사가 PR을 실패 처리합니다. 업로드 단계의 `if: always()`는 게이트가 실패해도 SARIF가 게시되도록 보장합니다.

## 로드맵

- **추가 탐지기:** 광고성 정보 수신동의(NIA-MKT-001) *(완료)*, 신용정보 미보호(CIA-ENC-001) *(완료)*, 거래기록 보존(ECA-RET-001) *(완료)*, 개인정보 파기(PIPA-RET-001) *(완료)*, 제3자/국외 이전(PIPA-XBR-001) *(완료)*
- **다국어 지원:** Python, JavaScript/TypeScript 탐지 패턴
- **추가 법률:** 전자상거래법 *(완료)*, 정보통신망법 *(완료)*, 신용정보법 *(완료)*
- **CI/CD 연동:** GitHub Action, SARIF 출력, 심각도 임계값 *(완료)*
- **설정 파일:** 사용자 정의 패턴 규칙 지원

## 릴리스

메인테이너: 릴리스 절차와 MCP 레지스트리 게시 방법은 [RELEASE.md](RELEASE.md)를 참고하세요.

## 라이선스

MIT
