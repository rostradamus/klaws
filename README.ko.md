# klaws

[English](README.md)

코드베이스를 스캔하여 한국 법률 준수 관련 위험 요소를 탐지하고, 발견 사항을 구체적인 법률 조항에 매핑하는 도구입니다.

현재 [개인정보 보호법(PIPA)](https://www.law.go.kr/법령/개인정보보호법)을 지원하며, 추가 한국 법률 지원이 예정되어 있습니다.

> **면책 조항:** klaws는 검토가 필요할 수 있는 준수 위험 요소를 식별합니다. 법률 자문에 해당하지 않으며, 확정적인 판단은 자격을 갖춘 법률 전문가와 상담하시기 바랍니다.

## 빠른 시작

```bash
# 빌드
go build -o klaws ./cmd/klaws/

# 디렉토리 스캔
klaws scan ./my-project

# 단일 파일 스캔
klaws scan ./MyService.java
```

## 설치

**요구사항:** Go 1.23+

```bash
git clone https://github.com/rostradamus/klaws.git
cd klaws
go build -o klaws ./cmd/klaws/
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
| `PIPA-LOG-001` | 개인정보 로깅 위험 | `log.*()` 호출에 개인정보 필드명(email, phone, SSN, password 등) 포함 여부 | MEDIUM | 제29조 |
| `PIPA-ENC-001` | 미암호화 개인정보 위험 | 민감 식별자 필드(주민번호, SSN 등)에 암호화 어노테이션 또는 호출 누락 여부 | HIGH | 제24조의2, 제29조 |
| `PIPA-CST-001` | 동의 확인 누락 위험 | `@PostMapping`/`@PutMapping` 엔드포인트에서 개인정보 수집 시 동의 확인 누락 여부 | HIGH | 제15조 |

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

MCP 클라이언트 설정에 추가합니다 (예: Claude Code `~/.claude/settings.json`):

```json
{
  "mcpServers": {
    "klaws": {
      "command": "/path/to/klaws",
      "args": ["serve"]
    }
  }
}
```

## 내장 법률 조항

klaws는 10개의 개인정보 보호법 조항을 바이너리에 내장하고 있습니다 (외부 파일 불필요):

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

## 로드맵

- **추가 탐지기:** 데이터 보존 기간(PIPA-RET-001), 국외 이전(PIPA-XBR-001)
- **다국어 지원:** Python, JavaScript/TypeScript 탐지 패턴
- **추가 법률:** 정보통신망법, 신용정보법
- **CI/CD 연동:** GitHub Action, SARIF 출력, 심각도 임계값
- **설정 파일:** 사용자 정의 패턴 규칙 지원

## 라이선스

MIT
