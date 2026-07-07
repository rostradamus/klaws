# Security Policy

*[한국어](#보안-정책) below.*

## Supported versions

Security fixes are released against the latest published version. Please upgrade to the most recent [release](https://github.com/rostradamus/klaws/releases/latest) before reporting an issue.

| Version | Supported |
|---------|-----------|
| Latest release | ✅ |
| Older releases | ❌ |

## Reporting a vulnerability

Please **do not** open a public issue for security vulnerabilities.

Instead, report privately through GitHub's [private vulnerability reporting](https://github.com/rostradamus/klaws/security/advisories/new) (the **"Report a vulnerability"** button under the repository's **Security** tab). This keeps the details confidential until a fix is available.

When reporting, please include:

- A description of the vulnerability and its impact
- Steps to reproduce (a minimal proof of concept if possible)
- The klaws version (`klaws --version`) and how you run it (CLI, stdio MCP, or `--http`)

We aim to acknowledge reports within a few days and to coordinate disclosure once a fix is ready.

## Security posture

klaws is designed to be safe to point at private code:

- **Local-only analysis.** Scanning is static pattern-matching on files you pass in. Source code never leaves your machine — nothing is uploaded or sent to any service.
- **One optional outbound call.** The only network request klaws makes is the `--live` law lookup / `get_law_reference` live fetch, which retrieves public statute text from [law.go.kr](https://www.law.go.kr). It sends only the statute's name (e.g. `개인정보보호법`, resolved from the provision you looked up) as the search query — never your code. Omit `--live` to stay fully offline.
- **Read-only.** klaws only reads the files it scans and never modifies them. Its MCP tools are annotated read-only.

When exposing the MCP server, harden it:

- Pass `--scan-root <dir>` to confine `scan_directory` / `scan_file` to a single directory tree.
- Pass `--auth-token <token>` (or set `KLAWS_AUTH_TOKEN`) when serving over `--http` to require bearer authentication.
- `--auth-token` provides bearer auth but **not TLS**. On untrusted networks, terminate TLS at a reverse proxy in front of klaws.

---

# 보안 정책

## 지원 버전

보안 수정 사항은 최신 게시 버전을 기준으로 릴리스됩니다. 문제를 신고하기 전에 [최신 릴리스](https://github.com/rostradamus/klaws/releases/latest)로 업그레이드해 주세요.

| 버전 | 지원 여부 |
|------|-----------|
| 최신 릴리스 | ✅ |
| 이전 릴리스 | ❌ |

## 취약점 신고

보안 취약점은 **공개 이슈로 등록하지 말아 주세요.**

대신 GitHub의 [비공개 취약점 신고](https://github.com/rostradamus/klaws/security/advisories/new) 기능(리포지토리 **Security** 탭의 **"Report a vulnerability"** 버튼)을 통해 비공개로 신고해 주세요. 수정이 완료될 때까지 세부 내용이 기밀로 유지됩니다.

신고 시 다음 내용을 포함해 주세요:

- 취약점 설명 및 영향
- 재현 절차 (가능하면 최소한의 개념 증명)
- klaws 버전(`klaws --version`)과 실행 방식(CLI, stdio MCP, 또는 `--http`)

며칠 이내에 신고를 확인하고, 수정이 준비되면 공개 시점을 조율하는 것을 목표로 합니다.

## 보안 설계

klaws는 비공개 코드에 안전하게 사용할 수 있도록 설계되었습니다:

- **로컬 전용 분석.** 스캔은 전달한 파일에 대한 정적 패턴 매칭입니다. 소스 코드는 기기를 벗어나지 않으며 업로드되거나 외부로 전송되지 않습니다.
- **선택적 외부 호출 1건.** klaws의 유일한 네트워크 요청은 `--live` 법령 조회 / `get_law_reference` 라이브 조회이며, [law.go.kr](https://www.law.go.kr)에서 공개 법령 원문을 가져옵니다. 조회한 조항에서 해석한 법령명(예: `개인정보보호법`)만 검색어로 전송하며, 코드는 전송하지 않습니다. `--live`를 생략하면 완전히 오프라인으로 동작합니다.
- **읽기 전용.** klaws는 스캔 대상 파일을 읽기만 하며 수정하지 않습니다. MCP 도구는 읽기 전용으로 표시됩니다.

MCP 서버를 노출할 때는 다음과 같이 강화하세요:

- `--scan-root <dir>`로 `scan_directory` / `scan_file`을 단일 디렉토리 트리로 제한하세요.
- `--http`로 제공할 때는 `--auth-token <token>`(또는 `KLAWS_AUTH_TOKEN` 환경 변수)으로 Bearer 인증을 요구하세요.
- `--auth-token`은 Bearer 인증을 제공하지만 **TLS는 제공하지 않습니다.** 신뢰할 수 없는 네트워크에서는 klaws 앞단의 리버스 프록시에서 TLS를 종료하세요.
