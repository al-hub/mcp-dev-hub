# #35 — 소유자 최초 설치 승인 절차 (WSL Option C)

상태: **사전점검 구현 후보 / 실제 root 설치 미승인**. 이 문서는 sudo, 관리자 인증, 보호 신뢰키 교체를 승인하지 않습니다. 비밀키·토큰·암호를 ChatGPT, GitHub Issue, Microduck, 원격 셸에 입력하지 마세요.

## 1. 지금 AI가 준비하는 범위 (사용자 작업 없음)

- 기존 GitHub PR #39의 **정확한 HEAD/BASE**, 독립 Codex 최종 감사 JSON과 실제 CI를 확인
- 변경된 정확한 HEAD로 생성한 비권한 불변 소스 패키지의 MANIFEST SHA-256과 61개 소스 파일 원본·해시·권한 검증
- 비권한 WSL에서 기존 보호 컨트롤러·정책 원본 2개의 Git 기준선, 소유권, 격리 시작 확인
- `scripts/protected-update-owner-bootstrap-preflight.mjs`는 위 두 검증을 실제 실행하고 root 영역/서명 역할은 **메타데이터만** 관찰. 암호·토큰·키를 읽지 않음. 결과의 `rootInstallAuthorized`는 항상 `false`.
- 독립 서명 코드를 원본 패키지에 보존하고 OS Codex→검토자→승인자 순서를 유지. 실패·UNKNOWN을 재실행하지 않음.

## 2. 소유자가 직접 해야 하는 일 — 아직 sudo 실행 금지

1. **본인 PC의 WSL 터미널에 직접 로그인**할 수 있는지 확인합니다. ChatGPT/ClosePaw SSH 셸을 소유자 인증으로 사용하지 않습니다.
2. GitHub PR #39에서 최종 HEAD와 요구 CI/리뷰 상태를 **직접 확인**합니다. 채팅에 기재된 체크섬 자체는 독립 서명이나 소유자 승인이 아닙니다.
3. Codex 실행 주체의 전용 인증 정보, GitHub 읽기 전용 자격증명(검토자/승인자별) 및 기존 root 원본 복구 방법을 **로컬의 소유자 전용 저장소로** 준비합니다. 어떤 자격증명·암호도 채팅으로 보내지 않습니다. 개인 Codex 로그인 정보를 Worker 계정에 노출하거나 무단 복제하지 않습니다.
4. 별도 OS 계정 `mcp35_codex` → `mcp35_reviewer` → `mcp35_approver`를 고정된 코드로 설치하는 **신뢰된 최초 설치 프로그램, 외부 고정 패키지 해시, OS 접근 범위, 복구 계획**을 본인이 검토합니다. 특히 독립 GitHub 정식 승인 요건을 충족해야 합니다.
5. 여기까지 모두 증명된 후에만 **본인 WSL 로컬 콘솔에서 제한된 관리자 인증 1회**를 수행합니다. 사용자가 인증하는 `sudo`는 이때 요청하며, 제가 원격 세션에서 암호를 입력·대신 승인하지 않습니다.

## 3. 실제 설치의 고정 순서 — 전부 사전조건 통과 후에만

1. 소유자 인증된 로컬 설치 도구가 검토된 정확한 코드 바이트와 digest를 root-owned immutable 경로로 복사·검증하고 기존 원본을 보호합니다. **mutable checkout을 root로 실행하지 않습니다.**
2. root 검증자가 실제 OS role·파일 소유권·디렉터리 모드·Codex/companion/Bubblewrap 바이너리 SHA-256을 확인합니다. 별도 `mcp35_codex` 서명자가 자기 계정에서 Ed25519 키를 생성하며, root는 공개키만 고정합니다. Codex의 실제 완료된 최종 HEAD/BASE 감사만 서명합니다.
3. 분리된 `mcp35_reviewer`, `mcp35_approver`가 각자 비밀키를 생성하고 동일한 감사·PR·CI·패키지·원본 증거를 검증하고 각각 서명합니다. CLI 종료 0, AGY 산출물, 합성 JSON으로 대체 불가.
4. 기존 root 고정 실행기는 짧은 만료시간·재사용 금지·독립 GitHub 보호 검사·서명 3개·허용된 원본 두 파일과 CAS/원자성/복구 계획이 모두 일치할 때만 제한된 **두 가지 명령**을 설치합니다. `NOPASSWD:ALL` 금지.
5. 업데이트 vA→vB, vB→vC 2회(각 사용자 sudo 0회), 실패 차단·롤백·원본 복구와 Worker/Dashboard/데이터 및 PC/Galaxy/private-SSE 수용 후 보호 PR 병합, main CI, Issue #35 종료.

## 4. 즉시 중단 조건

- 현 소스 후보는 **로컬 소유자 승인 root installer 자체가 설치돼 있지 않음**. 신뢰할 수 없는 원격 AI 셸에서 키를 발행하거나 root 권한을 가져와서는 안 됩니다.
- Codex 서명 계정·검토자·승인자 역할 중 하나라도 누락/중복/공유 UID, 빈 승인 또는 정확한 최신 HEAD 검증이 누락되면 설치 금지
- 서명·GitHub 승인·root 보호 경로의 누락 상태는 SOURCE PASS/CI PASS로 대체할 수 없습니다
- 이미 부분 설치된 상태이거나 SSH timeout/UNKNOWN이면 자동 재시도 금지, 실기기에서 소유자가 상태·복구 경로 확인

**진행 판정:** 비권한 사전점검 PASS는 *소스 인계 준비*만 의미. 실제 최초 root 설치 허용은 별도 소유자 인증 및 독립 서명·승인 후에만 결정합니다.
