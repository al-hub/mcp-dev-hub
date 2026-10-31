# mcp-dev-hub

여러 AI 클라이언트가 로컬 PC 및 SSH PC에서 개발 작업을 수행하도록 연결하는 공통 MCP 허브입니다.

## 현재 상태

초기 개발 기반입니다. 설정 검증, 실행기·작업 저장소 인터페이스, 공개 저장소 개인정보 검사와 CI를 제공합니다.
**MCP 서버 기동, 명령 실행, SSH 접속, 코딩 CLI 연결은 아직 구현되지 않았습니다.**
ChatGPT·Claude·Gemini의 실제 연결 호환성은 구현 후 클라이언트별로 검증합니다.

## 개발 시작

Node.js 24 이상을 사용합니다. 초기 검증은 외부 의존성 없이 실행됩니다.

```sh
npm test
npm run check:privacy
npm run check
```

`npm run check`는 Git이 추적하는 파일을 검사하므로 새 파일을 stage한 후 실행합니다.
설치·실행 서비스 배포 방법은 실행기 구현 후 추가합니다. 현재 명령은 개발 검증용입니다.

## 구조

- `src/config.ts`: 비공개 설정의 형식과 검증
- `src/executors/`: 로컬·SSH 공통 실행 계약
- `src/jobs/`: 지속 작업 및 상태 전이 계약
- `src/mcp/`: MCP 도구와 전송 계층 설계
- `src/agents/`: 코딩 CLI 어댑터 설계
- `config/hub.example.json`: 가상 값만 포함한 예제
- `scripts/check-privacy.mjs`: 커밋 대상의 금지 경로·민감정보 후보 검사
- `docs/`: 아키텍처, 단계별 완료 기준, 다음 작업

AI CLI는 먼저 [AGENTS.md](AGENTS.md)를 읽습니다. Claude와 Gemini용 진입 문서도 같은 지침을 가리킵니다.
개인정보 관리 기준은 [SECURITY.md](SECURITY.md)에 있습니다.

## AI 개발 모델 선택 원칙

- **무료·경량 모델 우선:** 파일 탐색, 요약, 반복 점검에는 실제 호출이 확인된 OpenCode 무료 모델을 먼저 고려합니다.
- **필요할 때 상향:** 일반 구현은 Codex 기본 모델 또는 AGY 중간급 모델, 복잡한 설계·보안 검토는 상위 모델을 선택합니다. 한 모델을 고정하지 않습니다.
- **독립 리뷰:** 구현과 리뷰는 가급적 다른 모델 계열로 분리하고, 중요도에 맞게 추론 수준을 조절합니다.
- **사용량·안전:** 작업별 호출 범위와 시간·토큰 예산을 제한하며, 할당량 소진·실패 시 무한 재시도나 무단 유료 모델 전환을 하지 않습니다.
- **검증 구분:** 모델 목록 노출, 짧은 응답 성공, 실제 개발·리뷰 완료를 구분해 기록합니다. 모델·계정별 제공 여부와 무료 한도는 변할 수 있습니다.

노트북에서 실호출이 확인된 OpenCode 무료 모델: `glm-5.3-flash-free`, `deepseek-v4.1-flash-free`, `mimo-v2.6-flash-free`, `nemotron-3.5-lightning-free`, `flint-40b-free`, `beam-free`, `big-pickle`, `nemotron-3.5-super-vl-free` (모두 `opencode/` 접두어). 상세 검증 및 갱신 기준은 [이슈 #10](https://github.com/al-hub/mcp-dev-hub/issues/10)을 참조합니다.
