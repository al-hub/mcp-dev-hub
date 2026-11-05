# MCP Dev Hub — 상위 제약 (Constraints)

**최종 목표:** 모바일 등에서 개발을 지시한 뒤 WSL Worker가 사전 승인된 범위의 코드 수정 → 격리 테스트 → 실제 독립 Codex 리뷰 → PR/필수 CI → 보호 규칙에 따른 병합 → main CI → Issue Close까지 **사용자 중간 개입 없이** 수행한다. 접속이 끊겨도 상태를 보존하고 이어서 처리한다.

이 문서에는 **프로젝트 전체의 방향·제약·이슈별 책임만 기록**한다. 개별 오류·환경 진단·증거·수정 내역·검증 및 해제 조건은 **담당 GitHub Issues/PRs**에서 관리한다.

## 상위 원칙

1. **WSL Worker가 실행 주체다.** Microduck MCP와 ClosePaw MCP는 선택적인 접속/관찰 수단이며, 특정 경로의 장애가 다른 경로의 개발·CI를 불필요하게 막아서는 안 된다.
2. **승인 범위 내 반복 사용자 개입 0회**가 목표다. 작업마다 sudo나 수동 설치를 요구하지 않되, 새로운 root 정책·허용 범위·신뢰키 변경을 AI가 독단적으로 승인하지 않는다.
3. **보안 게이트를 유지한다.** 최소 권한, 격리 실행, 실제 독립 Codex 리뷰, 필수 GitHub CI 및 branch 보호를 우회하지 않는다. 전역 AI_WRITE/AI_PUSH를 검증 없이 활성화하지 않는다.
4. **데이터와 실행 결과를 보존한다.** 기존 Worker/Dashboard·작업 원장·설정을 보존하고, unknown/timeout 결과는 식별자로 조회한다. 실패한 외부 작업을 추측해 재실행하지 않는다. 미검증을 성공으로 표시하거나 이슈를 조기 Close하지 않는다.
5. **기존 자산을 재사용한다.** 이미 검증한 코드·연결·CI·증거를 우선 활용하고 새 계정/앱/권한 확대나 반복 구축을 최소화한다.
6. **공개 정보는 비식별로 유지한다.** 실제 장비·계정·IP·개인 경로·SSH 구성·키·토큰·운영 로그는 기록하지 않는다. 위험 작업 전에는 담당 이슈의 최신 증거만 필요한 범위에서 재검증한다.

## 상세 문제 및 수용 책임

| 이슈 | 역할 / 현재 영향 (2026-11-06 확인 시점) |
| --- | --- |
| [MCP Dev Hub #35](https://github.com/al-hub/mcp-dev-hub/issues/35) | OPEN — 보호 실행기 무인 업데이트·최소 권한. Microduck 실행 범위·CLI 리뷰·보호 파일 권한의 [상세 제약 기록](https://github.com/al-hub/mcp-dev-hub/issues/35#issuecomment-6672144819) |
| [MCP Dev Hub #36](https://github.com/al-hub/mcp-dev-hub/issues/36) | OPEN — 범용 Issue → AI 개발 → 검증·병합·Close 자동화 |
| [MCP Dev Hub #37](https://github.com/al-hub/mcp-dev-hub/issues/37) | OPEN — 서로 다른 3건의 실제 개발·단절·복구 무인 수용 |
| [ClosePaw #225](https://github.com/al-hub/closepaw/issues/225) | OPEN — 선택적 Bridge→WSL 경로 복구. [실기기 제약 기록](https://github.com/al-hub/closepaw/issues/225#issuecomment-6672145304) |

**수용 순서:** #35 → #36 → #37. 이 순서는 최종 수용을 위한 조건이며, 가능한 코드 개발/CI를 불필요하게 멈추라는 뜻이 아니다. ClosePaw #225는 별도 복구한다. **최신 상태의 기준은 각각의 이슈**다.

## 유지 관리

- 상위 목표·보안 원칙·역할 분담이 바뀔 때에만 **이 문서**를 수정한다. 일상적인 장애 상태와 세부 검증·해제 근거는 해당 **Issue/PR**에서 갱신한다.
- [AGENTS.md](../../AGENTS.md)는 시작 지침, [docs/STATUS.md](../STATUS.md)는 진행 이력, [SECURITY.md](../../SECURITY.md)는 공개 정보 기준이다.
- 상세 제약의 이전 문서 버전은 [초판 PR #40](https://github.com/al-hub/mcp-dev-hub/pull/40) Git 이력과 담당 이슈 댓글에서 찾을 수 있다.
