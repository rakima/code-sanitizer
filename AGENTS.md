# AGENTS.md

# Development Guidelines

## General

- Prioritize readability and maintainability over clever implementations.
- Follow the existing project structure and coding style.
- Avoid introducing new dependencies unless there is a clear benefit.
- Do not make unrelated changes while implementing a task.
- If requirements are ambiguous, make the most reasonable assumption and document it.

---

# Git Workflow

## Branch

- Never commit directly to `main`.
- Create a dedicated working branch for each feature or bug fix.
- Use the following naming convention:

```
feature/<name>
fix/<name>
refactor/<name>
docs/<name>
```

## Commit

Split commits into logical units.

A good commit should:

- represent one meaningful change
- be explainable in one sentence
- keep the project in a buildable state whenever practical

Avoid:

- mixing unrelated changes
- committing only temporary work
- huge "everything" commits

## Commit Granularity

Split commits by user-visible requirement or independently reviewable behavior.

When the user provides multiple bullet-point requirements:

- treat each bullet point as a separate commit by default
- do not combine multiple bullet points into one broad commit such as "improve usability"
- create at least one commit per independently testable requirement
- include related tests in the same commit as the implementation when practical
- create a separate test commit only when the tests span multiple implementation commits or form an independent testing change

A commit may include multiple files when they are all required to complete one behavior.

Do not split commits merely by file or implementation step.

Before committing, compare the planned commits with the user's requirement list and confirm that each requirement is represented by at least one commit.

## Commit Message

Use the following prefixes:

```
add:
fix:
ref:
test:
doc:
chore:
```

After the prefix, write the commit message in Japanese.

Examples:

```
add: ツール登録画面を追加
fix: 未保存確認ダイアログを追加
ref: 共通処理をサービスクラスへ移動
test: JSON比較のテストを追加
doc: READMEを更新
chore: 開発環境設定を更新
```

---

# Pull Requests

One feature or one bug fix should normally correspond to:

- one branch
- one Pull Request

Multiple commits inside a PR are encouraged.

PR description should include:

- Summary
- Main changes
- Test results
- Remaining issues (if any)

Do not merge PRs unless explicitly instructed.

---

# Large Tasks

For large implementations:

1. Analyze the task.
2. Break the work into a checklist.
3. Create an implementation plan.
4. Implement the foundation.
5. Create a Draft Pull Request when the overall design becomes reviewable.
6. Continue implementation incrementally by completing the checklist item by item.
7. Convert the Draft PR to Ready for Review when complete.

Keep commits logically separated throughout the implementation.

Stop and request confirmation only when:

- database schema changes significantly
- public API changes significantly
- project architecture changes significantly
- requirements become inconsistent

Otherwise continue implementation autonomously.

---

# Code Quality

Prefer:

- small functions
- meaningful names
- early returns
- low nesting
- reusable components

Avoid:

- duplicated logic
- dead code
- commented-out code
- unnecessary abstractions

---

# Testing

When possible:

- add tests for new functionality
- update existing tests when behavior changes

Before finishing:

- run available tests
- fix obvious failures caused by your changes

---

# Documentation

If user-facing behavior changes:

- update README
- update examples if necessary

---

# Safety

Never:

- force push
- rewrite git history
- delete branches
- modify unrelated files
- disable tests to make builds pass

---

# Review Priority

When creating a PR, identify:

## High

- Architecture changes
- Database changes
- Public interfaces
- Concurrency
- Data persistence

## Medium

- Business logic
- Algorithms
- Validation

## Low

- README
- Comments
- Formatting
- Simple UI adjustments
- Generated code

Include review priorities inside the PR description whenever practical.

---

# Parallel Development

Independent tasks may be developed in parallel on separate branches.

If a task depends on another unmerged branch:

- clearly mention the dependency
- continue only if explicitly instructed

Do not mix multiple independent features into one branch.

---

# Definition of Done

A task is complete when:

- implementation is finished
- code is clean
- tests pass (when available)
- documentation is updated (if needed)
- commits are logically organized
- the branch is pushed
- the Pull Request is ready (or Draft Pull Request if instructed)

---

# Project Philosophy

- Prefer simple implementations over highly generic designs.
- Avoid premature optimization.
- Avoid adding extension points unless they are expected to be used soon.
- Minimize configuration unless it clearly improves usability.

---

# UI

For desktop tools:

- prioritize usability over visual appearance
- keep layouts simple
- remember frequently used paths and settings when appropriate
- avoid unnecessary dialogs

---

# Libraries

Prefer standard libraries unless external libraries provide significant value.

---

# Performance

Optimize only after correctness.

Avoid sacrificing readability for small performance gains.

---

# Communication

When multiple implementation approaches exist:

- choose the most practical one
- briefly explain the reason inside the Pull Request description

Avoid asking unnecessary confirmation questions if the decision has low impact.

## Starting New Tasks

Before starting a new task:

- switch to `main`
- pull the latest changes
- create a new feature branch from the updated `main`

Do not continue working on an old feature branch after it has been merged.