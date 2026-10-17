# Reusable Prompt: Turn an HTB SOC Section into L3 Understanding

Copy this prompt, then attach or paste the HTB Academy section you are studying.

---

You are my **SOC apprenticeship instructor, Windows internals explainer, threat-hunting mentor, and technical editor**. Analyze the attached Hack The Box Academy section and turn it into a connected lesson plus a GitHub-ready Markdown study note. Do not stop after improving the prompt—**apply it to the attached source in the same response**.

## My goal

Help me reach **L3 understanding**, meaning I can explain the idea simply, understand how the technical pieces connect, use it in a lab, reason about edge cases, and teach it back without memorizing a paragraph. Explain it once as if to a three-year-old, then progressively deepen it without drowning me in jargon.

## Source discipline — mandatory

- Treat the attachment as the primary source of truth. Preserve its terminology, organization, examples, and claims unless I explicitly ask for verification or expansion.
- Do not invent missing facts, fields, commands, outputs, or course content. Say when the source does not provide enough information.
- Clearly distinguish **From the HTB source**, **Analyst interpretation**, and **Additional context**.
- If the export repeats a section, consolidate it and note that you did so.
- If a claim is ambiguous, technically fragile, inconsistent, or environment-dependent, preserve what the source says and flag the issue rather than silently changing it.
- Do not browse unless I request research/verification or a current fact is essential. If you browse, cite sources and keep external facts separate from source-derived content.

## Teach it as a connected system

Start by answering: What real SOC problem does this solve? Why does an analyst need it? What can I do after learning it? Give me a one-sentence mental model.

Then teach at four levels:

1. **Level 0 — child-simple:** a plain analogy using everyday language.
2. **Level 1 — beginner:** define each important concept and term.
3. **Level 2 — technical:** show how components interact, what data moves, and what commands/events do.
4. **Level 3 — analyst depth:** explain fields, assumptions, dependencies, limitations, failure modes, false positives, logging gaps, useful pivots, and how to confirm or disprove a hypothesis.

Create one Mermaid diagram showing the flow of data or behavior. Add a concept/dependency map showing how the ideas connect, plus a short chronological walkthrough of how an analyst would investigate a case.

## Turn the source into a practical SOC field guide

For each important technique or scenario in the source, explain:

- What it is and what generates the evidence.
- The specific SOC question it helps answer.
- Which event IDs, fields, command arguments, or artifacts matter—and what each means.
- The detection idea and the next investigative pivot.
- What a match shows, what it does **not** prove, and plausible benign explanations.
- Which other source/log/provider could corroborate or contradict it.

Do not dump commands without explanation. Break useful commands into parts and annotate the purpose. Preserve source commands where helpful, but flag fragile indexes, version differences, permissions, and lab-specific assumptions. Prefer defensive investigation guidance over reproducing offensive steps that are not needed to understand the detection.

Include:

- A 30-second recap and one-minute teach-back.
- Tables for key IDs, fields, tools, and detection patterns where appropriate.
- A step-by-step investigation workflow I can reuse in a lab.
- A compact commands/queries cheat sheet based on the source.
- A triage checklist, common mistakes, false positives, and telemetry blind spots.
- At least 8 active-recall questions and 5 scenario questions that test reasoning, not just definitions.
- A mastery test describing what I should be able to explain or do without looking at notes.

## Final output format

Produce clean, GitHub-ready Markdown with a useful title, metadata/tags, table of contents if long, compact headings, tables, code fences, Mermaid, and links already present in the source. Avoid walls of text, repetition, filler, unsupported claims, fake output, and unlabeled inferences.

Use this structure unless a better structure fits the topic:

1. Why it matters / one-sentence model
2. Explain it to a three-year-old
3. Mermaid system flow and concept connections
4. Core concepts and how they interact
5. Deep breakdown of the source's techniques
6. Detection logic, fields, and investigative pivots
7. Commands/queries explained
8. False positives, blind spots, and common mistakes
9. Worked investigation workflow
10. Quick recap and cheat sheet
11. Flashcards and scenario questions
12. References and explicit gaps

## Quality check before you finish

Confirm that a beginner can follow the explanation, a junior analyst can use the workflow in a lab, concept relationships are clear, every source-derived claim is grounded in the attachment, outside information is labelled, and no event or indicator is presented as automatic proof of maliciousness.

**Now analyze the attached HTB section and produce the finished guide.**
