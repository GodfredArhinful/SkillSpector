# SkillSpector v2.13.0

## Summary

This release selectively backports security hardening, blocking scan fixes, and executable Python support onto v2.12.0. It includes 55 selected PRs; #743 is included through #734. It does not include every change merged into main since v2.12.0.

## Compatibility notes

- NVIDIA Build defaults to GLM-5.3 after retirement of the previous default. Explicit model overrides remain supported.
- The Codex CLI analysis provider is disabled because its read-only sandbox permits access to host secrets. Use another supported provider.
- MCP HTTP listeners are restricted to loopback. Remote deployments require an authenticating proxy.
- Baseline generation uses atomic replacement. Updates that cannot preserve ownership or group safely are refused; write a new baseline file.
- If a real directory ending in `!` collides with an archive-member path, rename that directory to allow both files to be fully inspected.
- Exact-fingerprint baselines are version-bound and must be regenerated after upgrading.
- Static-only scans do not require an active LLM provider. LLM-enabled scans still reject unknown provider settings.
- Other provider defaults remain as in v2.12.0. The newer-model default change from #806 and its rollback in #824 are not included.

## Included changes

### Security and scan integrity

- [#471](https://github.com/NVIDIA/SkillSpector/pull/471): Reads SKILL.md metadata correctly when the file starts with an invisible encoding marker.
- [#473](https://github.com/NVIDIA/SkillSpector/pull/473): Detects text-direction control characters that can disguise code in bundled scripts, not just Markdown.
- [#499](https://github.com/NVIDIA/SkillSpector/pull/499): Marks recursive scan coverage as incomplete when linked skill folders are deliberately skipped.
- [#545](https://github.com/NVIDIA/SkillSpector/pull/545): Detects access to sensitive files even when their paths are assembled from fixed strings.
- [#557](https://github.com/NVIDIA/SkillSpector/pull/557): Marks analysis incomplete when custom YARA rules cannot be loaded or compiled.
- [#577](https://github.com/NVIDIA/SkillSpector/pull/577): Preserves dangerous shell-command findings when deeper Python analysis cannot confidently replace them.
- [#578](https://github.com/NVIDIA/SkillSpector/pull/578): Keeps distinct shell-command findings separate, even when their displayed snippets look identical.
- [#593](https://github.com/NVIDIA/SkillSpector/pull/593): Adds lower-confidence warnings for multiline scripts that appear to open a remote shell, while preserving existing one-line detections.
- [#595](https://github.com/NVIDIA/SkillSpector/pull/595): Shows how many linked skill folders were skipped and includes that count in recursive scan coverage.
- [#601](https://github.com/NVIDIA/SkillSpector/pull/601): Checks complete TypeScript declaration files before treating them as non-executable, so partial or disguised runtime code is not skipped.
- [#604](https://github.com/NVIDIA/SkillSpector/pull/604): Flags bundled settings that run commands, redirect AI traffic, or automatically approve connected tool servers.
- [#611](https://github.com/NVIDIA/SkillSpector/pull/611): Finds Python flows from secret reads to risky uses even when the assignments and uses appear at different nesting depths.
- [#632](https://github.com/NVIDIA/SkillSpector/pull/632): Inspects hooks declared in Claude plugin manifests and reports incomplete coverage when those declarations cannot be fully checked.
- [#637](https://github.com/NVIDIA/SkillSpector/pull/637): Makes saved baselines cover every occurrence of a repeated finding, so later scans suppress them consistently.
- [#655](https://github.com/NVIDIA/SkillSpector/pull/655): Detects bundled Node settings that use the short -r flag to load and run extra code.
- [#657](https://github.com/NVIDIA/SkillSpector/pull/657): Preserves exact findings in baselines and protects existing baseline files during regeneration.
- [#691](https://github.com/NVIDIA/SkillSpector/pull/691): Improves TP4 responses for the specific OpenAI-provider Opus 5 route and rejects missing, malformed, or contradictory tool results.
- [#702](https://github.com/NVIDIA/SkillSpector/pull/702): Attaches AI review decisions to the correct findings and distinguishes disagreement from missing or failed reviews.
- [#721](https://github.com/NVIDIA/SkillSpector/pull/721): Detects sensitive data passed to urllib opener requests, including inline opener calls.
- [#725](https://github.com/NVIDIA/SkillSpector/pull/725): Displays untrusted names, filenames and findings literally in terminal reports, preventing markup crashes and spoofing.
- [#729](https://github.com/NVIDIA/SkillSpector/pull/729): Rejects scan output that points to the input file, including symbolic or hard links, preventing accidental overwrites.
- [#733](https://github.com/NVIDIA/SkillSpector/pull/733): Prevents untrusted names and findings from inserting fake headings, rows or HTML into batch Markdown reports.
- [#734](https://github.com/NVIDIA/SkillSpector/pull/734): Displays untrusted skill names and errors literally in batch terminals so markup and control characters cannot spoof the output.
- [#735](https://github.com/NVIDIA/SkillSpector/pull/735): Prevents untrusted finding text and filenames from changing Markdown report structure, using shared protection for core and batch reports.
- [#736](https://github.com/NVIDIA/SkillSpector/pull/736): Stops remote MCP scans from using the server’s Git credentials to clone private repositories while preserving trusted local Git access.
- [#737](https://github.com/NVIDIA/SkillSpector/pull/737): Disables the Codex CLI analysis provider because its read-only sandbox still permits host-secret reads, directing users to another provider.
- [#738](https://github.com/NVIDIA/SkillSpector/pull/738): Limits environment variables passed to agent CLI providers so unexpected secret variables are not forwarded to child processes.
- [#739](https://github.com/NVIDIA/SkillSpector/pull/739): Prevents long scanner output from blocking Pi’s secret redaction while still hiding secrets before the displayed output is shortened.
- [#740](https://github.com/NVIDIA/SkillSpector/pull/740): Prevents crafted Python literals and unfinished function headers from causing extremely slow scans.
- [#743](https://github.com/NVIDIA/SkillSpector/pull/743): Enforces per-skill batch timeouts by stopping stuck workers while other scans continue.
- [#744](https://github.com/NVIDIA/SkillSpector/pull/744): Limits unauthenticated MCP HTTP access to the local machine; remote access requires an authenticating proxy.
- [#745](https://github.com/NVIDIA/SkillSpector/pull/745): Redacts short configured secrets from OpenCode’s returned output without corrupting JSON values; separately written report files remain outside this redactor.
- [#746](https://github.com/NVIDIA/SkillSpector/pull/746): Pins the release workflow’s checkout action to a fixed commit so a moving version tag cannot silently change the code it runs.
- [#758](https://github.com/NVIDIA/SkillSpector/pull/758): Prevents registry reports from overwriting their input files.
- [#767](https://github.com/NVIDIA/SkillSpector/pull/767): Keeps the release GitHub token out of Git configuration during dependency installation and builds.
- [#786](https://github.com/NVIDIA/SkillSpector/pull/786): Detects encoded shell payloads that are decoded and executed.
- [#791](https://github.com/NVIDIA/SkillSpector/pull/791): Requires approval for external Pi scan inputs and blocks file-reading YARA includes.
- [#792](https://github.com/NVIDIA/SkillSpector/pull/792): Separates local and referenced-content caches so baseline suppression cannot use the wrong file.
- [#793](https://github.com/NVIDIA/SkillSpector/pull/793): Prevents real disk paths from being overwritten by archive members with the same virtual path. Collisions retain the real content and report failed coverage.
- [#794](https://github.com/NVIDIA/SkillSpector/pull/794): Inspects readable instructions hidden behind binary file prefixes while keeping ordinary PDF/GIF assets and XMP metadata from producing false alarms. Referenced or executable binaries still report their inspection limits.
- [#795](https://github.com/NVIDIA/SkillSpector/pull/795): Treats OMS signing bundles as untrusted input, inspecting decoded metadata and preserving raw evidence and incomplete coverage when parsing fails.
- [#796](https://github.com/NVIDIA/SkillSpector/pull/796): Reports malformed LLM responses as incomplete analysis instead of successful empty results.

### Blocking and regression fixes

- [#623](https://github.com/NVIDIA/SkillSpector/pull/623): Keeps Python findings when parser location columns are missing, instead of crashing or merging distinct findings together.
- [#627](https://github.com/NVIDIA/SkillSpector/pull/627): Recognizes more ordinary Markdown sentences and lists so their apostrophes do not cause false shell-parsing and incomplete-scan warnings.
- [#634](https://github.com/NVIDIA/SkillSpector/pull/634): Parses quoted shell assignments correctly so harmless trailing text does not falsely make a scan incomplete.
- [#661](https://github.com/NVIDIA/SkillSpector/pull/661): Avoids misleading high-severity warnings on SKILL.md self-references while still reporting missing or ambiguous files.
- [#686](https://github.com/NVIDIA/SkillSpector/pull/686): Accepts ordinary shell variable defaults and assignment values without falsely marking their files as partly scanned.
- [#700](https://github.com/NVIDIA/SkillSpector/pull/700): Lowers alerts for simple download pipelines that demonstrably parse incoming data rather than execute it.
- [#704](https://github.com/NVIDIA/SkillSpector/pull/704): Recognizes safely decodable shell printf escapes without incorrectly marking analysis incomplete.
- [#748](https://github.com/NVIDIA/SkillSpector/pull/748): Switches NVIDIA Build’s default from retired GLM-5.2 to GLM-5.3 while preserving explicit model overrides.
- [#799](https://github.com/NVIDIA/SkillSpector/pull/799): Tracks sensitive-data flow by function scope, avoiding collisions between unrelated variable names.
- [#802](https://github.com/NVIDIA/SkillSpector/pull/802): Keeps intentionally excluded files separate from failed analyzer work in coverage reports.

- [#828](https://github.com/NVIDIA/SkillSpector/pull/828): Counts the bytecode walk’s own CPU time toward its processing limit, so waiting behind concurrent analyzers does not make clean scans incomplete. The overall scan deadline still applies.
- [#844](https://github.com/NVIDIA/SkillSpector/pull/844): Avoids execution warnings for simple decode-to-checksum pipelines while retaining warnings for executable or redirected payloads. Keeps disk and archive error locations distinct when paths collide.

### Executable Python support

- [#579](https://github.com/NVIDIA/SkillSpector/pull/579): Recognizes more executable Python files, including .pyw files and extensionless launchers.

## Integration notes

Selected changes are applied as their merge deltas against v2.12.0. Required shared response-handling, analyzer support, and provider-neutral static-mode helpers are adapted without importing the deferred features. The release PR records the exact adaptations and validation results.

Release review also identified excessive backtracking in TypeScript declaration recognition. Matching now has a time limit; files that cannot be proven inert within it remain eligible for executable analysis.

## Validation

The [release PR](https://github.com/NVIDIA/SkillSpector/pull/833) records the tested commits, wheel identities, source and installed-wheel test results, sample scans, live NVIDIA Build checks, and remaining review gaps. Each result is scoped to its tested revision.

## Known limitations

- Existing limits on analysis, unsupported inputs, and unavailable requested providers remain visible as incomplete coverage. A completed process is not proof of a clean skill.
- Short-secret redaction applies to the OpenCode extension response; separately written report files are outside that redactor.
- This selected release does not include fixes from open PRs. Malformed provider responses are reported as incomplete analysis; the release does not claim to repair an external provider returning invalid responses.
