# SkillSpector 2.13.1

This patch release is based on the published v2.13.0 maintenance branch. It
corrects false incomplete-analysis reports for ordinary Python report strings,
quoted script text, regular expressions, and possessive Markdown prose, and
false P2 hidden-instruction findings that spanned visible text between HTML
comments. It also backports three security fixes merged to `main` after
v2.13.0: safer report and baseline file output, incomplete-coverage reporting
for failed batch gap-fill passes, and bounded tool-misuse context and deadlines.

## Selected changes

- [#778](https://github.com/NVIDIA/SkillSpector/pull/778) establishes bounded
  Python and Perl host-language ownership for the shell parser.
- [#784](https://github.com/NVIDIA/SkillSpector/pull/784) shares validated Python
  quote ownership with marker reconstruction.
- [#849](https://github.com/NVIDIA/SkillSpector/pull/849) corrects prose and
  report-string parsing, using those prerequisites.
- Additional release hardening retains the previous incomplete-inspection
  result when a report-shaped string is later assembled into a shell command.
  The check covers recognized local execution and a bounded set of bundled
  helpers, including import-time initialization. It does not lower findings
  or suppress an incomplete scan.
- Deep expressions in bundled Python helpers retain conservative shell bounds
  when the optional import proof exceeds Python's serialization recursion limit,
  instead of causing an analyzer failure.
- [#452](https://github.com/NVIDIA/SkillSpector/pull/452) keeps each P2
  hidden-instruction match inside one HTML comment, including the `--!>`,
  `<!-->` and `<!--->` closers. Keywords match at word and identifier
  boundaries, so visible text and words such as `target` or `POSTGRES` are not
  reported as hidden instructions. Run-together directives such as
  `PLEASEIGNOREPREVIOUSINSTRUCTIONS` remain detected.
- Source distributions exclude the `.uv-cache` directory used by the release
  workflow.

The release preserves v2.13.0's third-party dependency lock, provider and model
defaults, and existing publishing workflow. It does not take the remaining
unselected changes from `main`.

## Backported security fixes

- [#790](https://github.com/NVIDIA/SkillSpector/pull/790) makes the tool-misuse
  analyzer reuse one line index for finding context, so files with thousands of
  tool-misuse matches are no longer re-read in full for each new finding line.
  The TM1–TM4 checks and the Perl print helper now stop when the per-file static
  analysis time limit is reached, instead of only after the whole file is
  scanned.
- [#797](https://github.com/NVIDIA/SkillSpector/pull/797) keeps core findings
  and findings from completed batches when the contributed batch scanner's
  non-English gap-fill pass fails part-way. The skill is reported as incomplete
  (`gap_fill_status: "incomplete"` with failure reasons and at least a CAUTION
  recommendation), and the batch run exits with code 2. Previously the failed
  pass was treated as complete with no findings.
- [#798](https://github.com/NVIDIA/SkillSpector/pull/798) writes report files
  (`scan`, `scan --recursive`, `scan --mcp-registry` and the contributed batch
  scanner's `--output`) and baselines atomically through an already-opened,
  no-follow parent directory. SkillSpector refuses symlinked or special-file
  destinations, symlinked parent directories and read-only existing files
  instead of writing through them. `skillspector baseline <path> -o -` writes the
  baseline as JSON to stdout.

## Compatibility and remaining limits

Genuine incomplete inspection and independent security findings remain blocking
signals. A missing-reference advisory is distinct from an uninspected existing
artifact. This patch does not resolve every parser limitation: nested Markdown
table cases and references to otherwise inspected ZIP/XLSX containers retain
their existing limitations. Passive image handling is unchanged.

The bundled-helper check reads only materialized scan inputs. Unsupported,
ambiguous, missing, cyclic, or over-budget local evidence retains the previous
parser fallback. External imports and arbitrary interprocedural execution remain
outside this bounded proof; this release does not claim whole-program analysis.

Report and baseline file output requires POSIX no-follow directory operations.
On platforms without them, including Windows, `--output` to a file fails before
analysis: omit `--output` for scan and batch reports, or use
`skillspector baseline <path> -o -`, and redirect stdout to a new file outside
the scan target. The parent directory must be writable, and on macOS its
ancestor directories must also be readable. Report files are written with
owner-only (0600) permissions, including when an existing report is replaced;
run the Docker image with `--user "$(id -u):$(id -g)"` to read reports it writes
to a mounted directory. Baselines keep the v2.13.0 rules: new files are private,
replaced files keep their access metadata, and updates that would need an
in-place write are refused.

In this release, when `scan --recursive` refuses or fails to write its combined
report, it exits with code 1 and an error traceback rather than code 2; the
destination is still not written through. Single-skill scans, `baseline` and the
batch scanner exit with code 2 in that case.

The gap-fill change in #797 applies to the contributed batch scanner in
`contrib/batch_scan`, which is not packaged in the wheel.

Exact, version-bound finding baselines must be regenerated and reviewed for
2.13.1; do not relabel a baseline from another scanner version. Consumers should
validate the published wheel against their original inputs and baseline before
activating the upgrade.

Merging a release PR into `yashraj/v2.13.0-base` with the `release:publish` label
already present triggers the existing workflow to publish the GitHub `v2.13.1`
release with wheel and source-distribution assets. Without that label, merging
does not publish a release. This workflow does not publish to PyPI.
