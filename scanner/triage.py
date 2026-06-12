# ============================================================
# triage.py — uses Claude to check Semgrep's security findings
# Reads findings.json, asks Claude about each one, writes report.md
# ============================================================

import json                  # to read findings.json and read Claude's answer
import os                    # to check our API key is set
from pathlib import Path     # to read code files easily
import anthropic             # the Claude client

MODEL = "claude-sonnet-4-5"  # which Claude model to use


# ============================================================
# STEP 1: open findings + remove duplicates (same file & line)
# ============================================================
def load_findings():
    data = json.load(open("findings.json"))   # open + parse the JSON file
    results = data["results"]                 # the full list of findings

    seen = set()                              # file+line combos we've kept
    unique = []                               # the de-duplicated list
    for finding in results:
        key = (finding["path"], finding["start"]["line"])  # this finding's location
        if key not in seen:                   # not seen this spot before?
            seen.add(key)                     # remember it
            unique.append(finding)            # keep this finding
    return unique                             # return cleaned list


# ============================================================
# STEP 2: grab the code around a finding
# Shows REAL line numbers and marks the flagged line with >>>.
# Special handling for findings buried inside very long lines
# (like giant data constants) so Claude isn't misled.
# ============================================================
def get_code(path, line, col):
    all_lines = Path(path).read_text().splitlines()   # file -> list of lines

    # If the column is huge, the finding sits inside one very long line.
    if col > 300:
        target = all_lines[line - 1]                  # the long line
        first_word = target.lstrip()[:40]             # how the line starts

        # Is this line a constant/data assignment? (e.g. "CASES = (...")
        is_constant = "= (" in first_word or "= [" in first_word or "= {" in first_word

        start = max(0, col - 200)                     # slice around the trigger
        end = min(len(target), col + 200)
        snippet = target[start:end]

        note = (
            f"(This finding is at column {col} inside a very long line "
            f"({len(target)} chars).\n"
        )
        if is_constant:
            note += (
                f"IMPORTANT: line {line} is a DATA CONSTANT assignment that starts with "
                f"'{first_word.strip()}...'. The flagged code is example/demo DATA inside "
                f"this constant, not an executed code path. Attack strings stored in a "
                f"constant do NOT run. Judge accordingly.)\n"
            )
        else:
            note += "Showing the relevant slice of that line.)\n"

        return note + f"...{snippet}..."

    # Normal case: show 10 lines before and after, WITH real line numbers
    start = max(0, line - 11)
    end = min(len(all_lines), line + 10)
    numbered = []
    for i in range(start, end):
        marker = "  >>>" if (i + 1) == line else "     "  # arrow on the flagged line
        numbered.append(f"{marker} {i + 1}: {all_lines[i]}")
    return "\n".join(numbered)


# ============================================================
# STEP 2b: cheap taint-source check (used as a signal, not a gate)
# Does the flagged line read user input (params[...])?
# We use this to PRIORITIZE, never to silently drop a finding.
# ============================================================
def has_user_input(path, line):
    code_line = Path(path).read_text().splitlines()[line - 1]  # the flagged line
    return "params[" in code_line or "params.get" in code_line


# ============================================================
# STEP 3: ask Claude about one finding
# ============================================================
def ask_claude(client, finding):
    path = finding["path"]                # the file name
    line = finding["start"]["line"]       # the line number
    col = finding["start"]["col"]         # column number (spots giant lines)
    rule = finding["check_id"]            # which rule fired
    code = get_code(path, line, col)      # the surrounding code (STEP 2)

    question = f"""You are a security engineer triaging a code scan finding.
Decide if it is a REAL, exploitable vulnerability.

Key rule: trace whether attacker-controlled input (like a URL parameter, e.g. params[...])
can actually REACH the dangerous operation on the flagged line.

The code below has real line numbers. The flagged line is marked with >>>.
Judge ONLY the flagged line; do not renumber or refer to other line numbers.

Mark it false_positive ONLY if you are confident the dangerous call cannot receive
attacker input — for example:
- The flagged line is purely a constant or list/tuple of demo/description strings AND
  no user input reaches a dangerous function ON THAT LINE.
- The value reaching the dangerous call is hardcoded or internal, not user input.
- The input is fully sanitized before the dangerous call.

IMPORTANT: If the flagged line itself concatenates or formats user input (e.g. params[...])
into a dangerous call like execute(), exec(), urlopen(), subprocess with shell=True, or
pickle.loads(), it is ALWAYS true_positive — even if nearby lines look like setup code.

When unsure, choose true_positive (missing a real bug is worse than a false alarm).

Rule: {rule}
File: {path}, flagged line: {line}

Code:
{code}

Answer with ONLY this JSON, no extra text, no markdown:
{{"verdict": "true_positive or false_positive", "reason": "short reason", "fix": "how to fix it"}}"""

    reply = client.messages.create(
        model=MODEL,
        max_tokens=400,
        messages=[{"role": "user", "content": question}],
    )

    answer = reply.content[0].text.strip()   # Claude's text answer

    # Claude sometimes wraps JSON in ```fences``` — remove them
    if answer.startswith("```"):
        answer = answer.strip("`")
        if answer.startswith("json"):
            answer = answer[4:]
        answer = answer.strip()

    try:
        return json.loads(answer)
    except json.JSONDecodeError:
        return {
            "verdict": "needs_review",
            "reason": "Claude's answer was not valid JSON",
            "fix": answer[:200],
        }


# ============================================================
# STEP 4: main — run everything in order
# ============================================================
def main():
    if not os.environ.get("ANTHROPIC_API_KEY"):
        print("Please set ANTHROPIC_API_KEY first.")
        return

    findings = load_findings()               # STEP 1
    print("Found", len(findings), "findings. Asking Claude...")

    client = anthropic.Anthropic()           # connect to Claude
    report_lines = ["# Security Report\n"]

    for finding in findings:
        line = finding["start"]["line"]
        print("  checking line", line, "...")

        result = ask_claude(client, finding)              # STEP 3
        tainted = has_user_input(finding["path"], line)   # STEP 2b signal
        flag = " ⚡ user-input on line" if tainted else ""  # show the signal

        report_lines.append(f"## Line {line} — {result['verdict']}{flag}")
        report_lines.append(f"- Reason: {result['reason']}")
        report_lines.append(f"- Fix: {result['fix']}\n")

    Path("report.md").write_text("\n".join(report_lines))
    print("Done! Open report.md to see the results.")


if __name__ == "__main__":
    main()

















































# # import json
# # import os
# # import sys
# # import argparse
# # from pathlib import Path

# # import anthropic

# # # Which Claude model to use. Check console.anthropic.com for the current
# # # model names; swap this string if needed.
# # MODEL = "claude-sonnet-4-5"


# # # ---------- Piece 2: load the findings Semgrep produced ----------

# # def load_findings(path="findings.json"):
# #     data = json.load(open(path))
# #     return data["results"]


# # # ---------- Piece 3: read the code around a finding ----------

# # def get_code_context(path, line, window=10):
# #     lines = Path(path).read_text(errors="replace").splitlines()
# #     start = max(0, line - window - 1)
# #     end = min(len(lines), line + window)
# #     numbered = []
# #     for i in range(start, end):
# #         numbered.append(f"{i + 1} | {lines[i]}")
# #     return "\n".join(numbered)


# # # ---------- Piece 4: ask Claude to triage one finding ----------

# # PROMPT = """You are a senior application security engineer triaging a static \
# # analysis finding. Decide whether it is genuinely exploitable by tracing whether \
# # attacker-controlled input can reach the dangerous operation.

# # Rule that fired: {rule}
# # Scanner message: {message}
# # Location: {path} line {line}

# # Code context (line numbers included):
# # {code}

# # Think about: is the data reaching the dangerous call user-controlled, or is it a \
# # fixed/internal value? Is there sanitization in between? Is this test or demo code?

# # Respond with ONLY raw JSON, no markdown fences, in exactly this shape:
# # {{
# #   "verdict": "true_positive" | "false_positive" | "needs_review",
# #   "exploitability": "high" | "medium" | "low",
# #   "reasoning": "one or two sentences",
# #   "fix": "concrete code-level fix"
# # }}"""


# # def triage_finding(client, finding):
# #     path = finding["path"]
# #     line = finding["start"]["line"]

# #     prompt = PROMPT.format(
# #         rule=finding["check_id"],
# #         message=finding["extra"].get("message", ""),
# #         path=path,
# #         line=line,
# #         code=get_code_context(path, line),
# #     )

# #     response = client.messages.create(
# #         model=MODEL,
# #         max_tokens=600,
# #         messages=[{"role": "user", "content": prompt}],
# #     )

# #     text = response.content[0].text.strip()
# #     # Claude sometimes wraps JSON in ```fences``` — strip them defensively
# #     text = text.removeprefix("```json").removeprefix("```").removesuffix("```").strip()

# #     try:
# #         return json.loads(text)
# #     except json.JSONDecodeError:
# #         return {
# #             "verdict": "needs_review",
# #             "exploitability": "medium",
# #             "reasoning": "Claude's reply was not valid JSON.",
# #             "fix": text[:300],
# #         }


# # # ---------- Report writing ----------

# # VERDICT_ORDER = {"true_positive": 0, "needs_review": 1, "false_positive": 2}
# # EXPLOIT_ORDER = {"high": 0, "medium": 1, "low": 2}
# # ICON = {"true_positive": "🔴", "needs_review": "🟡", "false_positive": "⚪"}


# # def write_report(findings, output="report.md"):
# #     # Sort: true positives first, then by exploitability
# #     findings.sort(key=lambda f: (
# #         VERDICT_ORDER[f["triage"]["verdict"]],
# #         EXPLOIT_ORDER[f["triage"]["exploitability"]],
# #     ))

# #     tp = sum(f["triage"]["verdict"] == "true_positive" for f in findings)
# #     fp = sum(f["triage"]["verdict"] == "false_positive" for f in findings)
# #     nr = len(findings) - tp - fp

# #     out = [
# #         "# AI-Triaged Security Report\n",
# #         f"**{len(findings)} findings** — "
# #         f"🔴 {tp} true positive / ⚪ {fp} false positive / 🟡 {nr} needs review\n",
# #     ]

# #     for f in findings:
# #         t = f["triage"]
# #         out.append(f"## {ICON[t['verdict']]} {f['check_id']}")
# #         out.append(f"`{f['path']}:{f['start']['line']}`")
# #         out.append(f"- **Verdict:** {t['verdict']}  |  "
# #                    f"**Exploitability:** {t['exploitability']}")
# #         out.append(f"- **Why:** {t['reasoning']}")
# #         out.append(f"- **Fix:** {t['fix']}\n")

# #     Path(output).write_text("\n".join(out))
# #     print(f"\nReport written to {output}")
# #     print(f"🔴 {tp} true / ⚪ {fp} false / 🟡 {nr} review")


# # # ---------- main: glue it together ----------

# # def main():
# #     parser = argparse.ArgumentParser(description="LLM triage of Semgrep findings")
# #     parser.add_argument("--findings", default="findings.json")
# #     parser.add_argument("--output", default="report.md")
# #     parser.add_argument("--max", type=int, default=20,
# #                         help="Cap how many findings to triage (cost control)")
# #     args = parser.parse_args()

# #     if not os.environ.get("ANTHROPIC_API_KEY"):
# #         sys.exit("Set ANTHROPIC_API_KEY first (export ANTHROPIC_API_KEY=sk-ant-...).")

# #     findings = load_findings(args.findings)
# #     print(f"Loaded {len(findings)} findings. Triaging up to {args.max}...")

# #     client = anthropic.Anthropic()
# #     selected = findings[: args.max]
# #     for i, f in enumerate(selected, 1):
# #         short = f["check_id"].split(".")[-1]
# #         print(f"  [{i}/{len(selected)}] {short} (line {f['start']['line']})")
# #         f["triage"] = triage_finding(client, f)

# #     write_report(selected, args.output)


# # if __name__ == "__main__":
# #     main()




# # ============================================================
# # triage.py — uses Claude to check Semgrep's security findings
# # Reads findings.json, asks Claude about each one, writes report.md
# # ============================================================

# # --- import the tools we need ---
# import json                  # to read findings.json and read Claude's answer
# import os                    # to check our API key is set
# from pathlib import Path     # to read code files easily
# import anthropic             # the Claude client


# # --- settings ---
# MODEL = "claude-sonnet-4-5"  # which Claude model to use


# # ============================================================
# # STEP 1: open the findings file Semgrep made
# # ============================================================
# def load_findings():
#     data = json.load(open("findings.json"))  # open + parse the JSON file
#     return data["results"]                   # return just the list of findings


# # ============================================================
# # STEP 2: grab the code lines around a finding
# # (so Claude can see the context, not just one line)
# # ============================================================
# def get_code(path, line):
#     all_lines = Path(path).read_text().splitlines()  # read file into a list of lines
#     start = max(0, line - 11)                         # 10 lines before (don't go below 0)
#     end = min(len(all_lines), line + 10)              # 10 lines after (don't pass the end)
#     chunk = all_lines[start:end]                      # slice out that section
#     return "\n".join(chunk)                           # join them back into text


# # ============================================================
# # STEP 3: ask Claude about one finding
# # ============================================================
# def ask_claude(client, finding):
#     path = finding["path"]                # the file name
#     line = finding["start"]["line"]       # the line number
#     rule = finding["check_id"]            # which rule fired
#     code = get_code(path, line)           # the surrounding code (from STEP 2)

#     # the question we send to Claude
#     question = f"""You are a security engineer. Look at this code finding.

# Rule: {rule}
# File: {path}, line {line}

# Code:
# {code}

# Is this a real vulnerability? Answer with ONLY this JSON (no extra text):
# {{"verdict": "true_positive or false_positive", "reason": "short reason", "fix": "how to fix it"}}"""

#     # send the question to Claude
#     reply = client.messages.create(
#         model=MODEL,
#         max_tokens=400,
#         messages=[{"role": "user", "content": question}],
#     )

#     answer = reply.content[0].text.strip()   # get Claude's text answer

#     # Claude sometimes wraps JSON in ```fences``` — remove them
#     if answer.startswith("```"):
#         answer = answer.strip("`")            # remove the backticks
#         if answer.startswith("json"):
#             answer = answer[4:]               # remove the word "json"
#         answer = answer.strip()

#     # try to read it as JSON; if it fails, mark it for manual review
#     try:
#         return json.loads(answer)
#     except json.JSONDecodeError:
#         return {
#             "verdict": "needs_review",
#             "reason": "Claude's answer was not valid JSON",
#             "fix": answer[:200],
#         }




# # ============================================================
# # STEP 4: main — run everything in order
# # ============================================================
# def main():
#     # make sure the API key is set, or stop with a message
#     if not os.environ.get("ANTHROPIC_API_KEY"):
#         print("Please set ANTHROPIC_API_KEY first.")
#         return

#     findings = load_findings()               # STEP 1: get the findings
#     print("Found", len(findings), "findings. Asking Claude...")

#     client = anthropic.Anthropic()           # connect to Claude
#     report_lines = ["# Security Report\n"]    # we'll build the report here

#     # go through each finding one at a time
#     for finding in findings:
#         line = finding["start"]["line"]
#         print("  checking line", line, "...")

#         result = ask_claude(client, finding)  # STEP 3: ask Claude

#         # add this finding's result to the report
#         report_lines.append(f"## Line {line} — {result['verdict']}")
#         report_lines.append(f"- Reason: {result['reason']}")
#         report_lines.append(f"- Fix: {result['fix']}\n")

#     # write everything to report.md
#     Path("report.md").write_text("\n".join(report_lines))
#     print("Done! Open report.md to see the results.")


# # this line runs main() when you start the script
# if __name__ == "__main__":
#     main()




































































































































































# # # import json
# # # import subprocess
# # # import sys
# # # from pathlib import Path

# # # import anthropic

# # # def run_semgrep(target):
# # #     cmd = [
# # #         "semgrep",
# # #         "scan",
# # #         "--config",
# # #         "auto",
# # #         "--json",
# # #         "--quiet",
# # #         target
# # #     ]

# # #     result = subprocess.run(
# # #         cmd,
# # #         capture_output=True,
# # #         text=True
# # #     )

# # #     return json.loads(
# # #         result.stdout
# # #     ).get("results", [])
    
# # # def read_code(filepath):
# # #     return Path(filepath).read_text()    


# # # def triage_with_claude(finding, source):
# # #     client = anthropic.Anthropic()

# # #     prompt = f"""
# # # You are an Application Security Engineer.

# # # Review this Semgrep finding.

# # # Finding:
# # # {json.dumps(finding, indent=2)}

# # # Source Code:
# # # {source}

# # # Return:
# # # 1. Severity
# # # 2. True Positive or False Positive
# # # 3. Explanation
# # # 4. Remediation
# # # """

# # #     response = client.messages.create(
# # #         model="claude-opus-4-8",
# # #         max_tokens=600,
# # #         messages=[
# # #             {
# # #                 "role": "user",
# # #                 "content": prompt
# # #             }
# # #         ]
# # #     )

# # #     return response.content[0].text

