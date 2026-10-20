from __future__ import annotations

import argparse
import getpass
import json
import os
from pathlib import Path
import sys

from .common import ROOT, SafeError, http, load_local_env, now, read_json


def main():
    # Read the command and its options, then start the requested task. Keeping
    # command handling here lets the other modules focus on the assessment itself.
    parser = argparse.ArgumentParser(description="Read-only CVE-2024-21762 security triage")
    sub = parser.add_subparsers(dest="command", required=True)
    run_cmd = sub.add_parser("run", help="Execute a real model run or explicitly scripted replay")
    run_cmd.add_argument("--scenario", choices=[p.stem for p in (ROOT / "data/environment").glob("*.json")], default="baseline")
    run_cmd.add_argument("--provider", choices=["duke", "replay"], default="duke")
    run_cmd.add_argument("--evidence-mode", choices=["auto", "live", "cached"], default="auto")
    run_cmd.add_argument("--output", type=Path)
    run_cmd.add_argument("--controlled-failure", choices=["threat_unavailable"])
    sub.add_parser("configure", help="Enter Duke token privately into ignored local .env")
    sub.add_parser("models", help="List model IDs currently accessible to your Duke key")
    sub.add_parser("doctor", help="Check setup without revealing credentials")
    sub.add_parser("evaluate", help="Run controlled replay scenarios and write actual results")
    args = parser.parse_args()
    load_local_env()
    try:
        if args.command == "configure":
            # Collect credentials privately and limit access to the saved file
            # so the user does not need to put an API token in source code.
            key = getpass.getpass("Duke AI Gateway token (hidden; do not paste into chat): ")
            if not key or any(c.isspace() for c in key):
                raise SafeError("invalid_token_format")
            model = input("Model ID [GPT 4.1]: ").strip() or "GPT 4.1"
            if "\n" in model or "\r" in model:
                raise SafeError("invalid_model_id")
            path = ROOT / ".env"
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0), 0o600)
            if hasattr(os, "fchmod"):
                os.fchmod(fd, 0o600)
            with os.fdopen(fd, "w") as stream:
                stream.write("LITELLM_TOKEN=" + key + "\nTRIAGE_MODEL=" + model + "\n")
            print("Saved private local configuration to ignored .env")
        elif args.command == "models":
            # Ask Duke which models this credential can access before a run.
            from .models import DukeModel, DUKE_BASE
            provider = DukeModel(read_json(ROOT / "config/agent.json"))
            response = json.loads(http(DUKE_BASE + "/models", 10, credential=provider.credential))
            for record in response.get("data", []):
                print(record["id"])
        elif args.command == "doctor":
            # Check local setup and cached evidence without making a model call.
            print("Python:", sys.version.split()[0])
            print("Duke credential:", "configured" if os.environ.get("LITELLM_TOKEN") or os.environ.get("DUKE_AI_GATEWAY_API_KEY") else "missing (python3 -m triage configure)")
            print("Model:", os.environ.get("TRIAGE_MODEL") or read_json(ROOT / "config/agent.json")["model"])
            from .tools import Tools
            from .common import Budget
            config = read_json(ROOT / "config/agent.json")
            instance = Tools(read_json(ROOT / "data/environment/baseline.json"), Budget(config), ROOT / "artifacts", "cached")
            for source in ("cna", "cert", "kev"):
                instance.source(source)
                print("Verified cached evidence:", source)
        elif args.command == "evaluate":
            from scripts.evaluate import evaluate
            evaluate()
        else:
            # Delegate the assessment to the agent and print a short summary.
            # Insufficient evidence is a valid result; stopped execution is an error.
            from .agent import run
            output = args.output or ROOT / "artifacts/runs" / (args.scenario + "-" + args.provider + "-" + now().replace(":", "").replace("+", ""))
            assessment, checklist = run(ROOT / f"data/environment/{args.scenario}.json", output,
                                        provider=args.provider, evidence_mode=args.evidence_mode, controlled_failure=args.controlled_failure)
            print(json.dumps({"status": assessment["status"], "rating": assessment["rating"], "priority": assessment["priority"],
                              "policy_rule": assessment["policy_rule"], "model_mode": assessment["model"]["mode"],
                              "output": str(output), "technical_demo_complete": checklist["complete_run_technical_requirements_met"]}))
            if assessment["execution_status"] != "complete":
                return 2
        return 0
    except SafeError as exc:
        print("Setup/execution error:", str(exc), file=sys.stderr)
        return 2
    except (ValueError, KeyError, TypeError, OSError):
        print("Local configuration or output error; inspect setup and filesystem permissions. No remote exception body is logged.", file=sys.stderr)
        return 2


if __name__ == "__main__":
    # Running `python -m triage` starts here; return the command's exit status.
    raise SystemExit(main())
