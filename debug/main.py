import json
import os
import sys

result = {
    "all_env": {k: v for k, v in os.environ.items() if not k.startswith(("_", "PATH", "HOME", "SHELL", "USER", "LANG", "TERM", "TMPDIR", "LOGNAME", "PWD", "SHLVL", "OLDPWD", "SSH", "XPC", "SECURITYSESSION", "Apple", "COMMAND_MODE", "LC_", "COLORTERM", "VIRTUAL_ENV", "__CF", "__PYVENV"))},
    "argv": sys.argv,
    "stdin_available": not sys.stdin.isatty() if hasattr(sys.stdin, 'isatty') else "unknown",
}

try:
    import select
    if select.select([sys.stdin], [], [], 0.1)[0]:
        result["stdin_data"] = sys.stdin.read()[:500]
    else:
        result["stdin_data"] = "no stdin data"
except Exception as e:
    result["stdin_data"] = f"error: {e}"

print(json.dumps(result, indent=2, default=str))
