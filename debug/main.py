import json
import os

sections_raw = os.environ.get("sections", "NOT_SET")
print(json.dumps({
    "raw_type": str(type(sections_raw)),
    "raw_value": sections_raw,
    "raw_repr": repr(sections_raw),
}, indent=2))
