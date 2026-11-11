# Evidence folder

Every claim in the report should point to a file here. Use a predictable name:

```
v1-before.txt          v1-after.txt
v2-before.png          v2-after.png
v3-before.png          v3-after.png
v4-before.png          v4-after.png
v5-before.txt          v5-after.txt
v6-before.txt          v6-after.txt
pipeline-secret-red.png
pipeline-deps-red.png
pipeline-green.png
admission-rejected.png
netpol-before.png
netpol-after.png
zap-before.html
zap-after.html
detection-alert.png
ir-timeline.md
```

Rules:

- Capture the **request and response**, not just the browser.
- Include the timestamp and the environment (local compose / kind).
- Redact real secrets; fake values are fine.
- Do not edit screenshots after capture; annotate in the report instead.
- Keep the raw ZAP JSON as well as the HTML report.
