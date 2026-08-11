from pathlib import Path
import shutil

repo=Path.cwd()
public=repo/"public"
pkg=Path(__file__).resolve().parent
if not (public/"app.html").exists():
    raise SystemExit("Run from bullion-dealer-pro repo root.")

# Preview-only install. Do not replace /app.
for name in ("bdp-v3.html","bdp-v3.css","bdp-v3.js"):
    shutil.copy2(pkg/name, public/name)

print("Installed preview:")
print("  /bdp-v3.html")
print("No existing application files were replaced.")
