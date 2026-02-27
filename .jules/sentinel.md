# Sentinel Journal

## 2026-06-25 - Path Traversal in SPA Static File Serving
**Vulnerability:** The SPA catch-all route `/{path:path}` in `webui/src/webui/main.py` blindly joined the user-provided `path` with `STATIC_DIR` without validation.
**Learning:** `pathlib.Path` concatenation (`/`) does not automatically resolve `..` or prevent escaping the base directory. Simply checking `.is_file()` is insufficient because the traversal path (e.g., `../../etc/passwd`) can indeed be a valid file.
**Prevention:** Always use `.resolve()` to canonicalize the path and `.is_relative_to(base_dir)` to enforce that the target file resides within the intended directory subtree.
