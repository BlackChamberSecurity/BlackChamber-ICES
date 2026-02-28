## 2024-05-24 - Path Traversal in Static File Serving
**Vulnerability:** The `spa_catchall` route in `webui/src/webui/main.py` directly concatenated user input `path` to `STATIC_DIR` to serve files. This allowed directory traversal attacks using paths like `../../../../etc/passwd` because `FileResponse` serves the resolved file on disk.
**Learning:** Even when serving static single-page applications with a catchall route, directly appending user-controlled paths to a base directory using `pathlib` can lead to traversal if the path isn't strictly validated.
**Prevention:** Always `.resolve()` the concatenated path and use `.is_relative_to(base_dir.resolve())` to ensure the final path remains within the intended static directory before serving.
