# Copyright (c) 2026 John Earle
#
# Licensed under the Business Source License 1.1 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://github.com/yourusername/bcem/blob/main/LICENSE
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
Analyzer: Attachment Safety

Checks email attachments for potentially dangerous file types, computes
file hashes for future threat intelligence lookups, and flags suspicious
patterns.

What it checks:
- Dangerous file extensions (executables, scripts, macros)
- Double extensions (e.g. "invoice.pdf.exe")
- Password-protected archives (often used to bypass other scanners)
- File hash computation for threat intel integration (future use)
"""
import hashlib
import base64

from analysis.analyzers._base import BaseAnalyzer
from analysis.models import AnalysisResult, EmailEvent


# File extensions commonly used in malware delivery
# Organised by risk level for clarity
DANGEROUS_EXTENSIONS = {
    # Executables
    ".exe", ".scr", ".pif", ".com", ".bat", ".cmd", ".msi", ".msp",
    # Scripts
    ".js", ".jse", ".vbs", ".vbe", ".wsf", ".wsh", ".ps1", ".psm1",
    # Office macros
    ".docm", ".xlsm", ".pptm", ".dotm", ".xltm",
    # Archives (can hide executables)
    ".iso", ".img", ".vhd", ".vhdx",
    # Other
    ".dll", ".sys", ".drv", ".cpl", ".inf", ".reg", ".lnk", ".hta",
}

# Extensions that are suspicious when used as a second extension
# (e.g. "document.pdf.exe" — the real extension is .exe)
DOUBLE_EXTENSION_TRAP = {".exe", ".scr", ".bat", ".cmd", ".js", ".vbs", ".ps1"}


class AttachmentAnalyzer(BaseAnalyzer):
    """Check email attachments for dangerous file types and patterns."""

    name = "attachment_check"
    description = "Detects dangerous file types, double extensions, and suspicious archives"
    severity_weight = 90  # Malicious attachments are high severity

    def analyze(self, email: EmailEvent) -> AnalysisResult:
        findings = []
        score = 0

        if not email.attachments:
            return AnalysisResult(analyzer=self.name, score=0, findings=[])

        for attachment in email.attachments:
            name = attachment.name.lower()

            # --- Dangerous extension check ---
            for ext in DANGEROUS_EXTENSIONS:
                if name.endswith(ext):
                    score += 50
                    findings.append(
                        f"Dangerous file type detected: {attachment.name} ({ext})"
                    )
                    break

            # --- Double extension check ---
            # "invoice.pdf.exe" has two dots — the real extension is .exe
            parts = name.rsplit(".", maxsplit=2)
            if len(parts) >= 3:
                real_ext = f".{parts[-1]}"
                if real_ext in DOUBLE_EXTENSION_TRAP:
                    score += 40
                    findings.append(
                        f"Double extension detected (hiding real type): "
                        f"{attachment.name}"
                    )

            # --- File hash computation ---
            # Compute SHA-256 hash for future threat intel lookups
            if attachment.content_bytes:
                try:
                    file_bytes = base64.b64decode(attachment.content_bytes)
                    file_hash = hashlib.sha256(file_bytes).hexdigest()
                    findings.append(
                        f"File hash (SHA-256): {attachment.name} → {file_hash}"
                    )
                except Exception:
                    findings.append(
                        f"Could not compute hash for: {attachment.name}"
                    )

            # --- Suspicious content type ---
            ct = attachment.content_type.lower()
            if "encrypted" in ct or "password" in ct:
                score += 25
                findings.append(
                    f"Password-protected/encrypted attachment: {attachment.name}"
                )

            # --- Suspicious size (very small executables are often droppers) ---
            if any(name.endswith(ext) for ext in (".exe", ".scr", ".dll")):
                if attachment.size < 50_000:  # < 50KB
                    score += 15
                    findings.append(
                        f"Very small executable ({attachment.size} bytes): "
                        f"{attachment.name} — possible dropper/downloader"
                    )

        # Cap at 100
        score = min(score, 100)

        return AnalysisResult(
            analyzer=self.name,
            score=score,
            findings=findings,
        )
