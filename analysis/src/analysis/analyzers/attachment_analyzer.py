# Copyright (c) 2026 John Earle
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
Analyzer: Attachment Safety

Observations produced:
    attachment_count       (numeric)  — total attachments
    dangerous_extensions   (text)     — comma-separated dangerous exts found
    double_extensions      (text)     — comma-separated filenames with double exts
    encrypted_attachments  (numeric)  — count of password-protected attachments
    small_executables      (numeric)  — count of suspiciously small executables
    file_hashes            (text)     — comma-separated SHA-256 hashes
"""
import hashlib
import base64

from analysis.analyzers._base import BaseAnalyzer
from analysis.models import AnalysisResult, EmailEvent, Observation


DANGEROUS_EXTENSIONS = {
    ".exe", ".scr", ".pif", ".com", ".bat", ".cmd", ".msi", ".msp",
    ".js", ".jse", ".vbs", ".vbe", ".wsf", ".wsh", ".ps1", ".psm1",
    ".docm", ".xlsm", ".pptm", ".dotm", ".xltm",
    ".iso", ".img", ".vhd", ".vhdx",
    ".dll", ".sys", ".drv", ".cpl", ".inf", ".reg", ".lnk", ".hta",
}

DOUBLE_EXTENSION_TRAP = {".exe", ".scr", ".bat", ".cmd", ".js", ".vbs", ".ps1"}


class AttachmentAnalyzer(BaseAnalyzer):
    """Check email attachments for dangerous file types and patterns."""

    name = "attachment_check"
    description = "Detects dangerous file types, double extensions, and suspicious archives"
    order = 30  # simple filename check

    def analyze(self, email: EmailEvent) -> AnalysisResult:
        observations = [
            Observation(key="attachment_count", value=len(email.attachments), type="numeric"),
        ]

        if not email.attachments:
            return AnalysisResult(analyzer=self.name, observations=observations)

        dangerous_exts = []
        double_exts = []
        encrypted_count = 0
        small_exes = 0
        file_hashes = []

        for attachment in email.attachments:
            name = attachment.name.lower()

            # Dangerous extension
            for ext in DANGEROUS_EXTENSIONS:
                if name.endswith(ext):
                    dangerous_exts.append(ext)
                    break

            # Double extension
            parts = name.rsplit(".", maxsplit=2)
            if len(parts) >= 3:
                real_ext = f".{parts[-1]}"
                if real_ext in DOUBLE_EXTENSION_TRAP:
                    double_exts.append(attachment.name)

            # File hash
            if attachment.content_bytes:
                try:
                    file_bytes = base64.b64decode(attachment.content_bytes)
                    file_hash = hashlib.sha256(file_bytes).hexdigest()
                    file_hashes.append(file_hash)
                except Exception:
                    pass

            # Encrypted
            ct = attachment.content_type.lower()
            if "encrypted" in ct or "password" in ct:
                encrypted_count += 1

            # Small executable
            if any(name.endswith(ext) for ext in (".exe", ".scr", ".dll")):
                if attachment.size < 50_000:
                    small_exes += 1

        if dangerous_exts:
            observations.append(
                Observation(key="dangerous_extensions", value=",".join(dangerous_exts), type="text")
            )
        if double_exts:
            observations.append(
                Observation(key="double_extensions", value=",".join(double_exts), type="text")
            )
        if encrypted_count:
            observations.append(
                Observation(key="encrypted_attachments", value=encrypted_count, type="numeric")
            )
        if small_exes:
            observations.append(
                Observation(key="small_executables", value=small_exes, type="numeric")
            )
        if file_hashes:
            observations.append(
                Observation(key="file_hashes", value=",".join(file_hashes), type="text")
            )

        return AnalysisResult(analyzer=self.name, observations=observations)
