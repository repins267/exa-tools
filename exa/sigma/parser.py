"""Parse Sigma YAML rules into structured dicts.

Uses a minimal recursive-descent YAML parser (no PyYAML dependency) that
handles the specific patterns used in SigmaHQ rules.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any


def _strip_comment(line: str) -> str:
    """Remove trailing comments not inside quotes."""
    in_q = False
    qc = ""
    for i, ch in enumerate(line):
        if ch in ('"', "'") and not in_q:
            in_q = True
            qc = ch
        elif ch == qc and in_q:
            in_q = False
        elif ch == "#" and not in_q:
            return line[:i].rstrip()
    return line


def _parse_scalar(val: str) -> Any:
    """Parse a YAML scalar string into a Python value."""
    v = val.strip()
    if not v or v in ("~", "null"):
        return None
    if v in ("true", "True", "TRUE", "yes", "Yes"):
        return True
    if v in ("false", "False", "FALSE", "no", "No"):
        return False
    if (v.startswith('"') and v.endswith('"')) or (v.startswith("'") and v.endswith("'")):
        return v[1:-1]
    try:
        return int(v)
    except ValueError:
        pass
    return v


def _indent(line: str) -> int:
    return len(line) - len(line.lstrip())


class _Parser:
    """Line-by-line recursive YAML parser for Sigma rules."""

    def __init__(self, text: str) -> None:
        raw_lines = text.split("\n")
        # Pre-process: strip comments, keep track of original indent
        self.lines: list[tuple[int, str]] = []  # (indent, stripped_content)
        for raw in raw_lines:
            cleaned = _strip_comment(raw)
            if cleaned.strip() == "" or cleaned.strip().startswith("#"):
                continue
            self.lines.append((_indent(cleaned), cleaned.strip()))
        self.pos = 0

    def _peek(self) -> tuple[int, str] | None:
        if self.pos < len(self.lines):
            return self.lines[self.pos]
        return None

    def _advance(self) -> tuple[int, str]:
        item = self.lines[self.pos]
        self.pos += 1
        return item

    def parse_document(self) -> dict[str, Any]:
        return self._parse_mapping(0)

    def _parse_mapping(self, min_indent: int) -> dict[str, Any]:
        result: dict[str, Any] = {}
        while True:
            peek = self._peek()
            if peek is None or peek[0] < min_indent:
                break
            ind, line = peek

            # If this is a list item at our level, we're done
            if line.startswith("- ") and ind == min_indent:
                break

            # Must be a key: value line
            colon_pos = self._find_key_colon(line)
            if colon_pos < 0:
                self._advance()
                continue

            key = line[:colon_pos].strip()
            val_str = line[colon_pos + 1:].strip()
            self._advance()

            # Multi-line literal block
            if val_str == "|":
                result[key] = self._parse_literal_block(ind)
                continue

            # Inline value
            if val_str and val_str != "":
                if val_str.startswith("[") and val_str.endswith("]"):
                    result[key] = self._parse_flow_seq(val_str)
                else:
                    result[key] = _parse_scalar(val_str)
                continue

            # No inline value — check what's next
            next_peek = self._peek()
            if next_peek is None or next_peek[0] <= ind:
                result[key] = None
                continue

            child_indent = next_peek[0]
            if next_peek[1].startswith("- "):
                result[key] = self._parse_sequence(child_indent)
            else:
                result[key] = self._parse_mapping(child_indent)

        return result

    def _parse_sequence(self, min_indent: int) -> list[Any]:
        result: list[Any] = []
        while True:
            peek = self._peek()
            if peek is None or peek[0] < min_indent:
                break
            ind, line = peek
            if ind != min_indent or not line.startswith("- "):
                break

            item_content = line[2:].strip()
            self._advance()

            if not item_content:
                # Bare "- " — next lines are children
                next_peek = self._peek()
                if next_peek and next_peek[0] > ind:
                    child = self._parse_mapping(next_peek[0])
                    result.append(child)
                else:
                    result.append(None)
            elif self._find_key_colon(item_content) >= 0:
                # "- key: value" or "- key:" with children
                colon_pos = self._find_key_colon(item_content)
                key = item_content[:colon_pos].strip()
                val_str = item_content[colon_pos + 1:].strip()

                if val_str:
                    item_dict = {key: _parse_scalar(val_str)}
                else:
                    # Check for children
                    next_peek = self._peek()
                    if next_peek and next_peek[0] > ind:
                        child_indent = next_peek[0]
                        if next_peek[1].startswith("- "):
                            item_dict = {key: self._parse_sequence(child_indent)}
                        else:
                            item_dict = {key: self._parse_mapping(child_indent)}
                    else:
                        item_dict = {key: None}

                # Check if more keys follow at same or deeper indent
                while True:
                    next_peek = self._peek()
                    if next_peek is None:
                        break
                    # Continuation keys are at indent > ind (inside the list item)
                    if next_peek[0] <= ind:
                        break
                    if next_peek[1].startswith("- "):
                        break
                    ncolon = self._find_key_colon(next_peek[1])
                    if ncolon >= 0:
                        nk = next_peek[1][:ncolon].strip()
                        nv = next_peek[1][ncolon + 1:].strip()
                        self._advance()
                        if nv:
                            item_dict[nk] = _parse_scalar(nv)
                        else:
                            nnp = self._peek()
                            if nnp and nnp[0] > next_peek[0]:
                                if nnp[1].startswith("- "):
                                    item_dict[nk] = self._parse_sequence(nnp[0])
                                else:
                                    item_dict[nk] = self._parse_mapping(nnp[0])
                            else:
                                item_dict[nk] = None
                    else:
                        break

                result.append(item_dict)
            else:
                result.append(_parse_scalar(item_content))

        return result

    def _parse_literal_block(self, parent_indent: int) -> str:
        """Parse a multi-line literal block (|)."""
        lines: list[str] = []
        peek = self._peek()
        if peek is None:
            return ""
        block_indent = peek[0]
        while True:
            peek = self._peek()
            if peek is None or peek[0] < block_indent:
                break
            self._advance()
            lines.append(peek[1])
        return "\n".join(lines)

    def _parse_flow_seq(self, val: str) -> list[Any]:
        inner = val[1:-1]
        return [_parse_scalar(item) for item in inner.split(",") if item.strip()]

    def _find_key_colon(self, line: str) -> int:
        """Find the colon that separates key from value, handling URLs and quotes."""
        in_q = False
        qc = ""
        for i, ch in enumerate(line):
            if ch in ('"', "'") and not in_q:
                in_q = True
                qc = ch
            elif ch == qc and in_q:
                in_q = False
            elif ch == ":" and not in_q:
                # Must be followed by space, EOL, or nothing (for keys like "key:")
                if i + 1 >= len(line) or line[i + 1] in (" ", "\t"):
                    return i
                # Also match "key:" at end
                if i + 1 == len(line):
                    return i
        return -1


def parse_sigma_yaml(text: str) -> dict[str, Any]:
    """Parse a Sigma YAML document into a dict."""
    parser = _Parser(text)
    return parser.parse_document()


def parse_sigma_rule(path: str | Path) -> dict[str, Any]:
    """Parse a Sigma rule YAML file into a structured dict."""
    p = Path(path)
    text = p.read_text(encoding="utf-8")
    parsed = parse_sigma_yaml(text)

    # Normalize detection: flatten list-of-single-key-dicts into a single dict
    # Sigma uses patterns like:
    #   selection_img:
    #     - Image|endswith: [...]
    #     - OriginalFileName: [...]
    # This means "Image|endswith matches OR OriginalFileName matches"
    detection = parsed.get("detection", {})
    if isinstance(detection, dict):
        for sel_name, sel_val in detection.items():
            if sel_name == "condition":
                continue
            # Normalize scalar values in dicts to lists
            if isinstance(sel_val, dict):
                for fk, fv in sel_val.items():
                    if fv is not None and not isinstance(fv, list):
                        sel_val[fk] = [fv]

    # Ensure tags is a list
    if "tags" in parsed and not isinstance(parsed["tags"], list):
        parsed["tags"] = [parsed["tags"]] if parsed["tags"] else []

    return parsed
