"""Modern adapter for the public SCALE code-transformation pipeline.

The public SCALE repository generates line comments with an LLM and then uses
Tree-Sitter plus symbolic rules. Its released scripts are batch-oriented and
depend on a separately downloaded parser toolkit. This module preserves that
two-stage design behind a safe library interface:

1. generate concise line semantics with the configured LLM;
2. parse C/C++ with Tree-Sitter and serialize control-flow-aware nodes.

It is not claimed to be byte-for-byte identical to the authors' private MulVul
preprocessing or to the public SCALE batch outputs.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from openai import OpenAI
from tree_sitter import Language, Parser
import tree_sitter_c
import tree_sitter_cpp

from .settings import LLMSettings


@dataclass(frozen=True)
class LineComment:
    line: int
    comment: str


class OpenAILineCommenter:
    def __init__(self, client: OpenAI, model: str) -> None:
        self.client = client
        self.model = model

    @classmethod
    def from_settings(cls, settings: LLMSettings) -> "OpenAILineCommenter":
        return cls(
            OpenAI(api_key=settings.api_key, base_url=settings.base_url),
            settings.router_model,
        )

    def comment(self, code: str) -> tuple[LineComment, ...]:
        response = self.client.chat.completions.create(
            model=self.model,
            messages=[
                {
                    "role": "developer",
                    "content": (
                        "You are an expert C/C++ programmer. Produce concise, "
                        "literal semantic comments for relevant source lines. "
                        "Do not speculate about vulnerabilities. Return JSON only."
                    ),
                },
                {
                    "role": "user",
                    "content": (
                        "For each non-empty executable or control-flow line, return "
                        "its 1-based line number and a concise semantic comment. "
                        "Format: {\"line_comments\":[{\"line\":1,"
                        "\"comment\":\"...\"}]}.\n\nCode:\n```\n"
                        f"{code}\n```"
                    ),
                },
            ],
            response_format={"type": "json_object"},
            temperature=0,
        )
        content = response.choices[0].message.content
        if not content:
            raise RuntimeError("comment generator returned an empty response")
        payload = json.loads(content)
        raw_comments = payload.get("line_comments")
        if not isinstance(raw_comments, list):
            raise ValueError("comment generator response lacks line_comments")
        line_count = len(code.splitlines())
        comments: list[LineComment] = []
        for item in raw_comments:
            line = int(item["line"])
            comment = str(item["comment"]).strip().replace("\n", " ")
            if 1 <= line <= line_count and comment:
                comments.append(LineComment(line, comment))
        return tuple(comments)


class ScaleTransformer:
    """Create an SCT-like, control-flow-aware textual representation."""

    IMPORTANT_NODE_TYPES = frozenset(
        {
            "function_definition",
            "declaration",
            "expression_statement",
            "if_statement",
            "for_statement",
            "while_statement",
            "do_statement",
            "switch_statement",
            "case_statement",
            "return_statement",
            "break_statement",
            "continue_statement",
            "goto_statement",
            "call_expression",
            "assignment_expression",
        }
    )

    def __init__(
        self,
        commenter: OpenAILineCommenter | None = None,
    ) -> None:
        self.commenter = commenter

    def transform(self, code: str, language: str = "c") -> str:
        parser_name = {"c++": "cpp", "cpp": "cpp", "c": "c"}.get(language)
        if parser_name is None:
            raise ValueError("ScaleTransformer currently supports C and C++")
        comments = self.commenter.comment(code) if self.commenter else ()
        comments_by_line = {item.line: item.comment for item in comments}
        source = code.encode("utf-8")
        candidates = []
        for candidate_name in (parser_name, "cpp" if parser_name == "c" else "c"):
            grammar = (
                tree_sitter_c.language()
                if candidate_name == "c"
                else tree_sitter_cpp.language()
            )
            tree = Parser(Language(grammar)).parse(source)
            candidates.append((self._error_count(tree.root_node), candidate_name, tree))
        parse_errors, parser_name, tree = min(candidates, key=lambda item: item[0])

        rows = [f"[SCALE language={parser_name}] parse_errors={parse_errors}"]
        self._serialize(tree.root_node, source, comments_by_line, rows, depth=0)
        return "\n".join(rows)

    def _error_count(self, node: Any) -> int:
        return int(node.is_error or node.is_missing) + sum(
            self._error_count(child) for child in node.children
        )

    def _serialize(
        self,
        node: Any,
        source: bytes,
        comments: dict[int, str],
        rows: list[str],
        depth: int,
    ) -> None:
        include = node.type in self.IMPORTANT_NODE_TYPES
        next_depth = depth
        if include:
            start_line = node.start_point[0] + 1
            raw = source[node.start_byte : node.end_byte].decode("utf-8", errors="replace")
            snippet = " ".join(raw.strip().split())
            if len(snippet) > 240:
                snippet = snippet[:237] + "..."
            semantic = comments.get(start_line)
            prefix = "  " * depth
            row = f"{prefix}- {node.type} L{start_line}: {snippet}"
            if semantic:
                row += f" | semantic: {semantic}"
            rows.append(row)
            next_depth = depth + 1
        for child in node.children:
            self._serialize(child, source, comments, rows, next_depth)
