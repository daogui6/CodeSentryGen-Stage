from __future__ import annotations

import argparse
import hashlib
import json
import re
from collections import Counter
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]

SCHEMA_VERSION = (
    "avcs_trigger_semantic_relation_candidates_v0.1"
)

EXTRACTOR_VERSION = (
    "trigger_semantic_relation_extractor_v0.4"
)

DEFAULT_CORPUS = (
    ROOT
    / "output"
    / "avcs_trigger_candidate_evidence_corpus_v0.json"
)

DEFAULT_OUTPUT = (
    ROOT
    / "output"
    / "avcs_trigger_semantic_relation_candidates_v0.json"
)

GENERIC_SEMANTICS_KIND = (
    "generic_http_semantics_text"
)

FACT_KIND = (
    "security_context_relation_candidate"
)


VULNERABILITY_ID_RE = re.compile(
    r"\b(?:"
    r"CVE-\d{4}-\d+"
    r"|GHSA-[A-Za-z0-9-]+"
    r"|PYSEC-\d{4}-\d+"
    r")\b",
    re.IGNORECASE,
)


CODE_SPAN_RE = re.compile(
    r"`{1,2}(?P<code>[^`\r\n]{1,180})`{1,2}"
)


DOTTED_OR_CALL_RE = re.compile(
    r"""
    (?<![A-Za-z0-9_])
    (?P<symbol>
        [A-Za-z_][A-Za-z0-9_]*
        (?:
            \.
            [A-Za-z_][A-Za-z0-9_]*
        )+
    )
    (?:
        \s*
        \(
        [^()\r\n]{0,140}
        \)
    )?
    """,
    re.VERBOSE,
)


PLAIN_CALL_RE = re.compile(
    r"""
    ^
    (?P<symbol>
        [A-Za-z_][A-Za-z0-9_]*
    )
    \s*
    \(
    [^()\r\n]{0,140}
    \)
    $
    """,
    re.VERBOSE,
)


ASSIGNMENT_ANCHOR_RE = re.compile(
    r"""
    ^
    (?P<name>
        [A-Za-z_][A-Za-z0-9_]*
    )
    \s*=
    """,
    re.VERBOSE,
)


FILTER_ANCHOR_RE = re.compile(
    r"^\|[A-Za-z_][A-Za-z0-9_]*$"
)


DOTTED_SYMBOL_RE = re.compile(
    r"""
    ^
    [A-Za-z_][A-Za-z0-9_]*
    (?:
        \.
        [A-Za-z_][A-Za-z0-9_]*
    )+
    $
    """,
    re.VERBOSE,
)



URL_RE = re.compile(
    r"""
    (?:
        https?://
        |
        www\.
    )
    [^\s<>()\[\]{}"'`]+
    """,
    re.IGNORECASE | re.VERBOSE,
)


EMAIL_RE = re.compile(
    r"""
    \b
    [A-Za-z0-9._%+-]+
    @
    [A-Za-z0-9.-]+
    \.
    [A-Za-z]{2,63}
    \b
    """,
    re.VERBOSE,
)


DOMAIN_LIKE_ANCHOR_RE = re.compile(
    r"""
    ^
    (?:
        [a-z0-9]
        [a-z0-9-]*
        \.
    )+
    (?:
        com
        | org
        | net
        | edu
        | gov
        | mil
        | int
        | io
        | ai
        | dev
        | app
        | co
        | info
        | biz
        | me
        | tech
        | site
        | online
        | cloud
        | xyz
        | cn
        | uk
        | de
        | fr
        | jp
        | ru
        | us
        | ca
        | au
        | ch
        | nl
        | se
        | no
        | fi
        | in
    )
    $
    """,
    re.IGNORECASE | re.VERBOSE,
)


PROSE_ABBREVIATION_RE = re.compile(
    r"""
    \b
    (?:
        e\.g
        |
        i\.e
    )
    \.
    (?=
        \s
        |
        ,
    )
    """,
    re.IGNORECASE | re.VERBOSE,
)


EXPLICIT_AFFECTED_RE = re.compile(
    r"\b(?:"
    r"vulnerab\w*"
    r"|affected"
    r"|subject\s+to"
    r")\b",
    re.IGNORECASE,
)


UNAFFECTED_RE = re.compile(
    r"\b(?:"
    r"unaffected"
    r"|not\s+affected"
    r")\b",
    re.IGNORECASE,
)

SANDBOX_PROTECTION_RE = re.compile(
    r"\b(?:"
    r"does\s+not"
    r"|doesn't"
    r"|do\s+not"
    r"|don't"
    r"|cannot"
    r"|can't"
    r"|will\s+not"
    r"|won't"
    r")"
    r"\s+escape(?:s|d|ing)?"
    r"\s+the\s+sandbox\b",
    re.IGNORECASE,
)


NEGATED_BYPASS_RE = re.compile(
    r"\b(?:"
    r"does\s+not"
    r"|doesn't"
    r"|no\s+longer"
    r")\s+bypass(?:es|ed|ing)?\b",
    re.IGNORECASE,
)


BYPASS_RE = re.compile(
    r"\bbypass(?:es|ed|ing)?\b",
    re.IGNORECASE,
)


DOES_NOT_PREVENT_RE = re.compile(
    r"\b(?:"
    r"does\s+not\s+prevent"
    r"|doesn't\s+prevent"
    r")\b",
    re.IGNORECASE,
)


MITIGATION_RE = re.compile(
    r"\b(?:"
    r"disables?"
    r"|disallow(?:s|ed|ing)?"
    r"|prevents?"
    r")\b",
    re.IGNORECASE,
)


HARDENING_RE = re.compile(
    r"\b(?:"
    r"hardened"
    r"|safe\s+(?:option|default)"
    r")\b",
    re.IGNORECASE,
)


CONTEXT_PATTERNS = {
    "untrusted_input":
        re.compile(
            r"\buntrusted\b",
            re.IGNORECASE,
        ),

    "sandbox":
        re.compile(
            r"\bsandbox\w*\b",
            re.IGNORECASE,
        ),

    "oracle":
        re.compile(
            r"\boracle\b",
            re.IGNORECASE,
        ),

    "default_configuration":
        re.compile(
            r"\bdefault\s+configuration\b",
            re.IGNORECASE,
        ),
}


SECURITY_EFFECT_PATTERNS = {
    "arbitrary_code_execution":
        re.compile(
            r"\b(?:"
            r"arbitrary\s+(?:python\s+)?code"
            r"|code\s+execution"
            r")\b",
            re.IGNORECASE,
        ),

    "sql_injection":
        re.compile(
            r"\bsql\s+injection\b",
            re.IGNORECASE,
        ),

    "denial_of_service":
        re.compile(
            r"\b(?:"
            r"denial[- ]of[- ]service"
            r"|DoS"
            r")\b",
            re.IGNORECASE,
        ),

    "local_file_disclosure":
        re.compile(
            r"\b(?:"
            r"local[- ]file"
            r"|local\s+file\s+disclosure"
            r"|read\s+local\s+files?"
            r")\b",
            re.IGNORECASE,
        ),

    "xxe":
        re.compile(
            r"\b(?:"
            r"XXE"
            r"|external\s+entit(?:y|ies)"
            r")\b",
            re.IGNORECASE,
        ),

    "sandbox_escape":
        re.compile(
            r"\b(?:"
            r"escape(?:s|d|ing)?\s+the\s+sandbox"
            r"|bypass(?:es|ed|ing)?\s+the\s+sandbox"
            r")\b",
            re.IGNORECASE,
        ),
}


def clean_text(
    value: Any,
) -> str:
    return str(
        value
        if value is not None
        else ""
    ).strip()


def load_json(
    path: Path,
) -> dict[str, Any]:
    data = json.loads(
        path.read_text(
            encoding="utf-8"
        )
    )

    if not isinstance(
        data,
        dict,
    ):
        raise ValueError(
            f"Expected JSON object: {path}"
        )

    return data


def write_json(
    path: Path,
    data: dict[str, Any],
) -> None:
    path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    path.write_text(
        json.dumps(
            data,
            ensure_ascii=False,
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )


def stable_json(
    value: Any,
) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(
            ",",
            ":",
        ),
    )


def make_fact_id(
    *,
    source_key: str,
    evidence_unit_id: str,
    structured_value: dict[str, Any],
) -> str:
    payload = stable_json(
        {
            "source_key":
                source_key,

            "evidence_unit_id":
                evidence_unit_id,

            "fact_kind":
                FACT_KIND,

            "structured_value":
                structured_value,

            "extraction_method":
                (
                    "target_bound_"
                    "security_cue_anchor_"
                    "cooccurrence_v0"
                ),
        }
    )

    digest = hashlib.sha256(
        payload.encode(
            "utf-8"
        )
    ).hexdigest()[:20]

    return (
        "triggerrel_"
        + digest
    )


def normalized_ids(
    values: Any,
) -> list[str]:
    if not isinstance(
        values,
        list,
    ):
        return []

    result = []

    seen = set()

    for value in values:
        text = clean_text(
            value
        )

        if not text:
            continue

        key = text.lower()

        if key in seen:
            continue

        seen.add(
            key
        )

        result.append(
            text
        )

    return result


def sentence_segments(
    text: str,
) -> list[str]:
    raw = re.split(
        r"(?<=[.!?])\s+|\n+",
        text,
    )

    result = []

    for row in raw:
        normalized = " ".join(
            row.split()
        )

        if len(
            normalized
        ) < 20:
            continue

        result.append(
            normalized
        )

    return result


def target_bound_sections(
    text: str,
    vulnerability_ids: list[str],
) -> list[
    tuple[
        str,
        list[str],
        str,
    ]
]:
    target_set = {
        value.lower()
        for value
        in vulnerability_ids
    }

    if not target_set:
        return []

    matches = list(
        VULNERABILITY_ID_RE.finditer(
            text
        )
    )

    target_matches = [
        match
        for match in matches
        if match.group(0).lower()
        in target_set
    ]

    if not target_matches:
        return []

    sections = []

    seen_spans = set()

    for target_match in target_matches:
        start = target_match.start()

        line_start = text.rfind(
            "\n",
            0,
            start,
        )

        if line_start >= 0:
            start = (
                line_start
                + 1
            )

        end = len(
            text
        )

        for later in matches:
            if (
                later.start()
                <= target_match.start()
            ):
                continue

            later_id = (
                later.group(0)
                .lower()
            )

            if (
                later_id
                in target_set
            ):
                continue

            end = later.start()

            break

        span = (
            start,
            end,
        )

        if span in seen_spans:
            continue

        seen_spans.add(
            span
        )

        section = (
            text[
                start:end
            ].strip()
        )

        if not section:
            continue

        bound_ids = sorted(
            {
                match.group(0)
                for match
                in VULNERABILITY_ID_RE.finditer(
                    section
                )
                if (
                    match.group(0).lower()
                    in target_set
                )
            }
        )

        sections.append(
            (
                section,
                bound_ids,
                "generic_target_bound_section",
            )
        )

    return sections


def source_bound_sections(
    text: str,
    vulnerability_ids: list[str],
) -> list[
    tuple[
        str,
        list[str],
        str,
    ]
]:
    return [
        (
            text,
            vulnerability_ids,
            "source_identity_bound",
        )
    ]



def mask_non_program_text(
    text: str,
) -> str:
    masked = EMAIL_RE.sub(
        " ",
        text,
    )

    masked = URL_RE.sub(
        " ",
        masked,
    )

    # Natural-language abbreviations such as "e.g."
    # and "i.e." resemble dotted program symbols to
    # the generic anchor scanner. Mask the prose forms
    # before dotted/call extraction without globally
    # blacklisting legitimate attribute expressions.
    masked = PROSE_ABBREVIATION_RE.sub(
        " ",
        masked,
    )

    return masked


def looks_like_domain_anchor(
    text: str,
) -> bool:
    return (
        DOMAIN_LIKE_ANCHOR_RE.fullmatch(
            text
        )
        is not None
    )



def canonical_anchor(
    raw: str,
) -> str:
    text = " ".join(
        clean_text(
            raw
        ).split()
    )

    if not text:
        return ""

    if len(
        text
    ) > 140:
        return ""

    if not re.search(
            r"[A-Za-z0-9]",
            text,
    ):
        return ""

    if looks_like_domain_anchor(
        text
    ):
        return ""


    if FILTER_ANCHOR_RE.fullmatch(
        text
    ):
        return text

    assignment = (
        ASSIGNMENT_ANCHOR_RE.match(
            text
        )
    )

    if assignment is not None:
        return assignment.group(
            "name"
        )

    plain_call = (
        PLAIN_CALL_RE.fullmatch(
            text
        )
    )

    if plain_call is not None:
        return plain_call.group(
            "symbol"
        )

    call_prefix = re.match(
        r"""
        ^
        (?P<symbol>
            [A-Za-z_][A-Za-z0-9_]*
            (?:
                \.
                [A-Za-z_][A-Za-z0-9_]*
            )*
        )
        \s*
        \(
        """,
        text,
        re.VERBOSE,
    )

    if call_prefix is not None:
        return call_prefix.group(
            "symbol"
        )

    if DOTTED_SYMBOL_RE.fullmatch(
        text
    ):
        return text

    if re.fullmatch(
        r"[A-Za-z_][A-Za-z0-9_]*",
        text,
    ):
        if (
            "_"
            in text
            or any(
                char.isupper()
                for char in text
            )
        ):
            return text

    return ""


def anchors_from_segment(
    segment: str,
) -> list[str]:
    values = []

    scan_segment = (
        mask_non_program_text(
            segment
        )
    )

    for match in (
        DOTTED_OR_CALL_RE.finditer(
            scan_segment
        )
    ):
        anchor = canonical_anchor(
            match.group(0)
        )

        if (
            anchor
            and anchor
            not in values
        ):
            values.append(
                anchor
            )

    for match in (
        CODE_SPAN_RE.finditer(
            scan_segment
        )
    ):
        anchor = canonical_anchor(
            match.group(
                "code"
            )
        )

        if (
            anchor
            and anchor
            not in values
        ):
            values.append(
                anchor
            )

    values.sort(
        key=lambda value: (
            "." not in value,
            not value.startswith(
                "|"
            ),
            -len(
                value
            ),
            value.lower(),
        )
    )

    return values[:8]


def security_effects(
    segment: str,
) -> list[str]:
    return sorted(
        [
            name
            for name, pattern
            in SECURITY_EFFECT_PATTERNS.items()
            if pattern.search(
                segment
            )
        ]
    )


def context_tags(
    segment: str,
) -> list[str]:
    return sorted(
        [
            name
            for name, pattern
            in CONTEXT_PATTERNS.items()
            if pattern.search(
                segment
            )
        ]
    )


def relation_class(
    segment: str,
    effects: list[str],
) -> tuple[
    str,
    list[str],
]:
    cues = []

    if UNAFFECTED_RE.search(
            segment
    ):
        return (
            "unaffected_context",
            [
                "unaffected"
            ],
        )

    if SANDBOX_PROTECTION_RE.search(
            segment
    ):
        return (
            "mitigation_context",
            [
                "prevents_sandbox_escape"
            ],
        )

    if NEGATED_BYPASS_RE.search(
        segment
    ):
        return (
            "hardening_context",
            [
                "negated_bypass"
            ],
        )

    if DOES_NOT_PREVENT_RE.search(
        segment
    ):
        return (
            "mitigation_failure_context",
            [
                "does_not_prevent"
            ],
        )

    if HARDENING_RE.search(
        segment
    ):
        return (
            "hardening_context",
            [
                "hardened_or_safe"
            ],
        )

    if MITIGATION_RE.search(
        segment
    ):
        return (
            "mitigation_context",
            [
                "mitigation"
            ],
        )

    if BYPASS_RE.search(
        segment
    ):
        return (
            "bypass_context",
            [
                "bypass"
            ],
        )

    if EXPLICIT_AFFECTED_RE.search(
        segment
    ):
        return (
            "affected_context",
            [
                "affected"
            ],
        )

    if effects:
        return (
            "security_effect_context",
            [
                "explicit_security_effect"
            ],
        )

    return (
        "",
        cues,
    )


def contains_non_target_vulnerability(
    segment: str,
    vulnerability_ids: list[str],
) -> bool:
    target_set = {
        value.lower()
        for value
        in vulnerability_ids
    }

    for match in (
        VULNERABILITY_ID_RE.finditer(
            segment
        )
    ):
        if (
            match.group(0).lower()
            not in target_set
        ):
            return True

    return False


def make_excerpt(
    segment: str,
    max_chars: int = 500,
) -> str:
    text = " ".join(
        segment.split()
    )

    if len(
        text
    ) <= max_chars:
        return text

    return (
        text[
            : max_chars - 3
        ]
        + "..."
    )


def extract(
    corpus: dict[str, Any],
) -> dict[str, Any]:
    facts = []

    fact_ids = set()

    source_with_candidate = set()

    unit_with_candidate = set()

    relation_counter = Counter()

    distribution_counter = Counter()

    effect_counter = Counter()

    binding_counter = Counter()

    scanned_units = 0

    scanned_segments = 0

    generic_target_sections = 0

    skipped_cross_vulnerability = 0

    issues = []

    entries = corpus.get(
        "entries",
        [],
    )

    if not isinstance(
        entries,
        list,
    ):
        raise ValueError(
            "Corpus field 'entries' must be a list."
        )

    for entry in entries:
        if not isinstance(
            entry,
            dict,
        ):
            continue

        if (
            clean_text(
                entry.get(
                    "corpus_status"
                )
            )
            != "resolved"
        ):
            continue

        vulnerability_ids = (
            normalized_ids(
                entry.get(
                    "vulnerability_ids"
                )
            )
        )

        units = entry.get(
            "evidence_units",
            [],
        )

        if not isinstance(
            units,
            list,
        ):
            continue

        for unit in units:
            if not isinstance(
                unit,
                dict,
            ):
                continue

            text = unit.get(
                "text"
            )

            if not isinstance(
                text,
                str,
            ):
                continue

            scanned_units += 1

            unit_kind = clean_text(
                unit.get(
                    "unit_kind"
                )
            )

            if (
                unit_kind
                == GENERIC_SEMANTICS_KIND
            ):
                sections = (
                    target_bound_sections(
                        text,
                        vulnerability_ids,
                    )
                )

                generic_target_sections += (
                    len(
                        sections
                    )
                )

            else:
                sections = (
                    source_bound_sections(
                        text,
                        vulnerability_ids,
                    )
                )

            for (
                section,
                bound_ids,
                binding_mode,
            ) in sections:
                binding_counter[
                    binding_mode
                ] += 1

                for segment in (
                    sentence_segments(
                        section
                    )
                ):
                    scanned_segments += 1

                    if (
                        contains_non_target_vulnerability(
                            segment,
                            vulnerability_ids,
                        )
                    ):
                        skipped_cross_vulnerability += 1

                        continue

                    effects = (
                        security_effects(
                            segment
                        )
                    )

                    (
                        relation,
                        cues,
                    ) = relation_class(
                        segment,
                        effects,
                    )

                    if not relation:
                        continue

                    anchors = (
                        anchors_from_segment(
                            segment
                        )
                    )

                    if not anchors:
                        continue

                    contexts = (
                        context_tags(
                            segment
                        )
                    )

                    source_key = clean_text(
                        entry.get(
                            "source_key"
                        )
                    )

                    evidence_unit_id = clean_text(
                        unit.get(
                            "unit_id"
                        )
                    )

                    for anchor in anchors:
                        effect_values = (
                            effects
                            if effects
                            else [
                                None
                            ]
                        )

                        for effect in effect_values:
                            structured_value = {
                                "relation_class":
                                    relation,

                                "anchor":
                                    anchor,

                                "security_effect":
                                    effect,
                            }

                            fact_id = make_fact_id(
                                source_key=(
                                    source_key
                                ),
                                evidence_unit_id=(
                                    evidence_unit_id
                                ),
                                structured_value=(
                                    structured_value
                                ),
                            )

                            if (
                                fact_id
                                in fact_ids
                            ):
                                continue

                            fact_ids.add(
                                fact_id
                            )

                            facts.append(
                                {
                                    "fact_id":
                                        fact_id,

                                    "fact_kind":
                                        FACT_KIND,

                                    "candidate_status":
                                        "candidate",

                                    "review_required":
                                        True,

                                    "distribution":
                                        entry.get(
                                            "distribution"
                                        ),

                                    "vulnerability_ids":
                                        vulnerability_ids,

                                    "structured_value":
                                        structured_value,

                                    "source_key":
                                        source_key,

                                    "source_id":
                                        entry.get(
                                            "source_id"
                                        ),

                                    "source_type":
                                        entry.get(
                                            "source_type"
                                        ),

                                    "evidence_unit_id":
                                        evidence_unit_id,

                                    "unit_kind":
                                        unit_kind,

                                    "text_sha256":
                                        unit.get(
                                            "text_sha256"
                                        ),

                                    "extractor":
                                        EXTRACTOR_VERSION,

                                    "extraction_method":
                                        (
                                            "target_bound_"
                                            "security_cue_anchor_"
                                            "cooccurrence_v0"
                                        ),

                                    "confidence_level":
                                        "moderate",

                                    "confidence_basis":
                                        (
                                            "A code/configuration "
                                            "anchor and an explicit "
                                            "security relation cue "
                                            "co-occur in the same "
                                            "target-bound evidence "
                                            "segment. This is only "
                                            "a semantic relation "
                                            "candidate, not Trigger "
                                            "Evidence truth."
                                        ),

                                    "semantic_cues":
                                        cues,

                                    "context_tags":
                                        contexts,

                                    "target_binding_mode":
                                        binding_mode,

                                    "bound_target_ids":
                                        bound_ids,

                                    "evidence_excerpt":
                                        make_excerpt(
                                            segment
                                        ),

                                    "evidence_locator":
                                        unit.get(
                                            "locator",
                                            {},
                                        ),
                                }
                            )

                            source_with_candidate.add(
                                source_key
                            )

                            unit_with_candidate.add(
                                evidence_unit_id
                            )

                            relation_counter[
                                relation
                            ] += 1

                            distribution_counter[
                                clean_text(
                                    entry.get(
                                        "distribution"
                                    )
                                ).lower()
                            ] += 1

                            if effect:
                                effect_counter[
                                    effect
                                ] += 1

    facts.sort(
        key=lambda row: (
            clean_text(
                row.get(
                    "distribution"
                )
            ).lower(),
            clean_text(
                row.get(
                    "source_key"
                )
            ),
            clean_text(
                row.get(
                    "evidence_unit_id"
                )
            ),
            stable_json(
                row.get(
                    "structured_value"
                )
            ),
            clean_text(
                row.get(
                    "fact_id"
                )
            ),
        )
    )

    return {
        "schema_version":
            SCHEMA_VERSION,

        "extractor_version":
            EXTRACTOR_VERSION,

        "status":
            "resolved",

        "source_mode":
            (
                "deterministic_target_bound_"
                "semantic_relation_candidate_"
                "extraction"
            ),

        "semantic_boundary": {
            "consumes_candidate_evidence_corpus":
                True,

            "consumes_trigger_raw_ground_truth":
                False,

            "uses_llm_semantic_inference":
                False,

            "creates_semantic_relation_candidates":
                True,

            "creates_resolved_trigger_rules":
                False,

            "candidate_status_is_ground_truth":
                False,

            "all_candidates_require_review":
                True,

            "generic_web_requires_target_section_binding":
                True,

            "cross_vulnerability_generic_segments_are_skipped":
                True,

            "relation_signature_excludes_raw_sentence_text":
                True,

            "intended_next_stage":
                (
                    "conservative_cross_source_"
                    "candidate_validation"
                ),
        },

        "summary": {
            "corpus_entry_count":
                len(
                    [
                        row
                        for row in entries
                        if isinstance(
                            row,
                            dict,
                        )
                    ]
                ),

            "evidence_units_scanned":
                scanned_units,

            "segments_scanned":
                scanned_segments,

            "generic_target_bound_section_count":
                generic_target_sections,

            "cross_vulnerability_segment_skip_count":
                skipped_cross_vulnerability,

            "semantic_relation_candidate_count":
                len(
                    facts
                ),

            "units_with_candidates":
                len(
                    {
                        value
                        for value
                        in unit_with_candidate
                        if value
                    }
                ),

            "sources_with_candidates":
                len(
                    {
                        value
                        for value
                        in source_with_candidate
                        if value
                    }
                ),

            "distribution_counts":
                dict(
                    sorted(
                        distribution_counter.items()
                    )
                ),

            "relation_class_counts":
                dict(
                    sorted(
                        relation_counter.items()
                    )
                ),

            "security_effect_counts":
                dict(
                    sorted(
                        effect_counter.items()
                    )
                ),

            "target_binding_mode_counts":
                dict(
                    sorted(
                        binding_counter.items()
                    )
                ),

            "issue_count":
                len(
                    issues
                ),
        },

        "issues":
            issues,

        "facts":
            facts,
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Extract deterministic, target-bound "
            "security semantic relation candidates "
            "from Trigger Candidate Evidence Corpus."
        )
    )

    parser.add_argument(
        "--corpus",
        type=Path,
        default=DEFAULT_CORPUS,
    )

    parser.add_argument(
        "--out",
        type=Path,
        default=DEFAULT_OUTPUT,
    )

    args = parser.parse_args()

    corpus = load_json(
        args.corpus
    )

    result = extract(
        corpus
    )

    write_json(
        args.out,
        result,
    )

    summary = result.get(
        "summary",
        {},
    )

    print(
        "=" * 60
    )

    print(
        "TRIGGER SEMANTIC RELATION CANDIDATE SUMMARY"
    )

    print(
        "=" * 60
    )

    print(
        "[OK] schema:",
        result.get(
            "schema_version"
        ),
    )

    print(
        "[OK] status:",
        result.get(
            "status"
        ),
    )

    print(
        "[OK] evidence units scanned:",
        summary.get(
            "evidence_units_scanned",
            0,
        ),
    )

    print(
        "[OK] segments scanned:",
        summary.get(
            "segments_scanned",
            0,
        ),
    )

    print(
        "[OK] generic target sections:",
        summary.get(
            "generic_target_bound_section_count",
            0,
        ),
    )

    print(
        "[OK] cross-vulnerability segments skipped:",
        summary.get(
            "cross_vulnerability_segment_skip_count",
            0,
        ),
    )

    print(
        "[OK] relation candidates:",
        summary.get(
            "semantic_relation_candidate_count",
            0,
        ),
    )

    print(
        "[OK] sources with candidates:",
        summary.get(
            "sources_with_candidates",
            0,
        ),
    )

    print(
        "[OK] relation classes:",
        json.dumps(
            summary.get(
                "relation_class_counts",
                {},
            ),
            ensure_ascii=False,
            sort_keys=True,
        ),
    )

    print(
        "[OK] security effects:",
        json.dumps(
            summary.get(
                "security_effect_counts",
                {},
            ),
            ensure_ascii=False,
            sort_keys=True,
        ),
    )

    print(
        "[OK] saved:",
        args.out.resolve(),
    )


if __name__ == "__main__":
    main()