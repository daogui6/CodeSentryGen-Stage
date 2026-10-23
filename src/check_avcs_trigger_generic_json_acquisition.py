from __future__ import annotations

import json

from acquire_trigger_generic_http_evidence import (
    ACQUISITION_VERSION,
    CACHE_SCHEMA_VERSION,
    SCHEMA_VERSION,
    build_csaf_target_slice,
    extract_json_evidence_text,
    extract_json_text,
    is_json_content_type,
    is_supported_content_type,
)


def main() -> None:

    assert (
        SCHEMA_VERSION
        == "avcs_trigger_generic_http_acquisition_v0.3"
    )

    assert (
        CACHE_SCHEMA_VERSION
        == "avcs_trigger_generic_http_cache_v0.3"
    )

    assert (
        ACQUISITION_VERSION
        == "trigger_generic_http_acquisition_v0.3"
    )


    # --------------------------------------------------
    # Content-Type admission
    # --------------------------------------------------

    assert is_supported_content_type(
        "text/html"
    )

    assert is_supported_content_type(
        "text/plain"
    )

    assert is_json_content_type(
        "application/json"
    )

    assert is_supported_content_type(
        "application/json"
    )

    assert is_json_content_type(
        "application/vnd.oasis.csaf+json"
    )

    assert is_supported_content_type(
        "application/vnd.oasis.csaf+json"
    )

    assert not is_supported_content_type(
        "application/pdf"
    )


    # --------------------------------------------------
    # Generic JSON remains canonical.
    # --------------------------------------------------

    generic = {
        "message":
            "Synthetic generic JSON",

        "cve":
            "CVE-2026-0001",
    }

    generic_body = json.dumps(
        generic
    ).encode(
        "utf-8"
    )

    (
        generic_text,
        generic_mode,
        generic_meta,
    ) = extract_json_evidence_text(
        generic_body,
        encoding="utf-8",
        vulnerability_ids=[
            "CVE-2026-0001"
        ],
    )

    assert (
        generic_mode
        == "json_canonical_text"
    )

    assert not generic_meta[
        "csaf_like"
    ]

    assert (
        json.loads(
            generic_text
        )
        == generic
    )


    # --------------------------------------------------
    # Synthetic CSAF/VEX target slicing.
    # --------------------------------------------------

    csaf = {
        "document": {
            "category":
                "csaf_vex",

            "title":
                "Synthetic VEX",

            "tracking": {
                "id":
                    "CVE-2026-0001",

                "status":
                    "final",

                "version":
                    "1",
            },

            "references": [
                {
                    "url":
                        (
                            "https://example.invalid/"
                            "?id=999999"
                        ),
                }
            ],
        },

        "product_tree": {
            "branches": [
                {
                    "name":
                        "Huge unrelated product data",

                    "product":
                        {
                            "product_id":
                                "id=777777",
                        },
                }
            ],
        },

        "vulnerabilities": [
            {
                "cve":
                    "CVE-2026-0001",

                "title":
                    "Target vulnerability",

                "notes": [
                    {
                        "category":
                            "description",

                        "text":
                            (
                                "Origin validation uses "
                                "`re.match()` and may be "
                                "bypassed."
                            ),
                    }
                ],

                "references": [
                    {
                        "url":
                            (
                                "https://bugzilla."
                                "example.invalid/"
                                "show_bug.cgi?id=2466912"
                            ),
                    }
                ],

                "product_status": {
                    "known_affected": [
                        "id=123456"
                    ],
                },
            },

            {
                "cve":
                    "CVE-2026-9999",

                "title":
                    "Unrelated vulnerability",

                "notes": [
                    {
                        "category":
                            "description",

                        "text":
                            "SHOULD_NOT_APPEAR",
                    }
                ],
            },
        ],
    }


    (
        sliced,
        matched_ids,
        csaf_like,
    ) = build_csaf_target_slice(
        csaf,
        vulnerability_ids=[
            "GHSA-SYNTHETIC",
            "CVE-2026-0001",
        ],
    )

    assert csaf_like

    assert (
        matched_ids
        == [
            "CVE-2026-0001"
        ]
    )

    assert sliced is not None

    sliced_text = json.dumps(
        sliced,
        ensure_ascii=False,
        sort_keys=True,
    )

    assert (
        "CVE-2026-0001"
        in sliced_text
    )

    assert (
        "re.match"
        in sliced_text
    )

    assert (
        "SHOULD_NOT_APPEAR"
        not in sliced_text
    )

    assert (
        "product_tree"
        not in sliced
    )

    assert (
        "bugzilla"
        not in sliced_text.lower()
    )

    assert (
        "?id="
        not in sliced_text
    )

    assert (
        "product_status"
        not in sliced_text
    )


    body = json.dumps(
        csaf,
        ensure_ascii=False,
    ).encode(
        "utf-8"
    )

    (
        text,
        mode,
        metadata,
    ) = extract_json_evidence_text(
        body,
        encoding="utf-8",
        vulnerability_ids=[
            "CVE-2026-0001"
        ],
    )

    assert (
        mode
        == "json_csaf_target_slice"
    )

    assert metadata[
        "target_slice_applied"
    ]

    assert metadata[
        "matched_target_ids"
    ] == [
        "CVE-2026-0001"
    ]

    assert (
        "re.match"
        in text
    )

    assert (
        "?id="
        not in text
    )


    # --------------------------------------------------
    # CSAF without target match must NOT fall back to
    # the entire document.
    # --------------------------------------------------

    (
        missing_text,
        missing_mode,
        missing_metadata,
    ) = extract_json_evidence_text(
        body,
        encoding="utf-8",
        vulnerability_ids=[
            "CVE-2026-12345"
        ],
    )

    assert (
        missing_text
        == ""
    )

    assert (
        missing_mode
        == "json_csaf_target_unresolved"
    )

    assert missing_metadata[
        "csaf_like"
    ]

    assert not missing_metadata[
        "target_slice_applied"
    ]


    # --------------------------------------------------
    # Backward-compatible generic canonicalizer.
    # --------------------------------------------------

    canonical = extract_json_text(
        generic_body,
        encoding="utf-8",
    )

    assert (
        json.loads(
            canonical
        )
        == generic
    )


    # --------------------------------------------------
    # Invalid JSON must remain rejected.
    # --------------------------------------------------

    try:
        extract_json_text(
            b'{"broken": ',
            encoding="utf-8",
        )

    except json.JSONDecodeError:
        pass

    else:
        raise AssertionError(
            "Invalid JSON was silently accepted."
        )


    print(
        "[PASS] JSON and +json media types "
        "remain supported."
    )

    print(
        "[PASS] ordinary JSON remains "
        "canonicalized without semantic inference."
    )

    print(
        "[PASS] CSAF/VEX target CVE is sliced "
        "deterministically."
    )

    print(
        "[PASS] product tree, reference URLs, "
        "and unrelated CVEs stay out of "
        "semantic text."
    )

    print(
        "[PASS] missing target CVE does not "
        "fall back to whole-document evidence."
    )

    print(
        "[PASS] invalid JSON remains rejected."
    )

    print(
        "[PASS] Generic HTTP JSON/CSAF "
        "Acquisition v0.3."
    )


if __name__ == "__main__":
    main()
