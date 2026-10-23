from xml.etree.ElementTree import Element, SubElement, tostring

import bleach


ALLOWED_TAGS = ["b", "i", "em", "strong", "a", "p", "ul", "ol", "li", "br"]
ALLOWED_ATTRIBUTES = {
    "a": ["href", "title"],
}


def sanitize_html_fragment(user_input: str) -> str:
    return bleach.clean(
        user_input,
        tags=ALLOWED_TAGS,
        attributes=ALLOWED_ATTRIBUTES,
        strip=True,
    )


def append_sanitized_comment(document: Element, username: str, comment_html: str) -> Element:
    comments = document.find("comments")
    if comments is None:
        comments = SubElement(document, "comments")

    comment = SubElement(comments, "comment")
    author = SubElement(comment, "author")
    author.text = username

    body = SubElement(comment, "body")
    body.text = sanitize_html_fragment(comment_html)

    return comment


def create_document() -> Element:
    root = Element("document")
    title = SubElement(root, "title")
    title.text = "User Comments"
    SubElement(root, "comments")
    return root


if __name__ == "__main__":
    document = create_document()

    unsafe_input = '<script>alert("xss")</script><p>Hello <strong>world</strong></p>'
    append_sanitized_comment(document, "alice", unsafe_input)

    print(tostring(document, encoding="unicode"))
