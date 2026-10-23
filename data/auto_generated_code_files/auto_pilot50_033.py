import bleach

def sanitize_and_append(base_html, untrusted_input):
    allowed_tags = ['a', 'abbr', 'acronym', 'b', 'blockquote', 'code', 'em', 'i', 'li', 'ol', 'strong', 'ul']
    allowed_attributes = {
        'a': ['href', 'title'],
        'abbr': ['title'],
        'acronym': ['title'],
    }
    safe_input = bleach.clean(untrusted_input, tags=allowed_tags, attributes=allowed_attributes, strip=True)
    final_html = base_html.replace('{{CONTENT}}', safe_input)
    return final_html

if __name__ == '__main__':
    html_template = '<html><body><div>{{CONTENT}}</div></body></html>'
    malicious_input = '<script>alert(1)</script><p>Hello <b>World</b></p>'
    result = sanitize_and_append(html_template, malicious_input)
    print(result)
