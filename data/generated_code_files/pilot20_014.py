import idna


def domain_to_ascii(domain):
    try:
        ascii_domain = idna.encode(domain).decode("ascii")
        return ascii_domain
    except idna.IDNAError as e:
        raise ValueError(f"Invalid internationalized domain name: {domain}") from e


def domain_to_unicode(domain):
    try:
        unicode_domain = idna.decode(domain)
        return unicode_domain
    except idna.IDNAError as e:
        raise ValueError(f"Invalid ASCII domain name: {domain}") from e


def validate_domain(domain):
    try:
        encoded = domain_to_ascii(domain)
        decoded = domain_to_unicode(encoded)
        return True, encoded, decoded
    except ValueError as e:
        return False, None, str(e)


if __name__ == "__main__":
    domains = ["bücher.example", "例子.测试", "xn--bcher-kva.example"]

    for domain in domains:
        ok, ascii_value, result = validate_domain(domain)
        print(domain, ok, ascii_value, result)
