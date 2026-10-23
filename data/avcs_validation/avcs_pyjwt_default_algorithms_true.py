import jwt


token = "example.token.value"
verification_key = "verification-key-placeholder"

claims = jwt.decode(
    token,
    verification_key,
    algorithms=jwt.algorithms.get_default_algorithms(),
)