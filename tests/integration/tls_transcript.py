"""Minimal bounds-checked parsing for normal TLS 1.3 hello regression tests."""

TLS_HANDSHAKE_RECORD = 22
CLIENT_HELLO = 1
SERVER_HELLO = 2
PRE_SHARED_KEY_EXTENSION = 41
KEY_SHARE_EXTENSION = 51
SECP256R1 = 23
HELLO_RETRY_REQUEST_RANDOM = bytes.fromhex(
    "cf21ad74e59a6111be1d8c021e65b891"
    "c2a211167abb8c5e079e09e2c8a8339c"
)


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def take(data, offset, size, label):
    end = offset + size
    require(end <= len(data), f"truncated {label}")
    return data[offset:end], end


def take_vector(data, offset, size_bytes, label):
    encoded_size, offset = take(data, offset, size_bytes, f"{label} length")
    size = int.from_bytes(encoded_size, "big")
    return take(data, offset, size, label)


def tls_records(stream, direction):
    result = []
    offset = 0
    while offset < len(stream):
        begin = offset
        header, offset = take(stream, offset, 5, f"{direction} TLS record header")
        header_end = offset
        _, offset = take(
            stream,
            offset,
            int.from_bytes(header[3:5], "big"),
            f"{direction} TLS record payload",
        )
        result.append({
            "content_type": header[0],
            "begin": begin,
            "header_end": header_end,
            "end": offset,
        })
    return result


def plaintext_handshakes(stream, direction):
    """Return complete, pre-encryption handshake messages from a TLS byte stream."""
    plaintext = bytearray()
    for record in tls_records(stream, direction):
        if record["content_type"] == TLS_HANDSHAKE_RECORD:
            plaintext.extend(stream[record["header_end"]:record["end"]])

    messages = []
    offset = 0
    while offset < len(plaintext):
        header, offset = take(plaintext, offset, 4, f"{direction} handshake header")
        body, offset = take(
            plaintext,
            offset,
            int.from_bytes(header[1:4], "big"),
            f"{direction} handshake body",
        )
        messages.append((header[0], body))
    return messages


def extensions(data, offset, hello):
    encoded, offset = take_vector(data, offset, 2, f"{hello} extensions")
    require(offset == len(data), f"trailing bytes after {hello} extensions")
    result = []
    offset = 0
    while offset < len(encoded):
        extension_type, offset = take(encoded, offset, 2, f"{hello} extension type")
        extension_data, offset = take_vector(encoded, offset, 2, f"{hello} extension data")
        result.append((int.from_bytes(extension_type, "big"), extension_data))
    return result


def client_hello_extensions(body):
    _, offset = take(body, 0, 2 + 32, "ClientHello legacy version and random")
    _, offset = take_vector(body, offset, 1, "ClientHello session id")
    cipher_suites, offset = take_vector(body, offset, 2, "ClientHello cipher suites")
    require(
        cipher_suites and len(cipher_suites) % 2 == 0,
        "invalid ClientHello cipher suite vector",
    )
    compression, offset = take_vector(body, offset, 1, "ClientHello compression methods")
    require(compression, "empty ClientHello compression methods")
    return extensions(body, offset, "ClientHello")


def server_hello_extensions(body):
    fixed, offset = take(body, 0, 2 + 32, "ServerHello legacy version and random")
    server_random = fixed[2:]
    _, offset = take_vector(body, offset, 1, "ServerHello session id")
    _, offset = take(body, offset, 2 + 1, "ServerHello cipher suite and compression")
    return server_random, extensions(body, offset, "ServerHello")


def one_extension(items, extension_type, hello):
    matches = [data for kind, data in items if kind == extension_type]
    require(
        len(matches) == 1,
        f"{hello} has {len(matches)} key_share extensions instead of exactly one",
    )
    return matches[0]


def client_key_shares(extension_data):
    encoded, offset = take_vector(extension_data, 0, 2, "ClientHello key_share list")
    require(offset == len(extension_data), "trailing bytes after ClientHello key_share list")
    shares = []
    offset = 0
    while offset < len(encoded):
        group, offset = take(encoded, offset, 2, "ClientHello key_share group")
        key_exchange, offset = take_vector(
            encoded, offset, 2, "ClientHello key_share key_exchange"
        )
        require(key_exchange, "empty ClientHello key_share key_exchange")
        shares.append(int.from_bytes(group, "big"))
    return shares


def server_key_share(extension_data):
    group, offset = take(extension_data, 0, 2, "ServerHello key_share group")
    key_exchange, offset = take_vector(
        extension_data, offset, 2, "ServerHello key_share key_exchange"
    )
    require(offset == len(extension_data), "trailing bytes after ServerHello key_share")
    require(key_exchange, "empty ServerHello key_share key_exchange")
    return int.from_bytes(group, "big")


def validate_wire_hellos(client_stream, server_stream, context):
    client_hellos = [
        body
        for kind, body in plaintext_handshakes(client_stream, f"{context} client-sent")
        if kind == CLIENT_HELLO
    ]
    server_hellos = [
        body
        for kind, body in plaintext_handshakes(server_stream, f"{context} server-sent")
        if kind == SERVER_HELLO
    ]
    require(
        len(client_hellos) == 1,
        f"{context}: observed {len(client_hellos)} ClientHello messages instead of one",
    )
    require(
        len(server_hellos) == 1,
        f"{context}: observed {len(server_hellos)} ServerHello messages instead of one",
    )

    client_extensions = client_hello_extensions(client_hellos[0])
    require(
        all(kind != PRE_SHARED_KEY_EXTENSION for kind, _ in client_extensions),
        f"{context}: ClientHello offered pre_shared_key instead of a full handshake",
    )
    client_share = one_extension(client_extensions, KEY_SHARE_EXTENSION, "ClientHello")
    shares = client_key_shares(client_share)
    require(
        shares == [SECP256R1],
        f"{context}: ClientHello key_share groups are {shares}, expected [23]",
    )

    server_random, server_extensions = server_hello_extensions(server_hellos[0])
    require(
        server_random != HELLO_RETRY_REQUEST_RANDOM,
        f"{context}: wire ServerHello random identifies HelloRetryRequest",
    )
    require(
        all(kind != PRE_SHARED_KEY_EXTENSION for kind, _ in server_extensions),
        f"{context}: ServerHello selected a pre_shared_key identity",
    )
    selected_group = server_key_share(
        one_extension(server_extensions, KEY_SHARE_EXTENSION, "ServerHello")
    )
    require(
        selected_group == SECP256R1,
        f"{context}: ServerHello selected group {selected_group}, expected 23",
    )
