import pytest

from firstsignal.redact import Redactor


@pytest.mark.parametrize("text,secret", [
    ("postgres://app:hunter2pass@db:5432/x", "hunter2pass"),
    ("Authorization: Bearer abcdef1234567890", "abcdef1234567890"),
    ('{"password": "p@ssw0rd!"}', "p@ssw0rd!"),
    ("api_key=sk_live_abc123 other=1", "sk_live_abc123"),
    ("token eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTYifQ.abcDEF123456ghiJKL", "eyJhbGci"),
    ("aws key AKIAIOSFODNN7EXAMPLE used", "AKIAIOSFODNN7EXAMPLE"),
    ("github ghp_abcdefghijklmnopqrstuvwxyz0123456789", "ghp_abcdefghij"),
    ("mail from jane.doe@example.com", "jane.doe@example.com"),
])
def test_secrets_are_masked(text, secret):
    assert secret not in Redactor()(text)


def test_non_secrets_survive():
    line = "ERROR [api] connect() failed (111: Connection refused) while connecting to db.internal"
    assert Redactor()(line) == line


def test_ips_only_when_asked():
    assert "10.0.3.17" in Redactor()("client 10.0.3.17")
    assert Redactor(redact_ips=True)("client 10.0.3.17") == "client <IP>"


def test_disabled_and_extra_rules():
    assert Redactor(enabled=False)("password=abc") == "password=abc"
    assert Redactor(extra=[r"cust-\d+"])("order for cust-99812") == "order for <REDACTED>"


KEY_BLOCK = (
    "-----BEGIN RSA PRIVATE KEY-----\n"
    "MIIEowIBAAKCAQEAu1SU1LfVLPHCozMxH2Mo4lgOEePzNm0tRgeLezV6ffAt0gun\n"
    "VTLw7onLRnrq0/IzW7yWR7QkrmBL7jTKEn5u+qKhbwKfBstIs+bMY2Zkp18gnTxK\n"
    "-----END RSA PRIVATE KEY-----"
)


def test_whole_private_key_block_is_masked():
    out = Redactor()("loaded key:\n" + KEY_BLOCK + "\nstarting")
    assert "MIIEow" not in out and "VTLw7o" not in out and "END RSA" not in out
    assert out == "loaded key:\n<REDACTED_PRIVATE_KEY>\n\n\n\nstarting"  # line count kept


def test_key_body_lines_masked_even_without_markers():
    # a truncated tail can start in the middle of a key
    line = "MIIEowIBAAKCAQEAu1SU1LfVLPHCozMxH2Mo4lgOEePzNm0tRgeLezV6ffAt0gun"
    assert Redactor()(line) == "<REDACTED>"


@pytest.mark.parametrize("text,secret", [
    ("Authorization: Bearer abc123", "abc123"),
    ("proxy-authorization=Basic dXNlcjpw", "dXNlcjpw"),
    ('"Authorization": "Token x9"', "x9"),
    ("retry with bearer abc123", "abc123"),
    ("upstream call failed key 9f8a7c6b5d4e3f2a1b0c9d8e7f6a5b4c", "9f8a7c6b5d4e3f2a1b0c"),
    ("session secret Zk82hQ0pLx7Vb3nRt9WqY4mK", "Zk82hQ0pLx7Vb3nRt9WqY4mK"),
    ("callback sig=Zk82hQ0pLx7Vb3nRt9WqY4mK==", "Zk82hQ0pLx7Vb3nRt9WqY4mK"),
    ("token Zk8_2hQ0pLx-7Vb3nRt9Wq-Y4mK1a", "2hQ0pLx-7Vb3nRt9Wq"),
])
def test_short_and_unlabeled_secrets_are_masked(text, secret):
    assert secret not in Redactor()(text)


@pytest.mark.parametrize("line", [
    "basic authentication required",
    "bearer token expired",
    "pod payments-worker-6b8d9c7f5d-x2k4p evicted",
    "container checkout-api-deployment-75f8c9d6b4-2xk9q restarted",
    "request_id=3f2b9c1e-7a4d-4e8b-9c2f-1a2b3c4d5e6f",
    "trace_id=4bf92f3577b34da6 commit a1b2c3d4",
    "open /var/lib/postgresql/data/base/16384/2619: no space left on device",
    "GET /api/v2/orders/12345/items?page=2 HTTP/1.1 500",
    "s3://my-bucket-prod-2024/logs/2026/11/16/app.log",
    "at org.springframework.web.servlet.DispatcherServlet.doDispatch(DispatcherServlet.java:1067)",
    "HikariPool-1 - Connection is not available, request timed out after 30000ms.",
    "kafka consumer group orders-consumer-group-2024 rebalancing",
    "user=checkout_service_account_2024 AbstractPlatformTransactionManager rollback",
    "node ip-10-0-3-17.ec2.internal NotReady",
])
def test_useful_identifiers_survive(line):
    assert Redactor()(line) == line


def test_long_hex_is_masked_by_design():
    # 32+ hex characters cannot be told apart from a secret; hashes and container ids are masked too
    assert Redactor()("image sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08") == \
        "image sha256:<REDACTED>"
