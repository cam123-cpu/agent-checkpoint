"""deploy/external_check.py run against the real server over HTTPS, the way it runs against a deployment."""
import datetime as dt
import importlib.util
import pathlib

from test_web_security import serve, world  # noqa: F401  (fixture)

from agent_checkpoint.server import ServerConfig

SCRIPT = pathlib.Path(__file__).resolve().parent.parent / "deploy" / "external_check.py"


def load():
    spec = importlib.util.spec_from_file_location("external_check", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def self_signed(tmp_path):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = dt.datetime.now(dt.UTC)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(1).not_valid_before(now - dt.timedelta(days=1)).not_valid_after(now + dt.timedelta(days=90))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False)
            .sign(key, hashes.SHA256()))
    (tmp_path / "c.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    (tmp_path / "k.pem").write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                                       serialization.NoEncryption()))
    return str(tmp_path / "c.pem"), str(tmp_path / "k.pem")


def test_the_server_passes_its_own_outside_check(world, tmp_path, capsys):  # noqa: F811
    srv = serve(world[0], ServerConfig(), self_signed(tmp_path))
    try:
        url = f"https://localhost:{srv.server_address[1]}"
        code = load().main([url, "--insecure", "--skip-http", "--skip-ports", "--login-limit", "approver@acme.com"])
        out = capsys.readouterr().out
        assert code == 0, out
        assert "FAIL" not in out and "repeated wrong passwords are slowed down" in out
    finally:
        srv.shutdown()


def test_it_notices_a_plain_http_server(capsys):
    assert load().main(["http://example.invalid"]) == 2
