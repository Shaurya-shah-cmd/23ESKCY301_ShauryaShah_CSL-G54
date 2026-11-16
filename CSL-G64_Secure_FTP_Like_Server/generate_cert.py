
import datetime
import ipaddress
from pathlib import Path

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

# Generate private key
key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)

# Certificate details
name = x509.Name([
    x509.NameAttribute(
        NameOID.COUNTRY_NAME, "IN"
    ),
    x509.NameAttribute(
        NameOID.ORGANIZATION_NAME, "Cyber Security Lab"
    ),
    x509.NameAttribute(
        NameOID.COMMON_NAME, "localhost"
    ),
])

# Create self-signed certificate
cert = (
    x509.CertificateBuilder()
    .subject_name(name)
    .issuer_name(name)
    .public_key(key.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(
        datetime.datetime.now(datetime.timezone.utc)
    )
    .not_valid_after(
        datetime.datetime.now(datetime.timezone.utc)
        + datetime.timedelta(days=365)
    )
    .add_extension(
        x509.SubjectAlternativeName([
            x509.DNSName("localhost"),
            x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
        ]),
        critical=False,
    )
    .sign(key, hashes.SHA256())
)

# Save private key
Path("server.key").write_bytes(
    key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
)

# Save certificate
Path("server.crt").write_bytes(
    cert.public_bytes(serialization.Encoding.PEM)
)

print("Certificate generated successfully!")
print("Created: server.crt")
print("Created: server.key")