from flask import Flask, render_template, request, send_from_directory
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
import configparser

app = Flask(__name__)

def Generate_CSR(companyName,nationalCode,faCompanyName,email):
    config = configparser.ConfigParser()
    config.read("./static/fa.cnf")
    try :
        dn_section = config["dn"]
        companyName = companyName
        serialNumber = nationalCode
        organization = dn_section.get("O", "")
        persianName = faCompanyName
        country = dn_section.get("C", "")
        email = email
    except Exception as e:
        print(f"error : {e}")
    #ساخت کلید خصوصی
    private_key = rsa.generate_private_key(
        public_exponent = 65537,
        key_size = 2048
    )

    # ذخیره سازی کلید در فایل
    with open("./static/fa.key", "wb") as key_file:
        key_file.write(
            private_key.private_bytes(
                encoding = serialization.Encoding.PEM,
                format = serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm = serialization.NoEncryption()
            )
        )

    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, companyName),
        x509.NameAttribute(NameOID.SERIAL_NUMBER, serialNumber),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, persianName),
        x509.NameAttribute(NameOID.COUNTRY_NAME, country),
        x509.NameAttribute(NameOID.EMAIL_ADDRESS, email)
    ])

    csr = x509.CertificateSigningRequestBuilder().subject_name(
        subject
    ).sign(private_key, hashes.SHA256())

    with open("./static/fa.csr", "wb") as csr_file:
        csr_file.write(csr.public_bytes(serialization.Encoding.PEM))


    public_key = csr.public_key()

    with open("./static/fapub.txt", "wb") as pubkey_file:
        pubkey_file.write(
            public_key.public_bytes(
                encoding = serialization.Encoding.PEM,
                format = serialization.PublicFormat.SubjectPublicKeyInfo
            )
        )

@app.route('/', methods = ['GET', 'POST'])
def CSR():
    if request.method == "POST":
        companyName = request.form.get('company-name')
        nationalCode = request.form.get('national-code')
        faCompanyName = request.form.get('fa-company-name')
        email = request.form.get('email')
        Generate_CSR(companyName,nationalCode,faCompanyName,email)
        return render_template("index.html", show_download_links=True)
    return render_template("index.html", show_download_links=False)

@app.route('/<filename>')
def download_file(filename):
    return send_from_directory('./static', filename, as_attachment=True, download_name=filename)
