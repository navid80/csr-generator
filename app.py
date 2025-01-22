from flask import Flask, render_template, request, send_from_directory
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
import configparser
import os

app = Flask(__name__)

def Generate_CSR(companyName, nationalCode, faCompanyName, email):
    user_folder = os.path.join("static")
    config = configparser.ConfigParser()
    config.read(os.path.join(user_folder, "fa.cnf"))
    try:
        dn_section = config["dn"]
        companyName = companyName
        serialNumber = nationalCode
        organization = dn_section.get("O", "")
        persianName = faCompanyName
        country = dn_section.get("C", "")
        email = email
    except Exception as e:
        print(f"error : {e}")

    # ساخت کلید خصوصی
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    # ذخیره سازی کلید در فایل
    private_key_filename = "fa.key"
    with open(os.path.join(user_folder, private_key_filename), "wb") as key_file:
        key_file.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
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

    csr_filename = "fa.csr"
    with open(os.path.join(user_folder, csr_filename), "wb") as csr_file:
        csr_file.write(csr.public_bytes(serialization.Encoding.PEM))

    public_key = csr.public_key()

    public_key_filename = "fapub.txt"
    with open(os.path.join(user_folder, public_key_filename), "wb") as pubkey_file:
        pubkey_file.write(
            public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        )

    return private_key_filename, csr_filename, public_key_filename

@app.route('/', methods=['GET', 'POST'])
def CSR():
    if request.method == "POST":
        companyName = request.form.get('company-name')
        nationalCode = request.form.get('national-code')
        faCompanyName = request.form.get('fa-company-name')
        email = request.form.get('email')
        private_key_filename, csr_filename, public_key_filename = Generate_CSR(companyName, nationalCode, faCompanyName, email)
        return render_template("index.html", 
                              show_download_links=True, 
                              private_key_filename=private_key_filename, 
                              csr_filename=csr_filename, 
                              public_key_filename=public_key_filename)
    return render_template("index.html", show_download_links=False)

@app.route('/<filename>')
def download_file(filename):
    user_folder = os.path.join("static")
    return send_from_directory(user_folder, filename, as_attachment=True, download_name=filename)

if __name__ == '__main__':
    app.run(debug=True)
