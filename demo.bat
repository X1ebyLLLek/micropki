@echo off
cd /d "%~dp0"
echo ========================================================
echo MicroPKI Demo Script (Sprints 1-3)
echo ========================================================
echo.
echo Activating virtual environment...
if exist venv\Scripts\activate.bat (
    call venv\Scripts\activate.bat
) else (
    echo [WARNING] venv not found! Attempting to run with system python.
)

echo.
echo ========================================================
echo 1. RUNNING ALL AUTOMATED TESTS
echo ========================================================
echo Running pytest to verify all cryptography, CLI, Database, and Server logic...
python -m pytest tests/ -v

echo.
echo ========================================================
echo 2. STARTING PKI DEMO (Creating DB and Certificates)
echo ========================================================
echo - Cleaning up old demo files...
if exist demo_pki rmdir /s /q demo_pki
if exist demo_secrets rmdir /s /q demo_secrets
mkdir demo_secrets

echo - Generating mock passwords...
echo demo-root-pass > demo_secrets\root.pass
echo demo-inter-pass > demo_secrets\inter.pass

echo.
echo - Initializing SQLite Database...
python -m micropki db init --db-path ./demo_pki/demo.db

echo.
echo - Creating Root CA (Foundation of Trust)...
python -m micropki ca init --subject "/CN=Demo Root CA/O=University" --key-type rsa --key-size 4096 --passphrase-file ./demo_secrets/root.pass --out-dir ./demo_pki --validity-days 3650 --db-path ./demo_pki/demo.db

echo.
echo - Creating Intermediate CA...
python -m micropki ca issue-intermediate --root-cert ./demo_pki/certs/ca.cert.pem --root-key ./demo_pki/private/ca.key.pem --root-pass-file ./demo_secrets/root.pass --subject "CN=Demo Intermediate CA,O=University" --key-type rsa --key-size 4096 --passphrase-file ./demo_secrets/inter.pass --out-dir ./demo_pki --validity-days 1825 --pathlen 0 --db-path ./demo_pki/demo.db

echo.
echo - Issuing a Server Certificate (for a website)...
python -m micropki ca issue-cert --ca-cert ./demo_pki/certs/intermediate.cert.pem --ca-key ./demo_pki/private/intermediate.key.pem --ca-pass-file ./demo_secrets/inter.pass --template server --subject "CN=teacher-demo.com,O=University" --san dns:teacher-demo.com --out-dir ./demo_pki/certs --db-path ./demo_pki/demo.db

echo.
echo - Issuing a Client Certificate (for a user)...
python -m micropki ca issue-cert --ca-cert ./demo_pki/certs/intermediate.cert.pem --ca-key ./demo_pki/private/intermediate.key.pem --ca-pass-file ./demo_secrets/inter.pass --template client --subject "CN=Demo User" --san email:teacher@demo.com --out-dir ./demo_pki/certs --db-path ./demo_pki/demo.db

echo.
echo ========================================================
echo 3. SHOWING ISSUED CERTIFICATES FROM DATABASE
echo ========================================================
python -m micropki ca list-certs --db-path ./demo_pki/demo.db --format table

echo.
echo ========================================================
echo DEMO COMPLETE!
echo. 
echo All files have been saved to the "demo_pki" folder.
echo You can now test the HTTP Repository Server by running:
echo   python -m micropki repo serve --host 0.0.0.0 --port 8080 --db-path ./demo_pki/demo.db --cert-dir ./demo_pki/certs
echo ========================================================
pause
