import http.server
import socketserver
from urllib.parse import urlparse
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.ocsp import OCSPResponseBuilder, OCSPRequest
from .database import get_db_connection, get_db_path
from .ratelimit import RateLimit

class OCSPHandler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        # Rate limiting check
        client_ip = self.client_address[0]
        if not self.server.rate_limiter.check(client_ip):
            self.send_error(429, "Too Many Requests")
            return

        if self.path != "/":
            self.send_error(404)
            return

        length = int(self.headers.get('Content-Length', 0))
        data = self.rfile.read(length)

        try:
            req = OCSPRequest.load(data)
            cert_id = req.request_list[0].cert_id

            conn = get_db_connection(get_db_path())
            cursor = conn.cursor()
            cursor.execute("SELECT status, revoked_at, revocation_reason FROM certificates WHERE serial_hex = ?", 
                        (format(cert_id.serial_number, 'x').upper(),))
            row = cursor.fetchone()
            conn.close()

            if row is None:
                status = x509.ocsp.OCSPCertStatus.unknown
            elif row['status'] == 'revoked':
                status = x509.ocsp.OCSPCertStatus.revoked
            else:
                status = x509.ocsp.OCSPCertStatus.good

            builder = OCSPResponseBuilder()
            builder = builder.cert_id(cert_id)
            builder = builder.responder_id(x509.ocsp.OCSPResponderID.by_name(self.server.responder_cert.subject))
            builder = builder.cert_status(status)

            if status == x509.ocsp.OCSPCertStatus.revoked and row['revoked_at']:
                builder = builder.revocation_time(x509.ocsp.RevocationTime.fromisoformat(row['revoked_at']))

            response = builder.sign(self.server.responder_key, hashes.SHA256())
            resp_bytes = response.public_bytes(serialization.Encoding.DER)

            self.send_response(200)
            self.send_header("Content-Type", "application/ocsp-response")
            self.end_headers()
            self.wfile.write(resp_bytes)

        except Exception:
            self.send_error(400, "Malformed OCSP request")

def serve_ocsp(args, logger, audit_logger):
    limiter = RateLimit(args.rate_limit, args.rate_burst) if hasattr(args, 'rate_limit') else RateLimit(0, 10)
    with open(args.responder_cert, "rb") as f:
        responder_cert = x509.load_pem_x509_certificate(f.read())
    with open(args.responder_key, "rb") as f:
        responder_key = serialization.load_pem_private_key(f.read(), password=None)

    handler = OCSPHandler
    handler.server = type('Server', (), {
        'responder_cert': responder_cert,
        'responder_key': responder_key,
        'rate_limiter': limiter
    })()

    with socketserver.TCPServer((args.host, args.port), handler) as httpd:
        logger.info(f"OCSP responder запущен на http://{args.host}:{args.port}")
        audit_logger.log('AUDIT', 'ocsp_serve', 'start', 'OCSP responder запущен', {})
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            audit_logger.log('AUDIT', 'ocsp_serve', 'stop', 'OCSP responder остановлен', {})