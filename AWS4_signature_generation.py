import hashlib
import hmac
import datetime

# AWS Credentials
access_key = ""
secret_key = ""
region = "ap-south-1"
service = "ec2"

# Step 1: Create a Canonical Request
http_method = "GET"
canonical_uri = "/"
canonical_querystring = ""
canonical_headers = "host:ec2.amazonaws.com\nx-amz-date:{timestamp}\n"
signed_headers = "host;x-amz-date"
payload_hash = hashlib.sha256(b"").hexdigest()

canonical_request = (
    f"{http_method}\n"
    f"{canonical_uri}\n"
    f"{canonical_querystring}\n"
    f"{canonical_headers}\n"
    f"{signed_headers}\n"
    f"{payload_hash}"
)

# Step 2: Create the String to Sign
timestamp = datetime.datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
datestamp = timestamp[:8]
credential_scope = f"{datestamp}/{region}/{service}/aws4_request"
hashed_canonical_request = hashlib.sha256(canonical_request.encode("utf-8")).hexdigest()

string_to_sign = (
    f"AWS4-HMAC-SHA256\n"
    f"{timestamp}\n"
    f"{credential_scope}\n"
    f"{hashed_canonical_request}"
)

# Step 3: Calculate the Signature
def sign(key, msg):
    return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()

k_date = sign(("AWS4" + secret_key).encode("utf-8"), datestamp)
k_region = sign(k_date, region)
k_service = sign(k_region, service)
k_signing = sign(k_service, "aws4_request")

signature = hmac.new(k_signing, string_to_sign.encode("utf-8"), hashlib.sha256).hexdigest()

# Step 4: Construct Authorization Header
authorization_header = (
    f"AWS4-HMAC-SHA256 Credential={access_key}/{credential_scope}, "
    f"SignedHeaders={signed_headers}, Signature={signature}"
)


print("\nSignature:\n", signature)
print("\nAuthorization Header:\n", authorization_header)