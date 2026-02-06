# Example: Security Misconfiguration patterns
# These should be detected by the security misconfiguration detector

from flask import Flask
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

# Pattern 1: Debug mode enabled in Flask
app = Flask(__name__)
app.run(debug=True)  # Should flag: debug mode enabled

# Pattern 2: Debug mode in another style (should NOT flag - plain constant)
DEBUG = True  # Should NOT flag: just a constant assignment
app2 = Flask(__name__)
app2.config['DEBUG'] = DEBUG

# Pattern 3: Permissive CORS - allow_all_origins
fastapi_app = FastAPI()
fastapi_app.add_middleware(
    CORSMiddleware,
    allow_all_origins=True,  # Should flag: permissive CORS
    allow_credentials=True,
)

# Pattern 4: Permissive CORS - wildcard in allow_origins list
fastapi_app2 = FastAPI()
fastapi_app2.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Should flag: permissive CORS
    allow_credentials=True,
)

# Pattern 5: Permissive CORS - origins parameter with wildcard
def setup_cors():
    origins = "*"  # Should flag: permissive CORS
    return origins

# Commented out patterns (should NOT flag):
# app.run(debug=True)
# allow_all_origins=True
# origins = "*"

# Safe examples (should NOT flag):
# debug=False
# allow_origins=["https://example.com", "https://app.example.com"]
# origins=["https://trusted-site.com"]
