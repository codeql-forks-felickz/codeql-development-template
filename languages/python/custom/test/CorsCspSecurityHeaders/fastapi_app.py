from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI()

# Unescaped dots and an unbounded `.*` prefix: matches e.g. https://evilrestaurant.com
app.add_middleware(
    CORSMiddleware,
    allow_origin_regex=".*.(restaurant.com|deliveryservice.com)",  # $ Alert
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Unbounded `.*` directly before the domain: matches https://attackerexample.com
app.add_middleware(
    CORSMiddleware,
    allow_origin_regex=r"https://.*example\.com",  # $ Alert
    allow_credentials=True,
)

# Matches any origin.
app.add_middleware(
    CORSMiddleware,
    allow_origin_regex=".*",  # $ Alert
    allow_credentials=True,
)

# Wildcard origin list with credentials.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # $ Alert
    allow_credentials=True,
)

# Safe: escaped dots and sub-domain boundary.
app.add_middleware(
    CORSMiddleware,
    allow_origin_regex=r"https://([a-z0-9-]+\.)?(restaurant\.com|deliveryservice\.com)",
    allow_credentials=True,
)

# Safe: subdomain wildcard followed by an escaped dot.
app.add_middleware(
    CORSMiddleware,
    allow_origin_regex=r"https://.*\.example\.com",
    allow_credentials=True,
)

# Safe: explicit origin list.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://trusted.example.com"],
    allow_credentials=True,
)

# Not flagged: permissive regex without credentials.
app.add_middleware(
    CORSMiddleware,
    allow_origin_regex=".*",
    allow_credentials=False,
)

# Catch-all host after a scheme.
app.add_middleware(
    CORSMiddleware,
    allow_origin_regex=r"https://.*",  # $ Alert
    allow_credentials=True,
)

app.add_middleware(
    CORSMiddleware,
    allow_origin_regex=r"^https?://[^/]+$",  # $ Alert
    allow_credentials=True,
)

# Catch-all top-level alternative.
app.add_middleware(
    CORSMiddleware,
    allow_origin_regex=r"https://trusted\.example\.com|.*",  # $ Alert
    allow_credentials=True,
)

# Unbounded wildcard after the domain: matches https://trusted.example.com.evil.com
app.add_middleware(
    CORSMiddleware,
    allow_origin_regex=r"https://trusted\.example\.com.*",  # $ Alert
    allow_credentials=True,
)

# Safe: alternation of escaped sub-domains, optional port and a dot inside a character class.
app.add_middleware(
    CORSMiddleware,
    allow_origin_regex=r"https://(foo|bar)\.example\.com(:[0-9]+)?",
    allow_credentials=True,
)

app.add_middleware(
    CORSMiddleware,
    allow_origin_regex=r"https://[.a-z0-9-]+\.example\.com",
    allow_credentials=True,
)
