"""Reviewed fix guidance for bounded HarborDesk fixture observations, not CVEs."""


def guidance(finding):
    if finding.get("tool") != "harbordesk":
        return None
    identity = finding.get("tool_native_id")
    common = {
        "source": "Reviewed fixture-specific guidance. No vendor CVE or production compromise is claimed.",
        "example": None,
        "mitigations": [
            "Restrict the affected service to approved clients and accounts.",
            "Apply changes under change control and retain a rollback path.",
        ],
    }
    records = {
        "HD-13": (
            "Anonymous FTP access",
            "An anonymous FTP client retrieved the isolated fictional operations file.",
            "A reachable client can log in anonymously and retrieve files granted to that account; the lab proves access to its fixture file only.",
            "Disclosure of files available to the anonymous account.",
            [
                "Disable anonymous FTP accounts for non-public operational data.",
                "Create least-privilege named accounts; remove unnecessary file permissions.",
                "Use SFTP or properly configured FTPS when file transfer is required.",
            ],
            [
                "Repeat anonymous login: it must be denied.",
                "Verify a permitted named client can access only its intended files.",
            ],
        ),
        "HD-14": (
            "Plaintext FTP transport",
            "The bounded check completed an FTP login and fixture transfer without negotiating TLS.",
            "An attacker who can observe or alter the network path could inspect plaintext credentials or file contents. Traffic interception was not performed.",
            "Potential credential or file disclosure on an observable network path.",
            [
                "Replace plaintext FTP with SFTP or require FTPS for both control and data channels.",
                "Disable the plaintext listener when migration is complete.",
                "Do not treat the port-2122 authentication comparison as a transport-encryption fix.",
            ],
            [
                "Verify plaintext login is refused.",
                "Confirm successful authorized transfers use encryption on both control and data channels.",
            ],
        ),
        "HD-15": (
            "Expired TLS certificate",
            "The actual management TLS handshake supplied a certificate whose expiry time is in the past.",
            "Clients that enforce certificate validity will reject the endpoint. If users bypass warnings, server identity protections may be weakened; no interception was demonstrated.",
            "Loss of trusted connectivity and risk from certificate-warning bypass.",
            [
                "Renew the endpoint certificate with the intended hostname or IP in its SAN.",
                "Install the intended trust chain and enable automatic expiry monitoring.",
                "Use client trust validation; do not make verification bypass a permanent workaround.",
            ],
            [
                "Verify the installed certificate is inside its validity interval and matches the endpoint identity.",
                "Verify a client using the intended trust store connects without disabling certificate validation. A valid self-signed training certificate alone does not establish public trust.",
            ],
        ),
        "HD-16": (
            "Unauthenticated network management",
            "A TLS-connected client received the identified fictional management response without credentials.",
            "A client with network reachability could read exposed management information without an application identity. No write or administrative operation was attempted.",
            "Disclosure of exposed management information; administrative write capability is not established.",
            [
                "Require authenticated administrator authorization on every management route.",
                "Place management listeners on a restricted management network or allowlisted interface.",
                "Retain TLS and configure trusted certificates; encryption does not replace authorization.",
            ],
            [
                "Repeat the unauthenticated request: it must be denied.",
                "Verify approved administrators retain access and ordinary accounts cannot access management routes.",
            ],
        ),
    }
    if identity in ("HD-02", "HD-03"):
        data = (
            "SQL predicate injection",
            "The differential fixture request changed query behavior compared with the normal request.",
            "An attacker able to submit the affected parameter can alter the SQL predicate; the test used only disposable read-only fixture tables.",
            "Broadened fixture record access or fixture authentication bypass, depending on the affected route.",
            [
                "Replace string-concatenated SQL with bound query parameters.",
                "Keep database permissions minimal and handle errors without exposing query details.",
            ],
            [
                "Repeat the same predicate test against the secure comparison: injected input must remain data.",
                "Verify valid searches and valid logins still work.",
            ],
        )
    elif identity in ("HD-04", "HD-09", "HD-10", "HD-11", "HD-06", "HD-07"):
        data = (
            "Access-control failure",
            "The bounded request returned a protected-design fixture resource without its intended owner or administrator check.",
            "A client can request the known fixture endpoint or identifier and receive a resource belonging to another fixture account or intended for an administrator.",
            "Unauthorized disclosure of the specific fictional resources observed; no access to real user data was attempted.",
            [
                "Enforce authentication and authorization server-side on every request.",
                "Scope object queries by both object identifier and authorized account.",
                "Remove debug data from operational endpoints.",
            ],
            [
                "Repeat unauthenticated and cross-account requests: deny them without returning protected content.",
                "Verify the resource owner still has expected access, using the secure comparison as a regression target.",
            ],
        )
    elif identity == "HD-05":
        data = (
            "Unescaped HTML reflection",
            "A harmless HTML marker was returned unescaped in an HTML response. Browser script execution was not tested.",
            "An attacker can influence content in the reflected HTML context. Script execution requires additional context and browser verification.",
            "HTML content manipulation was observed; arbitrary script execution is not claimed.",
            [
                "Apply context-appropriate output encoding.",
                "Prefer safe text rendering APIs; use a reviewed sanitizer when rich HTML is necessary.",
                "Add a suitable CSP as defense in depth, not as a replacement for output encoding.",
            ],
            [
                "Repeat the harmless marker: it must appear as escaped text.",
                "Verify normal search output remains readable.",
            ],
        )
    elif identity == "HD-08":
        data = (
            "Session-cookie hardening",
            "The fixture login response omitted the reviewed cookie protection attributes.",
            "A separate script-injection, network-observation or cross-site request condition could increase exposure when cookie protections are absent.",
            "Potentially increased session exposure under those conditions; no session theft was performed.",
            [
                "Set HttpOnly and a suitable SameSite policy.",
                "Deploy production HTTPS and set Secure there; the HTTP-only local comparison is not a complete transport fix.",
                "Use server-managed unpredictable sessions in production rather than the deliberately simple fixture tokens.",
            ],
            [
                "Inspect Set-Cookie on the corrected endpoint.",
                "Test legitimate authentication flows and verify production cookies require HTTPS.",
            ],
        )
    elif identity == "HD-01":
        data = (
            "Response-header hardening",
            "The fixture response omitted the named browser-security headers.",
            "Missing headers can reduce defense in depth when another relevant application weakness exists. Their absence alone does not prove compromise.",
            "Depends on the separate weakness and the applicable browser control.",
            [
                "Configure CSP, nosniff, framing, referrer and permissions policies for the application needs.",
                "Use the secure response as a comparison; test policies before deployment.",
            ],
            [
                "Inspect the corrected response headers.",
                "Verify intended browser features still function.",
            ],
        )
    else:
        data = records.get(identity)
    if data is None:
        return None
    category, meaning, scenario, impact, patch, verify = data
    return {
        **common,
        "category": category,
        "meaning": meaning,
        "scenario": scenario,
        "impact": impact,
        "patch": patch,
        "verify": verify,
        "prerequisites": [
            "Reachability to the affected local training endpoint.",
            "The exact condition reproduced by the retained bounded check.",
        ],
    }
