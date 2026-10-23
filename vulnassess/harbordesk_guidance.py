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
        "HD-23": (
            "Unauthenticated network backup",
            "A visitor downloaded the entire fictional business backup from the management service without signing in.",
            "A client connects directly to the management listener and retrieves its backup. The retained counts come from the actual response, not a service banner.",
            "Full disclosure of the fictional backup; no real files, customer data or credentials are exposed.",
            [
                "Require administrator authorization on backup endpoints and restrict management reachability.",
                "Limit export contents and retention to the approved operational purpose.",
            ],
            [
                "Verify an unauthenticated backup request is denied and the authorized comparison still succeeds.",
                "Do not treat HTTP transport as encrypted or a fixture header as production session security.",
            ],
        ),
        "HD-24": (
            "Unauthenticated network management changes",
            "A visitor who was not signed in changed a management setting and paused the fictional dispatch queue. A separate request showed that dispatch was unavailable until the original setting was restored.",
            "A reachable client pauses the disposable in-memory queue through the management API. This is a real request/state/response change, not traffic flooding or process termination.",
            "Unauthorized control of the fictional service's availability only; no host or real business operation is changed.",
            [
                "Authenticate management writes and enforce administrator authorization per operation.",
                "Restrict management listeners and validate the exact permitted configuration fields.",
            ],
            [
                "Verify unauthenticated changes fail without altering the configuration.",
                "Verify legitimate management changes still work in the protected comparison.",
                "Retain and verify the original fixture state after the bounded test.",
            ],
        ),
        "HD-20": (
            "Cleartext HTTP transport",
            "The portal used ordinary HTTP instead of an encrypted HTTPS connection. This check observed the connection type; it did not capture anyone else's traffic.",
            "A client uses cleartext HTTP. An observer on a relevant network path could inspect traffic, but no interception or external network test was performed.",
            "Transport confidentiality is absent for this fictional loopback service; no real credential theft is claimed.",
            [
                "Use properly configured HTTPS and validated certificates outside this isolated lab.",
                "Do not treat /secure/ application routes as a transport-encryption fix.",
            ],
            [
                "Verify authorized clients use HTTPS with the intended trust configuration.",
                "Keep HTTP and optional FTP/TLS verification outcomes distinct.",
            ],
        ),
        "HD-21": (
            "Unauthenticated service inventory",
            "A visitor read the list of fictional services and ports without signing in. The list describes configuration; it does not prove that every listed service is running.",
            "A reachable client can read the declared lab service ports. These declarations do not establish that additional listeners are running or reachable.",
            "Disclosure of the observed lab configuration only; no remote discovery or host enumeration.",
            [
                "Restrict operational inventory to authenticated, authorized users.",
                "Return only the metadata needed by the approved client.",
            ],
            [
                "Verify anonymous and ordinary customer inventory requests are denied.",
                "Verify the fixture administrator still passes the comparison authorization check.",
            ],
        ),
        "HD-22": (
            "Verbose service version banner",
            "The server told visitors which Python and HTTP server versions it was using. That helps identify the software, but a version string alone does not prove a known vulnerability.",
            "A client can fingerprint the response implementation. A version string alone neither proves a CVE nor demonstrates exploitation.",
            "Low-severity implementation information disclosure, not a host compromise.",
            [
                "Minimize unnecessary product/version details in response headers.",
                "Maintain supported software; hiding a banner is not a substitute for patching.",
            ],
            [
                "Inspect the actual response header rather than the answer key.",
                "Verify the comparison omits implementation version details.",
            ],
        ),
        "HD-17": (
            "Unauthenticated bulk export",
            "A visitor downloaded every fictional customer, order, ticket and document collection without signing in.",
            "A reachable client can request the export without a session. The retained check records actual collection counts, not a real-data breach.",
            "Bulk disclosure of the fictional workspace rather than access to a single guessed object.",
            [
                "Require authenticated administrator authorization on every export request.",
                "Limit export fields and records to the caller's approved business scope.",
                "Audit authorized exports without recording sensitive record contents.",
            ],
            [
                "Verify anonymous and ordinary customer export requests are denied.",
                "Verify an approved administrator can still export only the intended records.",
            ],
        ),
        "HD-18": (
            "Protected-field mass assignment",
            "A customer changed its own profile's role to administrator. A separate administration request that had been denied then succeeded.",
            "A signed-in customer submits a protected role field through the self-service profile route. The role is read back and checked on a separate administrator request.",
            "Actual privilege escalation within the fictional process-local workspace; no host privileges or code execution.",
            [
                "Allowlist self-service fields such as display name; reject role and permission fields.",
                "Put role changes behind a separate administrator-only authorization path.",
                "Derive permissions from server-owned records, never client-supplied profile fields.",
            ],
            [
                "Verify protected role assignment is refused and administrator access remains denied.",
                "Verify legitimate display-name updates still succeed.",
                "The vulnerable and secure workspaces must remain isolated.",
            ],
        ),
        "HD-19": (
            "Missing object-write authorization",
            "A customer changed another account's fictional order total, and a separate read showed the new value.",
            "A client submits a different account's order identifier to the write route. The verifier restores the original process-local value after the read-back check.",
            "Unauthorized modification of a fictional order; no real payment, host file or external system is involved.",
            [
                "Authenticate writes and authorize the caller against the specific order.",
                "Bind object lookup to both order ID and authorized account.",
                "Validate totals server-side and retain an authorized change audit.",
            ],
            [
                "Verify anonymous writes fail and cross-account writes return no protected record.",
                "Verify the owner can update its own order and read back the permitted value.",
                "Verify refused writes leave the original order unchanged.",
            ],
        ),
        "HD-13": (
            "Anonymous FTP access",
            "A visitor signed in to the file service as anonymous and downloaded the fictional operations file without needing a named account.",
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
            "The file service sent its login and fictional file transfer without an encrypted connection. This check did not intercept traffic.",
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
            "The management service used a certificate that was already past its expiry date. Clients that check certificate dates can reject the connection.",
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
            "The encrypted management service returned its fictional administrator information without asking the visitor to sign in.",
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
            "Text entered into a search or sign-in field was treated as part of a database instruction instead of just data. In this lab, that changes which records or account the query returns.",
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
            "The service returned a record or administration page without checking that the visitor was allowed to see it.",
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
            "A visitor's text was placed into a web page as HTML instead of ordinary text. The check used a harmless marker; it did not run a script.",
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
            "The sign-in cookie was missing browser protections that help keep session information from other scripts, sites or insecure connections.",
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
            "The server left out browser safety headers: instructions that help browsers block risky content and information leaks. Their absence alone does not prove an exploit.",
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
