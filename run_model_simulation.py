"""Train and run the local asset-role model on labelled synthetic hosts.

This simulation proves the training, calibration, artifact, prediction, abstention,
and evaluation paths. It is not evidence of accuracy on real scan captures.
"""

import json
from pathlib import Path

from vulnassess.readers import parse_nmap_xml
from vulnassess.role_model import LabelledHost, calibrate, evaluate, save_model, train
from vulnassess.schema import Host, Service

ROOT = Path(__file__).resolve().parent
ARTIFACT = ROOT / "models" / "synthetic-role-model.json"
REPORT = ROOT / "reports" / "model-simulation.json"
TRAIN_DATA = ROOT / "tests" / "synthetic" / "synthetic_role_train.jsonl"
VALIDATION_DATA = ROOT / "tests" / "synthetic" / "synthetic_role_validation.jsonl"


def service(
    port: int,
    name: str,
    product: str,
    *,
    tls: bool = False,
) -> Service:
    protocol = "tcp"
    banner = f"{port}/{protocol} {name} {product}"
    return Service(
        port=port,
        protocol=protocol,
        name=name,
        product=product,
        banner=banner,
        tls=tls,
    )


def host(role: str, variant: int, address: str) -> Host:
    profiles = {
        "database": (
            ((3306, "mysql", "MySQL Server"), (5432, "postgresql", "PostgreSQL Server")),
            ("Linux server", "Linux server"),
        ),
        "web_frontend": (
            ((80, "http", "Apache httpd"), (443, "https", "nginx web server")),
            ("Linux server", "Linux server"),
        ),
        "app_server": (
            ((8080, "http", "Apache Tomcat"), (8080, "http", "Jetty application server")),
            ("Linux server", "Linux server"),
        ),
        "domain_controller": (
            ((88, "kerberos-sec", "Microsoft Kerberos"), (389, "ldap", "Microsoft LDAP")),
            ("Windows Server domain services", "Windows Server domain services"),
        ),
        "mail": (
            ((25, "smtp", "Postfix smtpd"), (143, "imap", "Dovecot imapd")),
            ("Linux server", "Linux server"),
        ),
        "file_share": (
            ((445, "microsoft-ds", "Samba smbd"), (2049, "nfs", "Linux nfsd")),
            ("Linux file server", "Linux file server"),
        ),
        "iot_embedded": (
            ((23, "telnet", "BusyBox telnetd"), (80, "http", "GoAhead-Webs embedded")),
            ("Embedded Linux", "Embedded Linux"),
        ),
        "network_device": (
            ((22, "ssh", "Cisco IOS sshd"), (22, "ssh", "Juniper Junos sshd")),
            ("Cisco IOS router", "Juniper Junos router"),
        ),
        "workstation": (
            ((3389, "ms-wbt-server", "Microsoft Terminal Services"), (22, "ssh", "OpenSSH")),
            ("Windows 11 workstation", "Ubuntu Desktop workstation"),
        ),
    }
    service_variants, os_variants = profiles[role]
    selected = service_variants[variant % len(service_variants)]
    primary = service(*selected, tls=selected[0] == 443)
    services = [primary]
    if role == "database":
        services.append(service(80, "http", "Apache httpd"))
    if role == "domain_controller":
        services = [
            service(88, "kerberos-sec", "Microsoft Kerberos"),
            service(389, "ldap", "Microsoft LDAP"),
        ]
    return Host(
        ip=address,
        hostname=f"synthetic-{role}-{variant}",
        os_guess=os_variants[variant % len(os_variants)],
        services=tuple(services),
    )


def examples(start: int, count_per_role: int, split: str) -> list[LabelledHost]:
    roles = (
        "app_server",
        "database",
        "domain_controller",
        "file_share",
        "iot_embedded",
        "mail",
        "network_device",
        "web_frontend",
        "workstation",
    )
    rows = []
    sequence = start
    for role in roles:
        for variant in range(count_per_role):
            octet = sequence % 250 + 1
            address = f"192.0.2.{octet}" if split == "train" else f"198.51.100.{octet}"
            rows.append(
                LabelledHost(
                    host=host(role, variant, address),
                    label=role,
                    group=f"synthetic-{split}-{role}-{variant}",
                    label_source="synthetic",
                )
            )
            sequence += 1
    return rows


def write_examples(path: Path, rows: list[LabelledHost]) -> None:
    path.write_text(
        "\n".join(json.dumps(row.to_json(), sort_keys=True) for row in rows) + "\n",
        encoding="utf-8",
    )


def main() -> int:
    training = examples(0, 6, "train")
    validation = examples(100, 2, "validation")
    write_examples(TRAIN_DATA, training)
    write_examples(VALIDATION_DATA, validation)
    model = train(
        training,
        epochs=800,
        learning_rate=0.15,
        l2=0.001,
        confidence_threshold=0.55,
        margin_threshold=0.10,
    )
    model = calibrate(model, validation)
    metrics = evaluate(model, validation)
    save_model(model, ARTIFACT)

    scan_hosts, _ = parse_nmap_xml(
        ROOT / "tests" / "synthetic" / "synthetic_nmap_two_machines.xml",
        "model-simulation",
    )
    scan_hosts.append(Host(ip="172.28.0.11"))
    predictions = [{"host_ip": item.ip, **model.predict(item).to_json()} for item in scan_hosts]

    report = {
        "status": "TESTED WITH SYNTHETIC",
        "real_capture_validation": "MISSING",
        "purpose": "exercise the complete local role-model lifecycle without claiming real accuracy",
        "model": {
            "artifact": str(ARTIFACT),
            "hash": model.model_hash,
            "algorithm": model.training["algorithm"],
            "classes": list(model.classes),
            "features": len(model.features),
            "temperature": model.temperature,
            "training_examples": len(training),
            "validation_examples": len(validation),
            "training_data": str(TRAIN_DATA),
            "validation_data": str(VALIDATION_DATA),
        },
        "validation": metrics,
        "product_host_predictions": predictions,
        "ranking_integration": "SHADOW ONLY: predictions did not alter ContextProfile or scores",
    }
    REPORT.parent.mkdir(parents=True, exist_ok=True)
    REPORT.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    print("LOCAL ROLE-MODEL SIMULATION")
    print("  status: TESTED WITH SYNTHETIC (real labelled captures are MISSING)")
    print(f"  algorithm: {model.training['algorithm']}")
    print(f"  artifact: {ARTIFACT}")
    print(f"  training data: {TRAIN_DATA}")
    print(f"  validation data: {VALIDATION_DATA}")
    print(f"  model hash: {model.model_hash}")
    print(f"  classes/features: {len(model.classes)}/{len(model.features)}")
    print(f"  train/validation: {len(training)}/{len(validation)} independent groups")
    print(f"  calibration temperature: {model.temperature}")
    print(
        "  validation: "
        f"accuracy={metrics['accuracy']:.3f} "
        f"coverage={metrics['coverage']:.3f} "
        f"macro_f1={metrics['macro_f1']:.3f} "
        f"log_loss={metrics['log_loss']:.3f} "
        f"ECE={metrics['expected_calibration_error']:.3f}"
    )
    print("  product hosts (shadow mode):")
    for prediction in predictions:
        suffix = " ABSTAINED" if prediction["abstained"] else ""
        print(
            f"    {prediction['host_ip']}: {prediction['label']} "
            f"confidence={prediction['confidence']:.3f} "
            f"margin={prediction['margin']:.3f}{suffix}"
        )
        print(f"      evidence: {prediction['evidence']}")
    print(f"  report: {REPORT}")
    print("  ranking: unchanged; model is shadow-only pending real labels and approval")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
