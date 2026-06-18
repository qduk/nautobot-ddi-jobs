"""Jobs to manage DDI objects."""
# pylint: disable=too-few-public-methods

import json
import os
from datetime import datetime, timezone
from itertools import chain
from pathlib import Path
import socket
from urllib.parse import urlparse

import dns.query
import dns.tsigkeyring
import dns.update
from jinja2 import Environment, FileSystemLoader
from nautobot.apps.jobs import BooleanVar, Job, JobHookReceiver, MultiObjectVar
from nautobot.extras.choices import SecretsGroupAccessTypeChoices, SecretsGroupSecretTypeChoices
from nautobot.extras.models import ExternalIntegration
from nautobot.core.models.utils import serialize_object_v2
from nautobot_dns_models import models as dns_models

JOB_GROUP_NAME = "Nautobot DDI Jobs"
name = JOB_GROUP_NAME  # pylint: disable=invalid-name

# Record types whose value ends in a domain name that must be fully qualified. Without a
# trailing dot, dnspython qualifies the name relative to the zone origin (e.g. a PTR target
# "www.example.com" becomes "www.example.com.<zone>"), corrupting the record. A/AAAA (IP) and
# TXT (free text) values must be left untouched.
_FQDN_VALUED_RECORD_TYPES = {"CNAME", "NS", "PTR", "MX", "SRV"}


def _bind9_integration():
    """Return the ExternalIntegration for BIND9.

    Looks up the integration by name from the BIND9_EXTERNAL_INTEGRATION
    environment variable, defaulting to ``"BIND9"``.
    """
    integration_name = os.environ.get("BIND9_EXTERNAL_INTEGRATION", "BIND9")
    try:
        return ExternalIntegration.objects.get(name=integration_name)
    except ExternalIntegration.DoesNotExist:
        raise ValueError(
            f"ExternalIntegration '{integration_name}' not found. "
            "Create a Nautobot ExternalIntegration whose remote_url encodes the BIND9 "
            "server hostname and port (e.g. dns://bind9.example.com:53) and attach a "
            "SecretsGroup containing a Generic/Username entry for the TSIG key name and "
            "a Generic/Token entry for the TSIG key secret. Override the integration "
            "name with the BIND9_EXTERNAL_INTEGRATION environment variable."
        ) from None


def _generate_soa_serial():
    """Return a monotonically increasing 32-bit-safe SOA serial.

    Uses the current UTC unix timestamp so each render produces a fresh
    serial without operator intervention. Stays within RFC 1035's 32-bit
    unsigned range until 2106.
    """
    return int(datetime.now(tz=timezone.utc).timestamp())


def record_values(data, record_type):
    """Extract record values based on record type."""
    zone = data.get("zone", {}).get("name")
    ttl = data.get("ttl")
    match record_type:
        case "A" | "AAAA":
            record_name = data["name"]
            # ``ip_address`` is a FK to an IPAM IPAddress, nested-expanded by serialize_object_v2
            # (depth=1). Prefer the denormalized host; fall back to stripping the mask off address.
            ip_address = data["ip_address"]
            value = ip_address.get("host") or ip_address["address"].split("/")[0]
        case "CNAME":
            record_name = data["name"]
            value = data["alias"]
        case "NS":
            record_name = data["name"]
            value = data["server"]
        case "SRV":
            record_name = data["name"]
            value = f'{data["priority"]} {data["weight"]} {data["port"]} {data["target"]}'
        case "MX":
            record_name = data["name"]
            value = f'{data["preference"]} {data["mail_server"]}'
        case "PTR":
            record_name = data["name"]
            value = data["ptrdname"]
        case "TXT":
            record_name = data["name"]
            # Wrap the text in one quoted character-string so spaces don't split it into
            # multiple strings (e.g. "v=spf1 mx -all" instead of "v=spf1" "mx" "-all").
            # Escape backslashes and embedded quotes per DNS presentation format.
            escaped = data["text"].replace("\\", "\\\\").replace('"', '\\"')
            value = f'"{escaped}"'
        case _:
            raise ValueError(f"Unsupported record type: {record_type}")
    return zone, record_name, ttl, value


def render_template(template_filepath: str, **kwargs) -> str:
    """Render a Jinja2 template under this package and return the result as a string.

    Args:
        template_filepath: Path to the template, relative to this package.
        **kwargs: Variables passed to the Jinja template.

    Returns:
        The rendered template content as a string.
    """
    template_dir, template_filename = template_filepath.rsplit("/", 1)
    template_path = Path(__file__).parent / template_dir
    env = Environment(loader=FileSystemLoader(template_path), trim_blocks=True, lstrip_blocks=True, autoescape=True)
    template = env.get_template(template_filename)
    return template.render(**kwargs)


def _record_type_from_class_name(class_name):
    """Strip the trailing ``Record`` suffix to get the DNS record-type string.

    For example ``ARecord`` → ``"A"``, ``AAAARecord`` → ``"AAAA"``,
    ``PTRRecord`` → ``"PTR"``. Class names are stable, whereas
    ``Meta.verbose_name`` is intended for UI display and could be
    localized or renamed without warning.
    """
    if not class_name.endswith("Record"):
        raise ValueError(f"Unexpected record class name: {class_name!r}; expected a *Record subclass")
    return class_name[: -len("Record")]


def _record_type_for(record):
    """Derive the DNS record-type string (e.g. ``"A"``, ``"AAAA"``, ``"PTR"``) from a model instance."""
    return _record_type_from_class_name(type(record).__name__)


def get_records(records_list):
    """Helper function to extract record values from a tuple."""
    records = []
    for record in records_list:
        data = serialize_object_v2(record)
        record_type = _record_type_for(record)
        _, record_name, ttl, value = record_values(data, record_type)
        records.append({"name": record_name, "ttl": ttl, "type": record_type, "value": value})
    return records


class BIND9JobHookReceiver(JobHookReceiver):
    """Job Hook receiver for BIND9."""

    class Meta:
        """Meta class for BIND9JobHookReceiver."""

        name = "BIND9 Job Hook Receiver"
        description = "Job Hook Receiver for BIND9 DNS updates."
        has_sensitive_variables = False
        hidden = True

    # pylint: disable=unused-argument
    def receive_job_hook(self, change, action, changed_object):
        """Run the job to update BIND9 records."""
        bind9 = _bind9_integration()
        parsed_url = urlparse(bind9.remote_url)
        server_name = parsed_url.hostname
        server_port = parsed_url.port or 53

        try:
            key_name = bind9.secrets_group.get_secret_value(
                access_type=SecretsGroupAccessTypeChoices.TYPE_GENERIC,
                secret_type=SecretsGroupSecretTypeChoices.TYPE_USERNAME,
            )
            key_secret = bind9.secrets_group.get_secret_value(
                access_type=SecretsGroupAccessTypeChoices.TYPE_GENERIC,
                secret_type=SecretsGroupSecretTypeChoices.TYPE_TOKEN,
            )
        except Exception as exc:
            raise ValueError(
                f"Failed to retrieve BIND9 credentials from ExternalIntegration '{bind9.name}': {exc}. "
                "Ensure the attached SecretsGroup contains a Generic/Username entry for the "
                "TSIG key name and a Generic/Token entry for the TSIG key secret."
            ) from exc
        model_class = change.changed_object_type.model_class()
        record_type = _record_type_from_class_name(model_class.__name__)
        try:
            zone, record_name, ttl, value = record_values(data=change.object_data_v2, record_type=record_type)
        except (KeyError, TypeError, ValueError) as e:
            self.logger.debug(
                msg=json.dumps(change.object_data_v2, sort_keys=True, indent=4),
                extra={"object": f"{record_type} record change data", "skip_db_logging": True},
            )
            raise ValueError(f"Error extracting record values: {e}") from e

        # Ensure domain-name values are absolute so dnspython does not qualify them to the zone.
        if record_type in _FQDN_VALUED_RECORD_TYPES and value and not value.endswith("."):
            value = f"{value}."

        keyring = dns.tsigkeyring.from_text({key_name: key_secret})
        update = dns.update.Update(zone=zone, keyring=keyring)
        if action == "create":
            update.add(record_name, ttl, record_type, value)
        elif action == "update":
            update.replace(record_name, ttl, record_type, value)
        elif action == "delete":
            update.delete(record_name, record_type)
        else:
            raise ValueError(f"Unknown action: {action}")

        try:
            addr_info = socket.getaddrinfo(server_name, server_port, socket.AF_UNSPEC, socket.SOCK_STREAM)
            resolved_ip = addr_info[0][4][0]
            response = dns.query.tcp(update, where=resolved_ip, port=server_port)
        except AttributeError as e:
            raise AttributeError(f"DNS query failed: {e}") from e
        except ConnectionRefusedError as e:
            raise ConnectionRefusedError(f"Connection to DNS server refused: {e}") from e
        if response.rcode() != 0:
            raise RuntimeError(f"DNS update failed with rcode: {dns.rcode.to_text(response.rcode())}")
        self.logger.info(
            "%sd %s record for `%s.%s` with value `%s`",
            action.capitalize(),
            record_type,
            record_name,
            zone,
            value,
        )


class BIND9TemplatingJob(Job):
    """Generate downloadable BIND9 configuration files from Nautobot data."""

    zones = MultiObjectVar(
        description="Select the DNS zones to include in the configuration.",
        model=dns_models.DNSZone,
        required=False,
    )

    all_zones = BooleanVar(
        description="Select all DNS zones.",
        required=False,
        default=False,
    )

    class Meta:
        """Meta class for BIND9TemplatingJob."""

        name = "BIND9 Configuration Templating"
        description = (
            "Generate BIND9 configuration files (named.conf and zone files) from Nautobot data "
            "and attach them to the job result as downloadable files."
        )
        has_sensitive_variables = False

    def run(self, zones, all_zones):  # pylint: disable=arguments-differ
        """Run the job to generate BIND9 configuration files."""
        # Validate input
        if not zones and not all_zones:
            self.logger.error("Please select at least one zone or choose to include all zones.")
            return
        if zones and all_zones:
            self.logger.error("Please select either specific zones or all zones, not both.")
            return
        if all_zones:
            zones = dns_models.DNSZone.objects.all()

        bind9 = _bind9_integration()
        try:
            key_name = bind9.secrets_group.get_secret_value(
                access_type=SecretsGroupAccessTypeChoices.TYPE_GENERIC,
                secret_type=SecretsGroupSecretTypeChoices.TYPE_USERNAME,
            )
            key_secret = bind9.secrets_group.get_secret_value(
                access_type=SecretsGroupAccessTypeChoices.TYPE_GENERIC,
                secret_type=SecretsGroupSecretTypeChoices.TYPE_TOKEN,
            )
        except Exception as exc:
            raise ValueError(
                f"Failed to retrieve BIND9 credentials from ExternalIntegration '{bind9.name}': {exc}. "
                "Ensure the attached SecretsGroup contains a Generic/Username entry for the "
                "TSIG key name and a Generic/Token entry for the TSIG key secret."
            ) from exc

        # General BIND9 configuration files, attached to the job result for download.
        self.logger.info("Generating BIND9 configuration for the %d selected DNS Zone(s).", len(zones))
        self.create_file("named.conf", render_template("bind9_templates/named.conf.j2"))
        self.create_file("named.conf.options", render_template("bind9_templates/named.conf.options.j2"))
        self.create_file(
            "named.conf.local",
            render_template(
                "bind9_templates/named.conf.local.j2",
                zones=zones,
                bind9_key_name=key_name,
                bind9_key_secret=key_secret,
            ),
        )

        # SOA serial for this render — shared across all zones rendered in this run.
        soa_serial = _generate_soa_serial()

        # Zone-specific configuration files
        for zone in zones:
            if zone.name.endswith(".in-addr.arpa") or zone.name.endswith(".ip6.arpa"):
                self.logger.info("Processing reverse zone: %s", zone.name)
                template_filepath = "bind9_templates/reverse.zone.j2"
                other_records = get_records(list(chain(zone.ptr_records.all())))
            else:
                self.logger.info("Processing forward zone: %s", zone.name)
                template_filepath = "bind9_templates/forward.zone.j2"
                other_records = get_records(
                    list(
                        chain(
                            zone.a_records.all(),
                            zone.aaaa_records.all(),
                            zone.cname_records.all(),
                            zone.srv_records.all(),
                            zone.txt_records.all(),
                        )
                    )
                )
            self.create_file(
                f"{zone.name}.zone",
                render_template(
                    template_filepath,
                    zone=zone,
                    soa_serial=soa_serial,
                    ns_records=get_records(list(zone.ns_records.all())),
                    mx_records=get_records(list(zone.mx_records.all())),
                    other_records=other_records,
                ),
            )
