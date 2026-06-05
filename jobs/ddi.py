"""Jobs to manage DDI objects."""
# pylint: disable=too-few-public-methods

import json
import os
from datetime import datetime, timezone
from itertools import chain
from pathlib import Path
from socket import gethostbyname
from urllib.parse import urlparse

import dns.query
import dns.tsigkeyring
import dns.update
from jinja2 import Environment, FileSystemLoader
from nautobot.apps.jobs import BooleanVar, Job, JobHookReceiver, MultiObjectVar, register_jobs
from nautobot.extras.choices import SecretsGroupAccessTypeChoices, SecretsGroupSecretTypeChoices
from nautobot.extras.models import ExternalIntegration
from nautobot.core.models.utils import serialize_object_v2
from nautobot_dns_models import models as dns_models

from . import models as ddi_models

JOB_GROUP_NAME = "Nautobot DDI Jobs"
name = JOB_GROUP_NAME  # pylint: disable=invalid-name


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
            value = data["address"]["host"]
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
            record_name = data["ptrdname"].split(".")[0]
            value = data["name"]
        case "TXT":
            record_name = data["name"]
            value = data["text"]
        case _:
            raise ValueError(f"Unsupported record type: {record_type}")
    return zone, record_name, ttl, value


def render_file(
    template_filepath: str,
    output_filepath: str,
    output_root: str | None = None,
    output_root_env_var: str = "BIND9_TEMPLATING_OUTPUTS",
    output_root_default: str = "/etc/bind/",
    **kwargs,
):
    """Render a Jinja2 template under this package to a file on disk.

    Writes atomically: the rendered output is staged to a sibling
    ``*.tmp`` file and then ``Path.replace()``'d into the final
    location. A crash mid-render therefore cannot leave the operator
    with a truncated or missing output file.

    Args:
        template_filepath: Path to the template, relative to this package.
        output_filepath: Path of the rendered file, relative to ``output_root``.
        output_root: Override for the output base directory. When ``None``
            the helper reads ``output_root_env_var`` from the environment,
            falling back to ``output_root_default``.
        output_root_env_var: Environment variable to read for the output root
            when ``output_root`` is omitted. Defaults to BIND9; KEA jobs pass
            ``"KEA_TEMPLATING_OUTPUTS"``.
        output_root_default: Last-resort fallback if neither ``output_root``
            nor the environment variable is set.
        **kwargs: Variables passed to the Jinja template.
    """
    if output_root is None:
        output_root = os.environ.get(output_root_env_var, output_root_default)

    template_dir, template_filename = template_filepath.rsplit("/", 1)
    template_path = Path(__file__).parent / template_dir
    env = Environment(loader=FileSystemLoader(template_path), trim_blocks=True, lstrip_blocks=True, autoescape=True)
    template = env.get_template(template_filename)

    output_dirname, output_filename = (output_root + output_filepath).rsplit("/", 1)
    output_dir = Path(output_dirname)
    output_dir.mkdir(parents=True, exist_ok=True)
    output_path = output_dir / output_filename
    tmp_path = output_path.with_name(f"{output_filename}.tmp")
    tmp_path.write_text(template.render(**kwargs))
    tmp_path.replace(output_path)


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


def _kea_default_settings():
    """Return KEA-related default lifetimes/timers from environment variables."""
    return {
        "default_valid_lifetime": int(os.environ.get("KEA_DEFAULT_VALID_LIFETIME", 3600)),
        "default_renew_timer": int(os.environ.get("KEA_DEFAULT_RENEW_TIMER", 900)),
        "default_rebind_timer": int(os.environ.get("KEA_DEFAULT_REBIND_TIMER", 1800)),
    }


def _serialize_subnet_for_kea(subnet):
    """Translate a ``DHCPSubnet`` (with prefetched pools/reservations) to template kwargs."""
    return {
        "subnet_id": subnet.subnet_id,
        "prefix": str(subnet.prefix.prefix),
        "valid_lifetime": subnet.valid_lifetime,
        "renew_timer": subnet.renew_timer,
        "rebind_timer": subnet.rebind_timer,
        "interface": subnet.interface,
        "pools": [{"start": p.start, "end": p.end} for p in subnet.pools.all()],
        "reservations": [
            {
                "identifier_type": r.identifier_type,
                "identifier_value": r.identifier_value,
                "ip_address": str(r.ip_address.host) if r.ip_address_id else "",
                "hostname": r.hostname,
            }
            for r in subnet.reservations.all()
            if r.ip_address_id
        ],
    }


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
            response = dns.query.tcp(update, where=gethostbyname(server_name), port=server_port)
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
    """Generate BIND9 configuration files from Nautobot data."""

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
        description = "Generate BIND9 configuration files from Nautobot data."
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

        # General BIND9 configuration files
        self.logger.info("Generating BIND9 configuration for the %d selected DNS Zone(s).", len(zones))
        render_file(template_filepath="bind9_templates/named.conf.j2", output_filepath="named.conf")
        render_file(template_filepath="bind9_templates/named.conf.options.j2", output_filepath="named.conf.options")
        render_file(
            template_filepath="bind9_templates/named.conf.local.j2",
            output_filepath="named.conf.local",
            zones=zones,
            bind9_key_name=key_name,
            bind9_key_secret=key_secret,
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
            render_file(
                template_filepath=template_filepath,
                output_filepath=f"zones/{zone.name}.zone",
                zone=zone,
                soa_serial=soa_serial,
                ns_records=get_records(list(zone.ns_records.all())),
                mx_records=get_records(list(zone.mx_records.all())),
                other_records=other_records,
            )