#!/usr/bin/python3
import os
import socket
import subprocess
import argparse
import sys
from jnpr.junos import Device
from jnpr.junos.utils.config import Config
import re
from argparse import SUPPRESS
from ipaddress import ip_interface
from jnpr.junos.exception import ConnectError, ConnectAuthError
from lxml import etree

try:
    import pexpect
except ImportError:
    pexpect = None

# error indi: Cobbler Create failed for host with error 'cm-macaddress'

# maserati-ci-a: Cobbler Create failed for host with error <Fault 1: "<class 'cobbler.cexceptions.CX'>:
# 'MAC address duplicated: 00:c5:2c:c0:cc:1d'">

# Create argument parser and add host
parser = argparse.ArgumentParser(
    description='DHCP update Utility',
    # usage=SUPPRESS,
    fromfile_prefix_chars='@',
    epilog="Example:\n"
           "  dhcp.py @leaf_list.txt -L\n\n"
           "Use @filename to load hosts from a file."
)

# Parse arguments
parser.add_argument('hosts', metavar='HOST', nargs='+', help='DHCP device hostname(s)')

parser.add_argument("-c","--configure", action="store_true", help="Run cobblerCreate command")

parser.add_argument("-d","--dry-run", action="store_true", help="Print commands without executing")

parser.add_argument("-debug","--debug-console", action="store_true",
                    help="Show live console login output during MAC discovery")

args = parser.parse_args()

# Now you can use the parsed arguments
host = args.hosts

HOME = os.path.expanduser("~")

invalid = []
lf_success = []
dry_run_banner_printed = False
cobbler_failures = []

credentials = [
    {"user": "regress", "password": "MaRtInI"},
    {"user": "admin", "password": "Hpe@2026"},
    {"user": "root", "password": "Da8dyTrUmP"},
    {"user": "root", "password": "Bl8kmAmBa"},
    {"user": "root", "password": "Embe1mpls"},
]

dhcp_tag = "None"

model_map = {
    "acx7024": "LG_S2C-acx-f",
    "acx7100": "LG_S2C-qfx-ms",
    "acx7100-32c": "LG_S2C-acx-f",
    "acx7100-48l": "LG_S2C-acx-f",
    "acx7332": "LG_S2C-acx",
    "acx7348": "LG_S2C-acx",
    "ptx10001-36mr": "LG_S2C-ptx-fixed",
    "ptx10002-36qdd": "LG_S2C-ptx-fixed",
    "ptx10002-60mr": "LG_S2C-PTX10002-60MR",
    "ptx10002-36cd": "LG_S2C-ptx10002-36cd",
    "ptx10003-160c": "LG_S2C-ptx-fixed",
    "ptx10003-80c": "LG_S2C-ptx-fixed",
    "ptx10004": "LG_S2C-ptx",
    "ptx10008": "LG_S2C-ptx",
#    "ptx10008-prem3": "LG_S2C-ptx",
    "ptx10016": "LG_S2C-ptx",
    "ptx12008": "LG_S2C-PTX12008",
    "qfx5130-32cd": "LG_S2C-qfx-ms",
    "qfx5140-24": "LG_S2C-QFX5140",
    "qfx5140-24cd8o": "LG_S2C-QFX5140",
    "qfx5220-128c": "LG_S2C-qfx-ms",
    "qfx5220-32cd": "LG_S2C-qfx-ms",
    "qfx5700": "LG_S2C-qfx-ms",
    "qfx5240-64od": "LG_S2C-qfx-ms"
}


def debug_console_log(message):
    if args.debug_console:
        print(f"[DEBUG-CONSOLE] {message}")


def debug_netconf_endpoint(resource, port=830, timeout=5):
    if not args.debug_console:
        return

    try:
        addrinfo = socket.getaddrinfo(resource, port, type=socket.SOCK_STREAM)
    except socket.gaierror as error:
        debug_console_log(f"{resource}: name resolution failed for port {port}: {error}")
        return

    endpoints = []
    seen = set()
    for family, socktype, proto, canonname, sockaddr in addrinfo:
        host = sockaddr[0]
        key = (family, host)
        if key in seen:
            continue
        seen.add(key)
        endpoints.append((family, host))

    if not endpoints:
        debug_console_log(f"{resource}: no resolved addresses for port {port}")
        return

    debug_console_log(
        f"{resource}: resolved NETCONF endpoint(s) on port {port}: {', '.join(host for _, host in endpoints)}"
    )

    for family, host in endpoints:
        family_name = "IPv6" if family == socket.AF_INET6 else "IPv4"
        debug_console_log(f"{resource}: probing {family_name} {host}:{port}")
        try:
            with socket.create_connection((host, port), timeout=timeout):
                debug_console_log(f"{resource}: TCP connect to {host}:{port} succeeded")
        except OSError as error:
            debug_console_log(f"{resource}: TCP connect to {host}:{port} failed: {error}")


def parse_mac_from_cli(output):
    match = re.search(r'(?:Current|Hardware)\s+address:\s*([0-9a-fA-F:]{17})', output)
    return match.group(1).lower() if match else None


def collect_mac_via_ssh(resource, credential, mgt_inter1):
    if pexpect is None:
        raise RuntimeError("SSH fallback requires pexpect, but it is not installed")

    prompt_pattern = r'[%>#]\s*$'
    last_error = None

    for cred in credential:
        child = None
        try:
            ssh_cmd = (
                "ssh -o StrictHostKeyChecking=no "
                "-o UserKnownHostsFile=/dev/null "
                "-o ConnectTimeout=10 "
                f"{cred['user']}@{resource}"
            )
            debug_console_log(f"{resource}: falling back to SSH CLI as '{cred['user']}'")
            child = pexpect.spawn(ssh_cmd, encoding="utf-8", timeout=20)

            if args.debug_console:
                child.logfile_read = sys.stdout

            while True:
                idx = child.expect([
                    r'(?i)are you sure you want to continue connecting \(yes/no(/\[fingerprint\])?\)\?',
                    r'(?i)password:',
                    prompt_pattern,
                    r'(?i)(authentication failed|login incorrect|permission denied)',
                    pexpect.EOF,
                    pexpect.TIMEOUT,
                ])

                if idx == 0:
                    debug_console_log(f"{resource}: accepting SSH host key for '{cred['user']}'")
                    child.sendline("yes")
                    continue

                if idx == 1:
                    debug_console_log(f"{resource}: SSH password prompt detected for '{cred['user']}'")
                    child.sendline(cred["password"])
                    continue

                if idx == 2:
                    prompt = child.after.strip()[-1] if child.after.strip() else ">"
                    debug_console_log(f"{resource}: SSH prompt detected = {prompt}")

                    if prompt == "#":
                        child.sendline("exit")
                        child.expect(prompt_pattern)
                        prompt = child.after.strip()[-1] if child.after.strip() else ">"

                    if prompt == "%":
                        debug_console_log(f"{resource}: entering Junos CLI from shell")
                        child.sendline("cli")
                        child.expect(r'>\s*$')

                    child.sendline("show version | no-more")
                    child.expect(r'>\s*$')
                    version_output = child.before

                    os_flavor = "EVO" if "EVO" in version_output.upper() else "JUNOS"
                    dhcp_tag = "l2-evopxe" if os_flavor == "EVO" else "K2RE"
                    mac_re0 = None
                    mac_re1 = None

                    if os_flavor == "EVO":
                        for interface_name in ["re0", "re1"]:
                            debug_console_log(
                                f"{resource}: running 'show interfaces {interface_name} extensive | match address'"
                            )
                            child.sendline(
                                f'show interfaces {interface_name} extensive | match "(Current|Hardware) address:"'
                            )
                            child.expect(r'>\s*$')
                            mac_output = child.before
                            mac_value = parse_mac_from_cli(mac_output)
                            if interface_name == "re0":
                                mac_re0 = mac_value
                            else:
                                mac_re1 = mac_value
                    else:
                        if not mgt_inter1:
                            raise ValueError(f"Unable to determine management interface for {resource}")

                        debug_console_log(
                            f"{resource}: running 'show interfaces {mgt_inter1} extensive | match address'"
                        )
                        child.sendline(
                            f'show interfaces {mgt_inter1} extensive | match "(Current|Hardware) address:"'
                        )
                        child.expect(r'>\s*$')
                        mac_re0 = parse_mac_from_cli(child.before)

                    child.sendline("exit")
                    child.expect(prompt_pattern)

                    if child.after.strip().endswith("%"):
                        child.sendline("exit")
                        child.expect(pexpect.EOF)

                    if not mac_re0 and not mac_re1:
                        raise ValueError(f"Unable to parse management MAC address via SSH for {resource}")

                    print(f"{resource}: Login successful via SSH CLI.")
                    return os_flavor, mac_re0, mac_re1, dhcp_tag

                if idx == 3:
                    raise RuntimeError(f"Authentication failed for user '{cred['user']}'")

                if idx == 4:
                    raise RuntimeError("SSH session ended unexpectedly")

                raise RuntimeError("Timed out waiting for SSH prompt")

        except Exception as error:
            last_error = error
            debug_console_log(
                f"{resource}: SSH fallback failed with user '{cred['user']}' ({type(error).__name__}): {error}"
            )
        finally:
            if child is not None and child.isalive():
                child.close(force=True)

    raise Exception(f"All SSH credential attempts failed for {resource}: {last_error}")


def fetch_resource_details(resource, credentials=credentials):
    print(f"[INFO] Fetching details for {resource}...")
    debug_console_log(f"{resource}: starting login attempts with {len(credentials)} credential set(s)")
    debug_netconf_endpoint(resource)
    command = (
        "lrm 'show -t=logical_interface_purpose_name,mac,name,component "
        f"interface(resource_name={resource} logical_interface_purpose_name=mgt)'"
    )

    output = subprocess.check_output(command, shell=True, text=True)
    # print(f"[DEBUG] MGT interface output for {resource}:\n{output}")

    mac_re0 = None
    mac_re1 = None
    mgt_inter1 = None
    mgt_inter2 = None

    for raw_line in output.splitlines():
        if "|" not in raw_line:
            continue

        columns = [col.strip() for col in raw_line.strip().strip("|").split("|")]
        if len(columns) < 4:
            continue

        if columns[0].lower() == "logical_interface_purpose_name":
            continue
        if columns[0].startswith("-"):
            continue

        # mac = columns[1]
        name = columns[2]
        component = columns[3].lower()
        base_name = name.split(".")[0]

        if component == "re0" or component == "if0":
            # mac_re0 = mac
            mgt_inter1 = base_name
        elif component == "re1":
            # mac_re1 = mac
            mgt_inter2 = base_name

    # print(f"[INFO] mgt_inter1={mgt_inter1}, mgt_inter2={mgt_inter2}")
    last_error = None
    netconf_port = 830
    for cred in credentials:
        try:
            debug_console_log(
                f"{resource}: opening NETCONF session to {resource}:{netconf_port} as '{cred['user']}'"
            )
            dev = Device(
                host=resource,
                user=cred["user"],
                password=cred["password"],
                port=netconf_port,
                timeout=20,
            )
            dev.open()
            print(f"{resource}: Login successful.")
            debug_console_log(f"{resource}: console login succeeded with user '{cred['user']}'")

            rsp = dev.rpc.get_software_information()
            version = rsp.findtext(".//junos-version")
            # print(etree.tostring(version, pretty_print=True).decode())

             
            if "EVO" in version.upper():
                os_flavor = "EVO"
                dhcp_tag = "l2-evopxe"

            else:
                os_flavor = "JUNOS"
                dhcp_tag = "K2RE"
            
            if os_flavor == "EVO":
                rsp = dev.rpc.get_interface_information(interface_name='re*')
                for phy in rsp.findall(".//physical-interface"):
                    name_elem = phy.find("name")
                    mac_elem = phy.find("current-physical-address")

                    if name_elem is None or mac_elem is None:
                        continue

                    name_text = name_elem.text.strip()
                    mac_text = mac_elem.text.strip()

                    if name_text.startswith("re0:"):
                        mac_re0 = mac_text

                    elif name_text.startswith("re1:"):
                        mac_re1 = mac_text

            else:
                if not mgt_inter1:
                    raise ValueError(
                        f"Unable to determine management interface for {resource}"
                    )

                rsp = dev.rpc.get_interface_information(interface_name=mgt_inter1)
                for phy in rsp.findall(".//physical-interface"):
                    mac_elem = phy.find("current-physical-address")
                    if mac_elem is not None:
                        mac_re0 = mac_elem.text.strip()
                        break

            dev.close()
            return os_flavor, mac_re0, mac_re1, dhcp_tag

        except Exception as e:
            last_error = e
            debug_console_log(
                f"{resource}: login failed with user '{cred['user']}' ({type(e).__name__}): {e}"
            )
            print(f"{resource}: Login failed with {cred['user']}: {e}")

    debug_console_log(f"{resource}: NETCONF login failed, trying SSH CLI fallback")

    ssh_fallback_error = None
    try:
        return collect_mac_via_ssh(resource, credentials, mgt_inter1)
    except Exception as ssh_error:
        ssh_fallback_error = ssh_error
        debug_console_log(f"{resource}: SSH CLI fallback failed: {ssh_error}")

    debug_console_log(f"{resource}: all login attempts failed")

    final_error = ssh_fallback_error if ssh_fallback_error is not None else last_error
    raise Exception(f"All credential attempts failed for {resource}: {final_error}")


def extract_cobbler_error(output_text):
    lower_output = output_text.lower()

    if "cm-macaddress" in lower_output:
        return "cm-macaddress"

    duplicate_match = re.search(r"MAC address duplicated:\s*([0-9a-f:]{17})", output_text, re.IGNORECASE)
    if duplicate_match:
        return f"MAC address duplicated: {duplicate_match.group(1).lower()}"

    if "mac address duplicated" in lower_output:
        return "MAC address duplicated"

    return None


def run_command(cmd, resource=None):
    print(f"[RUN] {cmd}")
    result = subprocess.run(cmd, shell=True, text=True,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE)

    is_evo_pxe_cmd = cmd.strip().startswith("/volume/evopxe/tools/evo-pxe-setup")
    has_setting_device_output = "Setting device" in (result.stdout or "")

    # evo-pxe-setup can return 1 even after successfully wiring device boot entries.
    if result.returncode != 0 and is_evo_pxe_cmd and has_setting_device_output and not result.stderr:
        print(result.stdout)
        # print("[INFO] evo-pxe-setup completed: treating as success")
        return

    if result.returncode != 0:
        print(f"[ERROR] Command failed with exit code {result.returncode}")
        if result.stderr:
            print(f"[ERROR] {result.stderr}")
        elif result.stdout:
            print("[ERROR] stderr was empty; command output was:")
            print(result.stdout)
        else:
            print("[ERROR] Command produced no output")
    else:
        print(result.stdout)

    if cmd.strip().startswith("cobblerCreate.py"):
        output_text = "\n".join(part for part in [result.stdout, result.stderr] if part)
        detected_error = extract_cobbler_error(output_text)
        if detected_error:
            host = resource if resource else "unknown-host"
            failure_message = f"{host}: Cobbler Create failed for host with error '{detected_error}'"
            cobbler_failures.append(failure_message)
            print(f"[COBBLER-ERROR] {failure_message}")


def iter_input_lines(inputs):
    for value in inputs:
        if value.startswith('@'):
            file_path = value[1:]
            with open(file_path, 'r') as infile:
                for line in infile:
                    stripped_line = line.strip()
                    if stripped_line:
                        yield stripped_line
            continue

        yield value


for line in iter_input_lines(args.hosts):
    parts = line.strip().split()
    has_prefilled_fields = False

    if not parts:
        continue

    resource = parts[0]

    command = f"lrm 'show resource(name={resource})'"

    res_output = subprocess.check_output(command, shell=True)
    res_output = res_output.decode('utf-8')
    model_match = re.search(r"(?im)^\s*model:\s*(\S+)", res_output)
    model = model_match.group(1) if model_match else None
    # print(f"[DEBUG] Output for {resource}:\n{res_output}")
    # dhcp_tag_match = re.search(r"cm-dhcp-tag:\s*(\S+)", res_output)
    # dhcp_tag = dhcp_tag_match.group(1) if dhcp_tag_match else None

    if "0 records found" in res_output:
        invalid.append(resource)
        print(f"{resource}: Not a valid host")
        continue

    elif "Sabey Bldg A" in res_output:
        cobbler = "q-cobbler01"

    elif "Sabey Bldg E" in res_output:
        cobbler = "q-cobbler02"

    else:
        cobbler = None

    # Case 1: full data
    if len(parts) >= 4:
        has_prefilled_fields = True
        os_flavor = parts[1]
        cm_dhcp_tag = parts[2]
        mac_re0 = parts[3].lower().replace("-", ":")
        mac_re1 = parts[4].lower().replace("-", ":") if len(parts) > 4 else None
        mgt_inter1 = None
        mgt_inter2 = None

    # Case 2: only hostname
    elif len(parts) == 1:
        os_flavor, mac_re0, mac_re1, dhcp_tag = fetch_resource_details(resource)
        cm_dhcp_tag = dhcp_tag

    else:
        print(f"[WARN] Skipping invalid line: {line.strip()}")
        continue

    if str(os_flavor).upper() != "EVO" and not has_prefilled_fields:
        print(f"[ERROR] {resource}: detected non-EVO os_flavor '{os_flavor}'.")
        print("[ERROR] This script currently supports EVO only. Halting execution.")
        sys.exit(2)

    if str(os_flavor).upper() != "EVO" and has_prefilled_fields:
        print(
            f"[WARN] {resource}: using pre-filled fields from input file with non-EVO os_flavor '{os_flavor}'."
        )

    model_tag = cm_dhcp_tag
    model_is_evo = str(model).strip().lower() == "evo"
    missing_model_tag = model_tag is None or str(model_tag).strip().lower() in {
        "",
        "none",
        "null",
        "n/a",
        "na",
        "-",
    }
    if model_is_evo and missing_model_tag:
        print(
            f"[WARN] {resource}: model_tag is missing for EVO model, check if DARE is supported."
        )

    # Build commands list
    commands = [
        f"lrm 'add resource_property(property_attribute=auto_recovery_type property_value=DARE "
        f"resource_name={resource})'",
        f"lrm 'add resource_property(property_attribute=cm-profile property_value=l2-junos "
        f"resource_name={resource})'",
        f"lrm 'add resource_property(property_attribute=cm-domain property_value=glo "
        f"resource_name={resource})'",
        f"lrm 'update resource(name={resource}) os_flavor={os_flavor}'",
        f"lrm 'add resource_property(property_attribute=cm-dhcp-tag resource_name={resource} "
        f"property_value={cm_dhcp_tag})'",
        f"lrm 'update resource_property(property_attribute=cm-dhcp-tag resource_name={resource}) "
        f"property_value={cm_dhcp_tag}'"
    ]

    if mac_re0:
        commands.append(
            f"lrm 'update interface(resource_name={resource} logical_interface_purpose_name=mgt component=re0) "
            f"mac={mac_re0}'"
        )

    if mac_re1:
        commands.append(
            f"lrm 'update interface(resource_name={resource} logical_interface_purpose_name=mgt component=re1) "
            f"mac={mac_re1}'"
        )

    if args.configure:
        if not cobbler:
            print(f"[WARN] Skipping cobblerCreate for {resource}: unable to determine cobbler server")
        else:
            commands.append(
                f"cobblerCreate.py --cobblerServer {cobbler} {resource}"
            )

    if os_flavor == "EVO" or os_flavor == "evo":
        evo_profile = model_map.get(model.lower()) if model else None

        if evo_profile:
            commands.append(
                f"/volume/evopxe/tools/evo-pxe-setup -D {resource} -t AR -n {evo_profile}"
            )
        else:
            print(f"[WARN] Unable to map model '{model}' to evo profile for {resource}")

    # Execute commands
    if args.dry_run and not dry_run_banner_printed:
        print("[DRY-RUN] Commands that would be executed:")
        dry_run_banner_printed = True

    for cmd in commands:
        if args.dry_run:
            print(f"{cmd}")
        else:
            run_command(cmd, resource=resource)


if cobbler_failures:
    print("\n[SUMMARY] Cobbler create errors detected:")
    for failure in cobbler_failures:
        print(f" - {failure}")