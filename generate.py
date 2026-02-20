#!/usr/bin/env python3
"""Generate zsh completion files for Monero CLI tools from C++ source code.

Usage: python3 generate.py <monero-source-dir> [output-dir]

Parses arg_descriptor definitions, set_handler calls, and add_arg registrations
from the Monero C++ source to produce deterministic zsh completion files.
"""

import os
import re
import sys
from collections import OrderedDict


# --- Regex patterns for C++ parsing ---

# Match: const command_line::arg_descriptor<TYPE> name = {"option-name", ...};
# Also matches with extra template params like <TYPE, false, true, 2>
ARG_DESCRIPTOR_RE = re.compile(
    r'arg_descriptor\s*<\s*'
    r'((?:std::)?[a-zA-Z_][\w:]*(?:\s*<\s*(?:std::)?[a-zA-Z_][\w:]*\s*>)?)'  # type
    r'(?:\s*,\s*[^>]*)?\s*>'  # optional extra template params
    r'\s+([\w:]+)\s*=\s*\{'   # variable name (may be qualified with ::)
    r'\s*"([^"]*)"'            # option name in quotes
    r'(.*?)\}\s*;',            # rest of initializer
    re.DOTALL
)

# Match function-defined arg_descriptors like in wallet_args.cpp:
# command_line::arg_descriptor<T> func_name() { return {"name", ...}; }
FUNC_ARG_RE = re.compile(
    r'arg_descriptor\s*<\s*'
    r'((?:std::)?[a-zA-Z_][\w:]*(?:\s*<\s*(?:std::)?[a-zA-Z_][\w:]*\s*>)?)'
    r'(?:\s*,\s*[^>]*)?\s*>'
    r'\s+(\w+)\s*\(\s*\)\s*\{'
    r'\s*return\s*\{\s*"([^"]*)"'
    r'(.*?)\}\s*;',
    re.DOTALL
)

# Match rpc_args constructor initialization:
# , member_name({"option-name", rpc_args::tr("description"), default})
RPC_CONSTRUCTOR_RE = re.compile(
    r',\s*(\w+)\s*\(\s*\{\s*"([^"]+)"\s*,\s*'
    r'rpc_args::tr\(\s*"((?:[^"\\]|\\.)*)"\s*\)'
    r'(.*?)\}\s*\)',
    re.DOTALL
)

# First member (uses : instead of ,)
RPC_CONSTRUCTOR_FIRST_RE = re.compile(
    r':\s*(\w+)\s*\(\s*\{\s*"([^"]+)"\s*,\s*'
    r'rpc_args::tr\(\s*"((?:[^"\\]|\\.)*)"\s*\)'
    r'(.*?)\}\s*\)',
    re.DOTALL
)


# --- Lookup tables ---

# Labels for value-taking options (used in zsh completion spec after the description)
OPTION_LABELS = {
    'config-file': 'config file',
    'log-file': 'log file',
    'log-level': 'log level',
    'max-log-file-size': 'size (bytes)',
    'max-log-files': 'count',
    'max-concurrency': 'threads',
    'proxy': 'proxy (ip\\:port)',
    'data-dir': 'data directory',
    'block-download-max-size': 'size (bytes)',
    'span-limit': 'minutes',
    'test-drop-download-height': 'height',
    'test-dbg-lock-sleep': 'time (ms)',
    'fixed-difficulty': 'difficulty',
    'fast-block-sync': 'enabled (1 or 0)',
    'prep-blocks-threads': 'threads',
    'show-time-stats': 'enabled (1 or 0)',
    'block-sync-size': 'blocks',
    'batch-max-weight': 'megabytes',
    'max-txpool-weight': 'weight (bytes)',
    'block-notify': 'command',
    'reorg-notify': 'command',
    'block-rate-notify': 'command',
    'db-sync-mode': 'mode',
    'p2p-bind-ip': 'IP address',
    'p2p-bind-ipv6-address': 'IPv6 address',
    'p2p-bind-port': 'port',
    'p2p-bind-port-ipv6': 'port',
    'p2p-external-port': 'port',
    'add-peer': 'peer (ip\\:port)',
    'add-priority-node': 'peer (ip\\:port)',
    'add-exclusive-node': 'peer (ip\\:port)',
    'seed-node': 'peer (ip\\:port)',
    'tx-proxy': 'proxy config',
    'anonymous-inbound': 'inbound config',
    'ban-list': 'ban list file',
    'out-peers': 'count',
    'in-peers': 'count',
    'tos-flag': 'flag',
    'limit-rate-up': 'rate (kB/s)',
    'limit-rate-down': 'rate (kB/s)',
    'limit-rate': 'rate (kB/s)',
    'max-connections-per-ip': 'count',
    'rpc-bind-ip': 'IP address',
    'rpc-bind-ipv6-address': 'IPv6 address',
    'rpc-restricted-bind-ip': 'IP address',
    'rpc-restricted-bind-ipv6-address': 'IPv6 address',
    'rpc-bind-port': 'port',
    'rpc-restricted-bind-port': 'port',
    'rpc-login': 'credentials (user\\:pass)',
    'rpc-access-control-origins': 'origins',
    'rpc-ssl-allowed-fingerprints': 'fingerprint',
    'bootstrap-daemon-address': 'URL',
    'bootstrap-daemon-login': 'credentials (user\\:pass)',
    'bootstrap-daemon-proxy': 'proxy (ip\\:port)',
    'rpc-payment-address': 'Monero address',
    'rpc-payment-difficulty': 'difficulty',
    'rpc-payment-credits': 'credits',
    'rpc-max-connections-per-public-ip': 'count',
    'rpc-max-connections-per-private-ip': 'count',
    'rpc-max-connections': 'count',
    'rpc-response-soft-limit': 'bytes',
    'zmq-rpc-bind-ip': 'IP address',
    'zmq-rpc-bind-port': 'port',
    'zmq-pub': 'address',
    'start-mining': 'Monero address',
    'mining-threads': 'threads',
    'extra-messages-file': 'file',
    'bg-mining-min-idle-interval': 'seconds',
    'bg-mining-idle-threshold': 'percentage',
    'bg-mining-miner-target': 'percentage',
    'pidfile': 'pid file',
    # Wallet options
    'wallet-file': 'wallet file',
    'generate-new-wallet': 'wallet file',
    'generate-from-device': 'wallet file',
    'generate-from-view-key': 'wallet file',
    'generate-from-spend-key': 'wallet file',
    'generate-from-keys': 'wallet file',
    'generate-from-multisig-keys': 'wallet file',
    'generate-from-json': 'JSON file',
    'electrum-seed': 'mnemonic seed',
    'restore-height': 'block height',
    'restore-date': 'date (YYYY-MM-DD)',
    'subaddress-lookahead': 'lookahead (major\\:minor)',
    'mnemonic-language': 'language',
    'daemon-address': 'daemon address (host\\:port)',
    'daemon-host': 'hostname',
    'daemon-port': 'port',
    'daemon-login': 'credentials (user\\:pass)',
    'daemon-ssl-allowed-fingerprints': 'fingerprint',
    'password': 'password',
    'password-file': 'password file',
    'shared-ringdb-dir': 'directory',
    'kdf-rounds': 'rounds',
    'hw-device': 'device',
    'hw-device-deriv-path': 'derivation path',
    'tx-notify': 'command',
    'extra-entropy': 'entropy file',
    'bitmessage-address': 'URL',
    'bitmessage-login': 'credentials (user\\:pass)',
    # Wallet RPC options
    'wallet-dir': 'wallet directory',
    # Blockchain utility options
    'input-file': 'input file',
    'output-file': 'output file',
    'block-start': 'block height',
    'block-stop': 'block height',
    'batch-size': 'batch size',
    'pop-blocks': 'number of blocks',
    'spent-output-db-dir': 'database directory',
    'extra-spent-list': 'file',
    'export': 'file',
    'txid': 'transaction hash',
    'output': 'amount/offset',
    'height': 'block height',
    'input': 'input file',
    # Gen multisig
    'filename-base': 'filename base',
    'scheme': 'scheme (M/N)',
    'threshold': 'threshold',
    'participants': 'participants',
    # Gen SSL cert
    'certificate-filename': 'certificate file',
    'private-key-filename': 'key file',
    'passphrase': 'passphrase',
    'passphrase-file': 'passphrase file',
}

# Options that take enum values: option-name -> (value1 value2 ...)
ENUM_OPTIONS = {
    'check-updates': '(disabled notify download update)',
    'igd': '(disabled enabled delayed)',
    'rpc-ssl': '(enabled disabled autodetect)',
    'daemon-ssl': '(enabled disabled autodetect)',
}

# Options whose values are files
FILE_LABELS = {
    'config-file', 'log-file', 'pidfile', 'ban-list',
    'rpc-ssl-private-key', 'rpc-ssl-certificate', 'rpc-ssl-ca-certificates',
    'extra-messages-file',
    'wallet-file', 'generate-new-wallet', 'generate-from-device',
    'generate-from-view-key', 'generate-from-spend-key',
    'generate-from-keys', 'generate-from-multisig-keys',
    'generate-from-json', 'password-file',
    'daemon-ssl-private-key', 'daemon-ssl-certificate',
    'daemon-ssl-ca-certificates', 'extra-entropy',
    'input-file', 'output-file', 'extra-spent-list', 'export',
    'input',
    'filename-base', 'certificate-filename', 'private-key-filename',
    'passphrase-file',
}

# Options whose values are directories
DIR_LABELS = {
    'data-dir', 'shared-ringdb-dir', 'wallet-dir', 'spent-output-db-dir',
}

# Network exclusion groups
NETWORK_EXCLUSIONS = {
    'testnet': '(--stagenet --regtest)',
    'stagenet': '(--testnet --regtest)',
    'regtest': '(--testnet --stagenet)',
}

# Wallet-only network exclusions (no regtest)
WALLET_NETWORK_EXCLUSIONS = {
    'testnet': '(--stagenet)',
    'stagenet': '(--testnet)',
}

# Positional arguments to filter out (they don't use --)
POSITIONAL_ARGS = {
    'daemon_command', 'command', 'inputs',
}


def extract_string_literals(text):
    """Extract and concatenate adjacent C++ string literals from text.

    Handles patterns like: "foo" "bar" -> "foobar"
    Also strips tr() and sw::tr() wrappers.
    """
    # Remove tr() / sw::tr() / genms::tr() / gencert::tr() / wallet_args::tr() wrappers
    text = re.sub(r'(?:\w+::)*tr\s*\(\s*("(?:[^"\\]|\\.)*"(?:\s*"(?:[^"\\]|\\.)*")*)\s*\)', r'\1', text)

    # Find all string literals and concatenate adjacent ones
    strings = re.findall(r'"((?:[^"\\]|\\.)*)"', text)
    return ''.join(strings)


def parse_arg_descriptors(source_text):
    """Parse arg_descriptor definitions from C++ source text.

    Returns dict: option_name -> {name, type, description, is_vector, is_bool}
    """
    args = OrderedDict()

    for m in ARG_DESCRIPTOR_RE.finditer(source_text):
        cpp_type = m.group(1).strip()
        var_name = m.group(2).strip()
        opt_name = m.group(3).strip()
        rest = m.group(4).strip()

        # Skip hidden/positional args
        if var_name in POSITIONAL_ARGS or opt_name in POSITIONAL_ARGS:
            continue
        if opt_name == 'daemon_command':
            continue

        is_vector = 'vector' in cpp_type
        is_bool = cpp_type == 'bool'

        # Extract description from rest
        desc = ''
        if rest.startswith(','):
            rest = rest[1:].strip()
            desc = extract_string_literals(rest)
            # The description is the first string; defaults come after
            # But extract_string_literals gets all - we want just the description part
            # Re-parse: after the option name, next quoted string(s) are description
            desc_match = re.search(r'(?:(?:\w+::)*tr\s*\(\s*)?("(?:[^"\\]|\\.)*"(?:\s*"(?:[^"\\]|\\.)*")*)', rest)
            if desc_match:
                desc = extract_string_literals(desc_match.group(0))

        if opt_name and opt_name != 'Hidden':
            args[opt_name] = {
                'name': opt_name,
                'type': cpp_type,
                'description': desc,
                'is_vector': is_vector,
                'is_bool': is_bool,
                'var_name': var_name,
            }

    # Also match function-defined arg_descriptors
    for m in FUNC_ARG_RE.finditer(source_text):
        cpp_type = m.group(1).strip()
        func_name = m.group(2).strip()
        opt_name = m.group(3).strip()
        rest = m.group(4).strip()

        is_vector = 'vector' in cpp_type
        is_bool = cpp_type == 'bool'

        desc = ''
        if rest.startswith(','):
            rest = rest[1:].strip()
            desc_match = re.search(r'(?:(?:\w+::)*tr\s*\(\s*)?("(?:[^"\\]|\\.)*"(?:\s*"(?:[^"\\]|\\.)*")*)', rest)
            if desc_match:
                desc = extract_string_literals(desc_match.group(0))

        if opt_name:
            args[opt_name] = {
                'name': opt_name,
                'type': cpp_type,
                'description': desc,
                'is_vector': is_vector,
                'is_bool': is_bool,
                'var_name': func_name,
            }

    return args


def parse_rpc_args(rpc_args_h_text, rpc_args_cpp_text):
    """Parse rpc_args from the header (types) and cpp (constructor initialization).

    Returns dict: option_name -> {name, type, description, is_vector, is_bool}
    """
    # Parse types from header
    member_types = {}
    for m in re.finditer(
        r'const\s+command_line::arg_descriptor\s*<\s*'
        r'((?:std::)?[a-zA-Z_][\w:]*(?:\s*<\s*(?:std::)?[a-zA-Z_][\w:]*\s*>)?)'
        r'(?:\s*,\s*[^>]*)?\s*>\s+'
        r'(\w+)\s*;',
        rpc_args_h_text
    ):
        cpp_type = m.group(1).strip()
        member_name = m.group(2).strip()
        member_types[member_name] = cpp_type

    # Parse constructor initialization from cpp
    args = OrderedDict()

    # First member uses ':'
    m = RPC_CONSTRUCTOR_FIRST_RE.search(rpc_args_cpp_text)
    if m:
        member_name = m.group(1).strip()
        opt_name = m.group(2).strip()
        desc = m.group(3).strip()
        cpp_type = member_types.get(member_name, 'std::string')
        is_bool = cpp_type == 'bool'
        is_vector = 'vector' in cpp_type
        args[opt_name] = {
            'name': opt_name,
            'type': cpp_type,
            'description': desc,
            'is_vector': is_vector,
            'is_bool': is_bool,
            'var_name': member_name,
        }

    # Remaining members use ','
    for m in RPC_CONSTRUCTOR_RE.finditer(rpc_args_cpp_text):
        member_name = m.group(1).strip()
        opt_name = m.group(2).strip()
        desc = m.group(3).strip()
        cpp_type = member_types.get(member_name, 'std::string')
        is_bool = cpp_type == 'bool'
        is_vector = 'vector' in cpp_type
        args[opt_name] = {
            'name': opt_name,
            'type': cpp_type,
            'description': desc,
            'is_vector': is_vector,
            'is_bool': is_bool,
            'var_name': member_name,
        }

    return args


def extract_balanced_call(text, start_pos):
    """Extract text within balanced parentheses starting at start_pos.

    start_pos should point to the opening '('.
    Returns the content between the outermost parens (excluding them).
    """
    if start_pos >= len(text) or text[start_pos] != '(':
        return ''
    depth = 0
    i = start_pos
    while i < len(text):
        if text[i] == '(':
            depth += 1
        elif text[i] == ')':
            depth -= 1
            if depth == 0:
                return text[start_pos + 1:i]
        i += 1
    return text[start_pos + 1:]


def parse_set_handlers_balanced(source_text):
    """Parse set_handler calls using balanced parenthesis matching.

    Returns list of (command_name, description) tuples.
    """
    commands = []
    pattern = re.compile(r'set_handler\s*\(')

    for m in pattern.finditer(source_text):
        paren_start = m.end() - 1  # position of '('
        body = extract_balanced_call(source_text, paren_start)
        if not body:
            continue

        # Extract string literals from the body
        strings = re.findall(r'"((?:[^"\\]|\\.)*)"', body)
        if not strings:
            continue

        cmd_name = strings[0]

        # The description is the last string (or second-to-last if there's a usage string)
        # set_handler("name", callback, "description")
        # set_handler("name", callback, "usage", "description")
        # We want the last quoted string as description
        if len(strings) >= 2:
            desc = strings[-1]
        else:
            desc = cmd_name

        commands.append((cmd_name, desc))

    return commands


def read_file(path):
    """Read a file and return its contents, or empty string if not found."""
    try:
        with open(path, 'r', encoding='utf-8', errors='replace') as f:
            return f.read()
    except FileNotFoundError:
        print(f"Warning: file not found: {path}", file=sys.stderr)
        return ''


def escape_zsh(text):
    """Escape special characters for zsh completion descriptions."""
    text = text.replace("'", "'\\''")
    text = text.replace('[', '\\[').replace(']', '\\]')
    text = text.replace('(', '\\(').replace(')', '\\)')
    text = text.replace('{', '\\{').replace('}', '\\}')
    text = text.replace('`', '\\`')
    text = text.replace('"', '\\"')
    text = text.replace('$', '\\$')
    text = text.replace(':', '\\:')
    # Collapse whitespace
    text = re.sub(r'\s+', ' ', text).strip()
    return text


def format_option(opt, network_exclusions=None):
    """Format a single option as a zsh completion spec line.

    Returns the formatted string like:
      '--option-name=[Description]:label:action'
    """
    name = opt['name']
    desc = opt.get('description', '') or name
    is_bool = opt.get('is_bool', False)
    is_vector = opt.get('is_vector', False)

    # Clean up description: take first sentence, strip newlines
    desc = re.sub(r'\s+', ' ', desc).strip()
    # Truncate long descriptions at first period or newline
    if '. ' in desc:
        desc = desc[:desc.index('. ') + 1]

    escaped_desc = escape_zsh(desc)

    # Build the prefix
    prefix = ''

    # help and version are exclusive with everything
    if name in ('help', 'version'):
        prefix = '(- *)'
    elif network_exclusions and name in network_exclusions:
        prefix = network_exclusions[name]

    # Repeatable (vector) args get * prefix
    if is_vector:
        prefix = '*'

    if is_bool:
        # Bool flag: no value
        if prefix:
            return f"    '{prefix}--{name}[{escaped_desc}]'"
        else:
            return f"    '--{name}[{escaped_desc}]'"
    else:
        # Value option
        label = OPTION_LABELS.get(name, '')
        if not label:
            label = name

        # Check for enum values
        if name in ENUM_OPTIONS:
            action = ENUM_OPTIONS[name]
            suffix = f':{label}:{action}'
        elif name in FILE_LABELS:
            suffix = f':{label}:_files'
        elif name in DIR_LABELS:
            suffix = f':{label}:_directories'
        else:
            suffix = f':{label}'

        if prefix:
            return f"    '{prefix}--{name}=[{escaped_desc}]{suffix}'"
        else:
            return f"    '--{name}=[{escaped_desc}]{suffix}'"


def format_subcommand(name, desc):
    """Format a subcommand for the commands array."""
    # Escape single quotes in description
    desc = desc.replace("'", "'\\''")
    # Clean up: first sentence, collapse whitespace
    desc = re.sub(r'\s+', ' ', desc).strip()
    if '. ' in desc:
        desc = desc[:desc.index('. ')]
    # Remove trailing period
    desc = desc.rstrip('.')
    return f"    '{name}:{desc}'"


# --- Per-tool option collectors ---

def collect_monerod_options(src_dir):
    """Collect all options for monerod."""
    options = OrderedDict()

    # common/command_line.cpp: help, version
    text = read_file(os.path.join(src_dir, 'src/common/command_line.cpp'))
    for opt in parse_arg_descriptors(text).values():
        options[opt['name']] = opt

    # daemon/command_line_args.h
    text = read_file(os.path.join(src_dir, 'src/daemon/command_line_args.h'))
    for opt in parse_arg_descriptors(text).values():
        options[opt['name']] = opt

    # daemonizer args
    text = read_file(os.path.join(src_dir, 'src/daemonizer/posix_daemonizer.inl'))
    for opt in parse_arg_descriptors(text).values():
        options[opt['name']] = opt

    text = read_file(os.path.join(src_dir, 'src/daemonizer/daemonizer.h'))
    for opt in parse_arg_descriptors(text).values():
        options[opt['name']] = opt

    # cryptonote_core/cryptonote_core.cpp
    text = read_file(os.path.join(src_dir, 'src/cryptonote_core/cryptonote_core.cpp'))
    for opt in parse_arg_descriptors(text).values():
        options[opt['name']] = opt

    # blockchain_db/blockchain_db.cpp
    text = read_file(os.path.join(src_dir, 'src/blockchain_db/blockchain_db.cpp'))
    for opt in parse_arg_descriptors(text).values():
        options[opt['name']] = opt

    # p2p/net_node.cpp
    text = read_file(os.path.join(src_dir, 'src/p2p/net_node.cpp'))
    p2p_args = parse_arg_descriptors(text)
    # Get types from header
    h_text = read_file(os.path.join(src_dir, 'src/p2p/net_node.h'))
    p2p_types = {}
    for m in re.finditer(
        r'arg_descriptor\s*<\s*'
        r'((?:std::)?[a-zA-Z_][\w:]*(?:\s*<\s*(?:std::)?[a-zA-Z_][\w:]*\s*>)?)'
        r'(?:\s*,\s*[^>]*)?\s*>\s+'
        r'(\w+)\s*;',
        h_text
    ):
        cpp_type = m.group(1).strip()
        var_name = m.group(2).strip()
        p2p_types[var_name] = cpp_type

    for opt in p2p_args.values():
        if opt['var_name'] in p2p_types:
            real_type = p2p_types[opt['var_name']]
            opt['is_vector'] = 'vector' in real_type
            opt['is_bool'] = real_type == 'bool'
            opt['type'] = real_type
        options[opt['name']] = opt

    # rpc/rpc_args.h + rpc_args.cpp
    h_text = read_file(os.path.join(src_dir, 'src/rpc/rpc_args.h'))
    cpp_text = read_file(os.path.join(src_dir, 'src/rpc/rpc_args.cpp'))
    for opt in parse_rpc_args(h_text, cpp_text).values():
        options[opt['name']] = opt

    # rpc/core_rpc_server.cpp
    text = read_file(os.path.join(src_dir, 'src/rpc/core_rpc_server.cpp'))
    for opt in parse_arg_descriptors(text).values():
        options[opt['name']] = opt

    # cryptonote_basic/miner.cpp
    text = read_file(os.path.join(src_dir, 'src/cryptonote_basic/miner.cpp'))
    for opt in parse_arg_descriptors(text).values():
        options[opt['name']] = opt

    return options


def collect_monerod_subcommands(src_dir):
    """Collect daemon interactive subcommands."""
    text = read_file(os.path.join(src_dir, 'src/daemon/command_server.cpp'))
    commands = parse_set_handlers_balanced(text)

    # Reorder: help and apropos first
    reordered = []
    rest = []
    for name, desc in commands:
        if name in ('help', 'apropos'):
            reordered.append((name, desc))
        else:
            rest.append((name, desc))
    return reordered + rest


def collect_wallet_cli_options(src_dir):
    """Collect all options for monero-wallet-cli."""
    options = OrderedDict()

    # common/command_line.cpp: help, version
    text = read_file(os.path.join(src_dir, 'src/common/command_line.cpp'))
    for opt in parse_arg_descriptors(text).values():
        options[opt['name']] = opt

    # wallet/wallet_args.cpp (inline + function-defined)
    text = read_file(os.path.join(src_dir, 'src/wallet/wallet_args.cpp'))
    for opt in parse_arg_descriptors(text).values():
        options[opt['name']] = opt

    # simplewallet/simplewallet.cpp
    text = read_file(os.path.join(src_dir, 'src/simplewallet/simplewallet.cpp'))
    for opt in parse_arg_descriptors(text).values():
        options[opt['name']] = opt

    # wallet/wallet2.cpp
    text = read_file(os.path.join(src_dir, 'src/wallet/wallet2.cpp'))
    for opt in parse_arg_descriptors(text).values():
        options[opt['name']] = opt

    # wallet/message_store.cpp
    text = read_file(os.path.join(src_dir, 'src/wallet/message_store.cpp'))
    for opt in parse_arg_descriptors(text).values():
        options[opt['name']] = opt

    # Remove positional 'command' arg
    options.pop('command', None)

    return options


def collect_wallet_cli_subcommands(src_dir):
    """Collect wallet-cli interactive subcommands."""
    text = read_file(os.path.join(src_dir, 'src/simplewallet/simplewallet.cpp'))
    commands = parse_set_handlers_balanced(text)

    # Filter: skip mms subcommands (they show as "mms init", "mms info", etc.)
    # Keep only top-level commands
    filtered = []
    for name, desc in commands:
        if ' ' in name:
            # Skip mms subcommands like "mms init"
            continue
        filtered.append((name, desc))

    # Reorder: help and apropos first
    reordered = []
    rest = []
    for name, desc in filtered:
        if name in ('help', 'apropos'):
            reordered.append((name, desc))
        else:
            rest.append((name, desc))
    return reordered + rest


def collect_wallet_rpc_options(src_dir):
    """Collect all options for monero-wallet-rpc."""
    options = OrderedDict()

    # common/command_line.cpp: help, version
    text = read_file(os.path.join(src_dir, 'src/common/command_line.cpp'))
    for opt in parse_arg_descriptors(text).values():
        options[opt['name']] = opt

    # wallet/wallet_args.cpp
    text = read_file(os.path.join(src_dir, 'src/wallet/wallet_args.cpp'))
    for opt in parse_arg_descriptors(text).values():
        options[opt['name']] = opt

    # wallet/wallet_rpc_server.cpp
    text = read_file(os.path.join(src_dir, 'src/wallet/wallet_rpc_server.cpp'))
    for opt in parse_arg_descriptors(text).values():
        # Skip local password args (defined inside functions)
        if opt['var_name'] == 'arg_password' and opt['description'] == 'password':
            continue
        options[opt['name']] = opt

    # rpc_args (shared RPC options)
    h_text = read_file(os.path.join(src_dir, 'src/rpc/rpc_args.h'))
    cpp_text = read_file(os.path.join(src_dir, 'src/rpc/rpc_args.cpp'))
    for opt in parse_rpc_args(h_text, cpp_text).values():
        options[opt['name']] = opt

    # wallet/wallet2.cpp
    text = read_file(os.path.join(src_dir, 'src/wallet/wallet2.cpp'))
    for opt in parse_arg_descriptors(text).values():
        options[opt['name']] = opt

    # wallet/message_store.cpp
    text = read_file(os.path.join(src_dir, 'src/wallet/message_store.cpp'))
    for opt in parse_arg_descriptors(text).values():
        options[opt['name']] = opt

    # daemonizer non-interactive
    text = read_file(os.path.join(src_dir, 'src/daemonizer/daemonizer.h'))
    for opt in parse_arg_descriptors(text).values():
        options[opt['name']] = opt

    # Remove positional 'command' arg
    options.pop('command', None)

    return options


def collect_blockchain_import_options(src_dir):
    """Collect options for monero-blockchain-import."""
    options = OrderedDict()

    text = read_file(os.path.join(src_dir, 'src/common/command_line.cpp'))
    for opt in parse_arg_descriptors(text).values():
        if opt['name'] == 'help':
            options[opt['name']] = opt

    text = read_file(os.path.join(src_dir, 'src/blockchain_utilities/blockchain_import.cpp'))
    for opt in parse_arg_descriptors(text).values():
        options[opt['name']] = opt

    # Core options (data-dir, testnet, stagenet)
    text = read_file(os.path.join(src_dir, 'src/cryptonote_core/cryptonote_core.cpp'))
    core_args = parse_arg_descriptors(text)
    for name in ('data-dir', 'testnet', 'stagenet'):
        if name in core_args:
            options[name] = core_args[name]

    return options


def collect_blockchain_export_options(src_dir):
    """Collect options for monero-blockchain-export."""
    options = OrderedDict()

    text = read_file(os.path.join(src_dir, 'src/common/command_line.cpp'))
    for opt in parse_arg_descriptors(text).values():
        if opt['name'] == 'help':
            options[opt['name']] = opt

    text = read_file(os.path.join(src_dir, 'src/blockchain_utilities/blockchain_export.cpp'))
    for opt in parse_arg_descriptors(text).values():
        options[opt['name']] = opt

    text = read_file(os.path.join(src_dir, 'src/cryptonote_core/cryptonote_core.cpp'))
    core_args = parse_arg_descriptors(text)
    for name in ('data-dir', 'testnet', 'stagenet'):
        if name in core_args:
            options[name] = core_args[name]

    return options


def collect_blockchain_prune_options(src_dir):
    """Collect options for monero-blockchain-prune."""
    options = OrderedDict()

    text = read_file(os.path.join(src_dir, 'src/common/command_line.cpp'))
    for opt in parse_arg_descriptors(text).values():
        if opt['name'] == 'help':
            options[opt['name']] = opt

    text = read_file(os.path.join(src_dir, 'src/blockchain_utilities/blockchain_prune.cpp'))
    for opt in parse_arg_descriptors(text).values():
        options[opt['name']] = opt

    text = read_file(os.path.join(src_dir, 'src/cryptonote_core/cryptonote_core.cpp'))
    core_args = parse_arg_descriptors(text)
    for name in ('data-dir', 'testnet', 'stagenet'):
        if name in core_args:
            options[name] = core_args[name]

    return options


def collect_blockchain_prune_known_spent_data_options(src_dir):
    """Collect options for monero-blockchain-prune-known-spent-data."""
    options = OrderedDict()

    text = read_file(os.path.join(src_dir, 'src/common/command_line.cpp'))
    for opt in parse_arg_descriptors(text).values():
        if opt['name'] == 'help':
            options[opt['name']] = opt

    text = read_file(os.path.join(src_dir, 'src/blockchain_utilities/blockchain_prune_known_spent_data.cpp'))
    for opt in parse_arg_descriptors(text).values():
        options[opt['name']] = opt

    text = read_file(os.path.join(src_dir, 'src/cryptonote_core/cryptonote_core.cpp'))
    core_args = parse_arg_descriptors(text)
    for name in ('data-dir', 'testnet', 'stagenet'):
        if name in core_args:
            options[name] = core_args[name]

    return options


def collect_blockchain_stats_options(src_dir):
    """Collect options for monero-blockchain-stats."""
    options = OrderedDict()

    text = read_file(os.path.join(src_dir, 'src/common/command_line.cpp'))
    for opt in parse_arg_descriptors(text).values():
        if opt['name'] == 'help':
            options[opt['name']] = opt

    text = read_file(os.path.join(src_dir, 'src/blockchain_utilities/blockchain_stats.cpp'))
    for opt in parse_arg_descriptors(text).values():
        options[opt['name']] = opt

    text = read_file(os.path.join(src_dir, 'src/cryptonote_core/cryptonote_core.cpp'))
    core_args = parse_arg_descriptors(text)
    for name in ('data-dir', 'testnet', 'stagenet'):
        if name in core_args:
            options[name] = core_args[name]

    return options


def collect_blockchain_ancestry_options(src_dir):
    """Collect options for monero-blockchain-ancestry."""
    options = OrderedDict()

    text = read_file(os.path.join(src_dir, 'src/common/command_line.cpp'))
    for opt in parse_arg_descriptors(text).values():
        if opt['name'] == 'help':
            options[opt['name']] = opt

    text = read_file(os.path.join(src_dir, 'src/blockchain_utilities/blockchain_ancestry.cpp'))
    for opt in parse_arg_descriptors(text).values():
        options[opt['name']] = opt

    text = read_file(os.path.join(src_dir, 'src/cryptonote_core/cryptonote_core.cpp'))
    core_args = parse_arg_descriptors(text)
    for name in ('data-dir', 'testnet', 'stagenet'):
        if name in core_args:
            options[name] = core_args[name]

    return options


def collect_blockchain_depth_options(src_dir):
    """Collect options for monero-blockchain-depth."""
    options = OrderedDict()

    text = read_file(os.path.join(src_dir, 'src/common/command_line.cpp'))
    for opt in parse_arg_descriptors(text).values():
        if opt['name'] == 'help':
            options[opt['name']] = opt

    text = read_file(os.path.join(src_dir, 'src/blockchain_utilities/blockchain_depth.cpp'))
    for opt in parse_arg_descriptors(text).values():
        options[opt['name']] = opt

    text = read_file(os.path.join(src_dir, 'src/cryptonote_core/cryptonote_core.cpp'))
    core_args = parse_arg_descriptors(text)
    for name in ('data-dir', 'testnet', 'stagenet'):
        if name in core_args:
            options[name] = core_args[name]

    return options


def collect_blockchain_usage_options(src_dir):
    """Collect options for monero-blockchain-usage."""
    options = OrderedDict()

    text = read_file(os.path.join(src_dir, 'src/common/command_line.cpp'))
    for opt in parse_arg_descriptors(text).values():
        if opt['name'] == 'help':
            options[opt['name']] = opt

    text = read_file(os.path.join(src_dir, 'src/blockchain_utilities/blockchain_usage.cpp'))
    for opt in parse_arg_descriptors(text).values():
        # 'input' here is a positional arg (empty description, used as directory path)
        if opt['name'] == 'input':
            continue
        options[opt['name']] = opt

    text = read_file(os.path.join(src_dir, 'src/cryptonote_core/cryptonote_core.cpp'))
    core_args = parse_arg_descriptors(text)
    for name in ('testnet', 'stagenet'):
        if name in core_args:
            options[name] = core_args[name]

    return options


def collect_blockchain_mark_spent_outputs_options(src_dir):
    """Collect options for monero-blockchain-mark-spent-outputs."""
    options = OrderedDict()

    text = read_file(os.path.join(src_dir, 'src/common/command_line.cpp'))
    for opt in parse_arg_descriptors(text).values():
        if opt['name'] == 'help':
            options[opt['name']] = opt

    text = read_file(os.path.join(src_dir, 'src/blockchain_utilities/blockchain_blackball.cpp'))
    for opt in parse_arg_descriptors(text).values():
        # 'inputs' is a positional vector arg (Monero DB paths)
        if opt['name'] == 'inputs':
            continue
        options[opt['name']] = opt

    return options


def collect_gen_trusted_multisig_options(src_dir):
    """Collect options for monero-gen-trusted-multisig."""
    options = OrderedDict()

    # common/command_line.cpp: help, version
    text = read_file(os.path.join(src_dir, 'src/common/command_line.cpp'))
    for opt in parse_arg_descriptors(text).values():
        options[opt['name']] = opt

    # wallet_args.cpp provides log/config options
    text = read_file(os.path.join(src_dir, 'src/wallet/wallet_args.cpp'))
    for opt in parse_arg_descriptors(text).values():
        # Skip wallet-file, generate-from-json, password-file (not used by gen_multisig)
        if opt['name'] in ('wallet-file', 'generate-from-json', 'password-file'):
            continue
        options[opt['name']] = opt

    # gen_multisig.cpp
    text = read_file(os.path.join(src_dir, 'src/gen_multisig/gen_multisig.cpp'))
    for opt in parse_arg_descriptors(text).values():
        options[opt['name']] = opt

    return options


def collect_gen_ssl_cert_options(src_dir):
    """Collect options for monero-gen-ssl-cert."""
    options = OrderedDict()

    # common/command_line.cpp: help, version
    text = read_file(os.path.join(src_dir, 'src/common/command_line.cpp'))
    for opt in parse_arg_descriptors(text).values():
        options[opt['name']] = opt

    # gen_ssl_cert.cpp
    text = read_file(os.path.join(src_dir, 'src/gen_ssl_cert/gen_ssl_cert.cpp'))
    for opt in parse_arg_descriptors(text).values():
        options[opt['name']] = opt

    return options


# --- Output generation ---

def generate_completion_file(tool_name, func_name, options, subcommands=None,
                             network_exclusions=None, positional_line=None):
    """Generate a complete zsh completion file."""
    lines = [f'#compdef {tool_name}', '', f'_{func_name}() {{']

    # If there are subcommands, declare state variable and commands array
    if subcommands:
        cmd_var = 'daemon_commands' if 'monerod' in tool_name else 'wallet_commands'
        lines.append('  local state')
        lines.append('')
        lines.append(f'  local -a {cmd_var}')
        lines.append(f'  {cmd_var}=(')
        for name, desc in subcommands:
            lines.append(format_subcommand(name, desc))
        lines.append('  )')
        lines.append('')

    # Sort options: help first, version second, then alphabetical
    sorted_opts = []
    help_opt = options.pop('help', None)
    version_opt = options.pop('version', None)

    if help_opt:
        sorted_opts.append(help_opt)
    if version_opt:
        sorted_opts.append(version_opt)

    sorted_opts.extend(sorted(options.values(), key=lambda o: o['name']))

    lines.append('  _arguments \\')

    all_option_lines = []
    for opt in sorted_opts:
        all_option_lines.append(format_option(opt, network_exclusions))

    # Add positional/subcommand line if needed
    if subcommands:
        cmd_type = 'daemon command' if 'monerod' in tool_name else 'wallet command'
        all_option_lines.append(
            f"    '*::{cmd_type}:->command'"
        )
    elif positional_line:
        all_option_lines.append(f"    '{positional_line}'")

    # Join with ' \' line continuations
    for i, line in enumerate(all_option_lines):
        if i < len(all_option_lines) - 1:
            lines.append(line + ' \\')
        else:
            lines.append(line)

    # Add state handler for subcommands
    if subcommands:
        cmd_var = 'daemon_commands' if 'monerod' in tool_name else 'wallet_commands'
        cmd_type = 'daemon command' if 'monerod' in tool_name else 'wallet command'
        lines.append('')
        lines.append('  case $state in')
        lines.append('    command)')
        lines.append('      if (( CURRENT == 1 )); then')
        lines.append(f'        _describe -t commands "{cmd_type}" {cmd_var}')
        lines.append('      fi')
        lines.append('    ;;')
        lines.append('  esac')

    lines.append('}')
    lines.append('')
    lines.append(f'_{func_name} "$@"')
    lines.append('')

    return '\n'.join(lines)


def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <monero-source-dir> [output-dir]", file=sys.stderr)
        sys.exit(1)

    src_dir = sys.argv[1]
    out_dir = sys.argv[2] if len(sys.argv) > 2 else '.'

    if not os.path.isdir(src_dir):
        print(f"Error: {src_dir} is not a directory", file=sys.stderr)
        sys.exit(1)

    os.makedirs(out_dir, exist_ok=True)

    # Generate each tool's completion file
    tools = [
        {
            'name': 'monerod',
            'func': 'monerod',
            'collector': collect_monerod_options,
            'subcommand_collector': collect_monerod_subcommands,
            'network_exclusions': NETWORK_EXCLUSIONS,
        },
        {
            'name': 'monero-wallet-cli',
            'func': 'monero-wallet-cli',
            'collector': collect_wallet_cli_options,
            'subcommand_collector': collect_wallet_cli_subcommands,
            'network_exclusions': WALLET_NETWORK_EXCLUSIONS,
        },
        {
            'name': 'monero-wallet-rpc',
            'func': 'monero-wallet-rpc',
            'collector': collect_wallet_rpc_options,
            'network_exclusions': WALLET_NETWORK_EXCLUSIONS,
        },
        {
            'name': 'monero-blockchain-import',
            'func': 'monero-blockchain-import',
            'collector': collect_blockchain_import_options,
            'network_exclusions': WALLET_NETWORK_EXCLUSIONS,
        },
        {
            'name': 'monero-blockchain-export',
            'func': 'monero-blockchain-export',
            'collector': collect_blockchain_export_options,
            'network_exclusions': WALLET_NETWORK_EXCLUSIONS,
        },
        {
            'name': 'monero-blockchain-prune',
            'func': 'monero-blockchain-prune',
            'collector': collect_blockchain_prune_options,
            'network_exclusions': WALLET_NETWORK_EXCLUSIONS,
        },
        {
            'name': 'monero-blockchain-prune-known-spent-data',
            'func': 'monero-blockchain-prune-known-spent-data',
            'collector': collect_blockchain_prune_known_spent_data_options,
            'network_exclusions': WALLET_NETWORK_EXCLUSIONS,
        },
        {
            'name': 'monero-blockchain-stats',
            'func': 'monero-blockchain-stats',
            'collector': collect_blockchain_stats_options,
            'network_exclusions': WALLET_NETWORK_EXCLUSIONS,
        },
        {
            'name': 'monero-blockchain-ancestry',
            'func': 'monero-blockchain-ancestry',
            'collector': collect_blockchain_ancestry_options,
            'network_exclusions': WALLET_NETWORK_EXCLUSIONS,
        },
        {
            'name': 'monero-blockchain-depth',
            'func': 'monero-blockchain-depth',
            'collector': collect_blockchain_depth_options,
            'network_exclusions': WALLET_NETWORK_EXCLUSIONS,
        },
        {
            'name': 'monero-blockchain-usage',
            'func': 'monero-blockchain-usage',
            'collector': collect_blockchain_usage_options,
            'network_exclusions': WALLET_NETWORK_EXCLUSIONS,
            'positional': ':blockchain database directory:_directories',
        },
        {
            'name': 'monero-blockchain-mark-spent-outputs',
            'func': 'monero-blockchain-mark-spent-outputs',
            'collector': collect_blockchain_mark_spent_outputs_options,
            'positional': '*:Monero database directory:_directories',
        },
        {
            'name': 'monero-gen-trusted-multisig',
            'func': 'monero-gen-trusted-multisig',
            'collector': collect_gen_trusted_multisig_options,
            'network_exclusions': WALLET_NETWORK_EXCLUSIONS,
        },
        {
            'name': 'monero-gen-ssl-cert',
            'func': 'monero-gen-ssl-cert',
            'collector': collect_gen_ssl_cert_options,
        },
    ]

    for tool in tools:
        print(f"Generating _{tool['name']}...")

        options = tool['collector'](src_dir)
        subcommands = None
        if 'subcommand_collector' in tool:
            subcommands = tool['subcommand_collector'](src_dir)

        content = generate_completion_file(
            tool_name=tool['name'],
            func_name=tool['func'],
            options=options,
            subcommands=subcommands,
            network_exclusions=tool.get('network_exclusions'),
            positional_line=tool.get('positional'),
        )

        out_path = os.path.join(out_dir, f"_{tool['name']}")
        with open(out_path, 'w') as f:
            f.write(content)

    print("Done.")


if __name__ == '__main__':
    main()
