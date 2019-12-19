#!/usr/bin/env python



import argparse
import collections
import datetime
import hashlib
import re
import sys
import yaml


TABLES = ("filter", "mangle", "nat", "raw", "security")
BUILTIN_CHAINS = ("FORWARD", "INPUT", "OUTPUT", "POSTROUTING", "PREROUTING")
IPT_COMMANDS = (
    "-A", "--append",
    "-C", "--check",
    "-D", "--delete",
    "-E", "--rename-chain",
    "-F", "--flush",
    "-I", "--insert",
    "-L", "--list",
    "-N", "--new-chain",
    "-P", "--policy",
    "-R", "--replace",
    "-S", "--list-rules",
    "-X", "--delete-chain",
    "-Z", "--zero",
    "-h",
)

MANAGED_TEMPLATE = "PMIPT[%s]"
MANAGED_EXAMPLE = MANAGED_TEMPLATE % "name"
MANAGED_CHAIN_RE = re.compile(r"^PMIPT\[[\w-]+\]$")
MANAGED_RULE_RE = re.compile(r"--comment ['\"]?PMIPT\[([\w-]+)\]['\"]?")


class PMIPTException(Exception): pass  # noqa: E701


def linereader(iterable):
    """Convenience generator for reading an iterable like a config file.

    Arguments:
        Any iterable of strings.

    Yields:
        A tuple of (linenumber, line) where linenumber starts at 1 and line has
        been stripped. Lines beginning with "#" are considered comments and are
        skipped entirely.
    """
    for idx, line in enumerate(iterable):
        lineno = idx + 1
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        yield lineno, line


class PMIPTConfig(object):
    class Error(PMIPTException): pass  # noqa: E701,E301
    class ParseError(Error): pass  # noqa: E701,E301
    class ExpectedDict(ParseError): pass  # noqa: E701,E301
    class ExpectedList(ParseError): pass  # noqa: E701,E301
    class InvalidChainName(ParseError): pass  # noqa: E701,E301
    class MalformedYaml(ParseError): pass  # noqa: E701,E301
    class RuleHasCommand(ParseError): pass  # noqa: E701,E301
    class RuleHasComment(ParseError): pass  # noqa: E701,E301
    class UnknownKeys(ParseError): pass  # noqa: E701,E301
    class UnknownTable(ParseError): pass  # noqa: E701,E301

    def __init__(self, tables):
        """Initialize PMIPTConfig object.

        Dictionary is expected to be formatted appropriately:

            {
                "filter": {
                    "OUTPUT": {
                        "rules": OrderedDictionary({
                            digest1: rule1,
                            digest2: rule2,
                            ...,
                        }),
                    },
                    "PMIPT[mychain]": {
                        "rules": OrderedDictionary({
                            digest1: rule1,
                            digest2: rule2,
                            ...,
                        }),
                },
                "mangle": {
                    "INPUT": {
                        "rules": OrderedDictionary({
                            digest1: rule1,
                            digest2: rule2,
                            ...,
                        }),
                    },
                },
            }

        Arguments:
            tables: tables dictionary.
        """
        self.tables = tables

    @classmethod
    def from_fp(cls, fp):
        """Instantiate PMIPTconfig from an open file-like object.

        The contents of the file must be a YAML dictionary in the format:

            table1:
              chain1:
                  rules:
                  - <rulespec>
                  - <rulespec>
                  - <rulespec>
              chain2:
                  rules:
                  - <rulespec>
                  - <rulespec>
                  ...

        Arguments:
            fp: file-like object to parse.

        Returns:
            Instantiated PMIPTConfig object.

        Raises:
            PMIPTConfig.ParseError: file contents incorrectly formatted.
        """
        try:
            return cls.from_dict(yaml.safe_load(fp.read()))
        except yaml.YAMLError as err:
            raise cls.MalformedYaml(str(err))

    @classmethod
    def from_dict(cls, data):
        """Instantiate PMIPTConfig from a dictionary.

        Expects the dictionary to in the format:

            {
                "table 1": {
                    "chain 1": {
                        "rules": [rule1, rule2, ruleN],
                    },
                    "chain N": {
                        "rules": [rule1, rule2, ruleN],
                    },
                },
                "table N": {
                    ...
                }
            }

        Arguments:
            data: dictionary to build the object from.

        Returns:
            Instantiated PMIPTConfig object.

        Raises:
            PMIPTConfig.ExpectedDict: data is not a dictionary.
            PMIPTConfig.ParseError: dictionary incorrectly formatted.
        """
        if not isinstance(data, dict):
            raise cls.ExpectedDict()
        tables = {table: {} for table in TABLES}
        for table in data:
            tables[table] = cls._parse_table(table, data[table])
        return cls(tables)

    @classmethod
    def _parse_table(cls, name, data):
        """Parse a single table dictionary.

        Arguments:
            name: name of the table being parsed.
            data: dictionary to parse as a table definition.

        Returns:
            A dictionary of chains within the named table.

            {
                chain1: chain1_dictionary,
                chain2: chain2_dictionary,
                ...,
            }

        Raises:
            PMIPTConfig.ExpectedDict: data is not a dictionary.
            PMIPTConfig.UnknownTable: table name is not one of TABLES.
            PMIPTConfig.ParseError: data dictionary is incorrectly formatted.
        """
        if name not in TABLES:
            raise cls.UnknownTable(name)
        if not isinstance(data, dict):
            raise cls.ExpectedDict(name)
        table = {}
        for chain in sorted(data):
            table[chain] = cls._parse_chain(name, chain, data[chain])
        return table

    @classmethod
    def _parse_chain(cls, table, name, data):
        """Parse a single chain dictionary.

        Arguments:
            table: name of the table this chain belongs to.
            name: name of the chain being parsed. Must match a builtin or the
                MANAGED_CHAIN_RE pattern.
            data: dictionary to parse as a chain definition.

        Returns:
            An ordered dictionary of rules within this chain, keyed by a digest
            of each rule's original configuration.

            {
                digest1: rule1,
                digest2: rule2,
                ...,
            }

        Raises:
            PMIPTConfig.ExpectedDict: data is not a dictionary.
            PMIPTConfig.ExpectedList: data["rules"] is not a list.
            PMIPTConfig.InvalidChainName: chain name is not a builtin and
                doesn't match MANAGED_CHAIN_RE.
            PMIPTConfig.UnknownKeys: data includes unknown keys.
            PMIPTConfig.ParseError: data dictionary is incorrectly formatted.
        """
        if name not in BUILTIN_CHAINS and not MANAGED_CHAIN_RE.match(name):
            raise cls.InvalidChainName("%s.%s must be builtin or match %s"
                                       % (table, name, MANAGED_EXAMPLE))
        if not isinstance(data, dict):
            raise cls.ExpectedDict("%s.%s" % (table, name))
        unknown = set(data) - set(["rules"])
        rules = data.get("rules", [])
        if unknown:
            raise cls.UnknownKeys("%s.%s: %s" % (table, name, unknown))
        if not isinstance(rules, list):
            raise cls.ExpectedList("%s.%s.rules" % (table, name))
        chain = collections.OrderedDict()
        for rule in rules:
            digest, rule = cls._parse_rule(table, name, rule)
            chain[digest] = rule
        return chain

    @classmethod
    def _parse_rule(cls, table, chain, rule):
        """Parse a single rule definition.

        Rules are raw IPTables fragments without the command (e.g., -A <chain>)
        and without any comment. Commands other than -A may not be modeled with
        PMIPT.

        Arguments:
            table: name of the table this rule belongs to.
            chain: name of the chain this rules belongs to.
            rule: raw IPTables rule definition, minus -A <chain>.

        Returns:
            A tuple (digest, rule). digest is the sha256 hex digest of the
            original rule string. rule has been prefixed with '-A <chain>' and
            suffixed with '-m comment --comment "PMIPT[<digest>]"'.

        Raises:
            PMIPTConfig.RuleHasCommand: the rule already has a command defined.
            PMIPTConfig.RuleHasComment: the rule already has a comment defined.
        """
        if any(rule.startswith(opt) for opt in IPT_COMMANDS):
            raise cls.RuleHasCommand("%s.%s: %s" % (table, chain, rule))
        if ("-m comment" in rule
                or "--match comment" in rule
                or "--comment" in rule):
            raise cls.RuleHasComment("%s.%s: %s" % (table, chain, rule))
        sha = hashlib.sha256()
        sha.update(rule.encode('utf-8'))
        digest = sha.hexdigest()
        rule = " ".join([
            "-A %s" % chain,
            rule,
            '-m comment --comment "%s"' % (MANAGED_TEMPLATE % digest),
        ])
        return digest, rule


class IPTablesState(object):
    class Error(PMIPTException): pass  # noqa: E701,E301
    class ParseError(Error):  # noqa: E301
        def __init__(self, lineno, msg=""):
            linemsg = "line %d" % lineno
            msg = ("%s: %s" % (linemsg, msg)) if msg else linemsg
            super(IPTablesState.ParseError, self).__init__(msg)

    class MalformedLine(ParseError): pass  # noqa: E701,E301
    class MissingCommit(ParseError): pass  # noqa: E701,E301
    class MissingTableContext(ParseError): pass  # noqa: E701,E301
    class UnknownTable(ParseError): pass  # noqa: E701,E301

    def __init__(self, tables):
        """Initialize IPTablesState object.

        Dictionary is expected to be formatted appropriately:

            {
                "filter": {
                    "OUTPUT": [rule1, rule2, ...],
                    "PMIPT[mychain]": [rule1, rule2, ...],
                },
                "mangle": {
                    "INPUT": [rule1, rule2, ...],
                },
                ...
            }

        Arguments:
            tables: tables dictionary.
        """
        self.tables = tables

    @classmethod
    def from_fp(cls, fp):
        """Instantiate IPTablesState from an open file-like object.

        Arguments:
            fp: file-like object whose contents are in iptables-save format.

        Returns:
            Instantiated IPTablesState object.

        Raises:
            IPTablesState.ParseError: file contents incorrectly formatted.
        """
        return cls.from_lines(fp.readlines())

    @classmethod
    def from_lines(cls, lines):
        """Instantiate IPTablesState from an iterable of strings.

        Arguments:
            lines: an iterable of strings in iptables-save format.

        Returns:
            Instantiated IPTablesState object.

        Raises:
            IPTablesState.MalformedLine: line is incorrectly formatted.
            IPTablesState.MissingCommit: table is not closed with COMMIT.
            IPTablesState.MissingTableContext: configuration outside table.
            IPTablesState.UnknownTable: table listed that is not one of TABLES.
            IPTablesState.ParseError: file contents incorrectly formatted.
        """
        # the format of iptables-save is both static and limited. Only five
        # types of lines are produced:
        #
        # # comment
        # *tablename <-- begin a table clause
        # :CHAINNAME CHAINPOLICY [COUNTERS] <-- declare a chain
        # -A CHAIN <rulespec> <-- only ever includes -A
        # COMMIT <-- commit the changes and effectively end the table clause
        #
        # iptables-save is unlikely to change in the near future given how long
        # it's gone untouched, so it should be safe to trade flexibility for
        # the clarity of rigid parsing logic.
        # table -> chain -> rules
        tables = {table: collections.OrderedDict() for table in TABLES}
        table = None

        for lineno, line in linereader(lines):
            # tables
            if line.startswith("*"):
                if table is not None:
                    raise cls.MissingCommit(lineno, table)
                table = line[1:]
                if table not in TABLES:
                    raise cls.UnknownTable(lineno, table)
                tables[table] = {}
                continue

            # everything else must be in a table context
            elif table is None:
                raise cls.MissingTableContext(lineno)

            # commit current table
            if line == "COMMIT":
                table = None
                continue

            # chains
            elif line.startswith(":"):
                # :NAME policy [optional stats]
                parts = line[1:].split()
                if len(parts) < 2:
                    raise cls.MalformedLine(lineno, line)
                chain = parts[0]
                tables[table][chain] = []
                continue

            # rules
            elif line.startswith("-A"):
                chain = line.split()[1]
                tables[table][chain].append(line)
            else:
                raise cls.MalformedLine(lineno, line)

        # final table committed?
        if table is not None:
            raise cls.MissingCommit(lineno, table)  # pylint: disable=W0631
        return cls(tables)


def generate_output(config, state, prog="PMIPT"):
    """Generate output to reconcile state with config.

    Arguments:
        config: instantiated PMIPTConfig object.
        state: instantiated IPTablesState object.
        prog: name of the program to include in the output commments.

    Returns:
        A string command that will reconcile state with config when passed to
        iptables-restore -n.
    """
    # build the output
    now = datetime.datetime.utcnow().isoformat()
    output = [
        "# WARNING: iptables-restore MUST BE CALLED WITH --noflush",
        "#",
        "# Generated by %s on %s" % (prog, now),
    ]

    # NOTE: sorted() is used ONLY for the sake of stable output. The order
    # of table and chain definitions doesn't matter to iptables-restore.
    # Order of rules within tables, however, is vitally important and should
    # not be modified.
    for table in sorted(TABLES):
        config_table = config.tables[table]
        state_table = state.tables[table]

        changes = []

        # add new chains first
        for chain in sorted(set(config_table) - set(state_table)):
            if MANAGED_CHAIN_RE.match(chain):
                changes.append(":%s -" % chain)

        # delete all managed rules to be re-added later. A future revision
        # should allow keeping unchanged rules, but it must take order into
        # account. For now it's easier to just delete + recreate on the
        # assumption that this code will be run infrequently.
        for chain in sorted(state_table):
            for rule in state_table[chain]:
                if MANAGED_RULE_RE.search(rule):
                    changes.append(rule.replace("-A", "-D", 1))

        # add all managed rules
        for chain in sorted(config_table):
            for rule in list(config_table[chain].values()):
                changes.append(rule)

        # remove deleted chains last
        for chain in sorted(set(state_table) - set(config_table)):
            if MANAGED_CHAIN_RE.match(chain):
                changes.append("-X %s" % chain)

        if changes:
            output.append("*%s" % table)
            output.extend(changes)
            output.append("COMMIT")

    return "\n".join(output)


def build_parser(prog=None):
    desc = ("Compare PMIPT rules with iptables-save output and output actions"
            " to be taken in format compatible with iptables-restore -n.")
    parser = argparse.ArgumentParser(prog=prog, description=desc)
    parser.add_argument("config", default="/etc/pmipt.conf",
                        help="config file to apply")
    parser.add_argument("state", default="-",
                        help="path to iptables-save output or - for stdin")
    return parser


def main(argv=sys.argv[:]):
    parser = build_parser(argv[0])
    args = parser.parse_args()

    with open(args.config) as fp:
        config = PMIPTConfig.from_fp(fp)

    if args.state == "-":
        state = IPTablesState.from_fp(sys.stdin)
    else:
        with open(args.state) as fp:
            state = IPTablesState.from_fp(fp)

    print(generate_output(config, state, prog=parser.prog))


if __name__ == "__main__":
    sys.exit(main(sys.argv[:]))
