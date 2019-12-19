import collections
import hashlib
import io

import mock
import pytest
import yaml

import pmipt


def digest_matches(digest, data):
    """Utility function to validate digest matches sha256(data)."""
    sha = hashlib.sha256()
    sha.update(data.encode('utf-8'))
    return sha.hexdigest() == digest


def test_linereader():
    """Verify linereader behaves as expected."""
    line_1 = "line 1"
    line_2 = "       \t\n"
    line_3 = "  # comment line"
    line_4 = "line 4"

    reader = pmipt.linereader([line_1, line_2, line_3, "   %s\n" % line_4])
    assert next(reader) == (1, line_1)
    # line 2 is skipped because it's just whitespace
    # line 3 is skipped because it's a comment
    # line 4 should still be 4 and should also be stripped
    assert next(reader) == (4, line_4)


def test_pmiptconfig_initialization():
    """Veriy that PMIPTConfig initialization behaves as expected."""
    tables = object()
    config = pmipt.PMIPTConfig(tables)
    assert config.tables is tables


def test_pmiptconfig_from_fp(raw_pmipt_config):
    """Verify that PMIPTConfig.from_fp properly reads from a file object."""
    fp = io.StringIO(str(yaml.dump(raw_pmipt_config)))
    config = pmipt.PMIPTConfig.from_fp(fp)
    assert isinstance(config, pmipt.PMIPTConfig)


def test_pmiptconfig_from_fp_not_yaml():
    """Verify that PMIPTConfig.from_fp errors out on non-YAML."""
    fp = io.StringIO(u"\tnot yaml")
    with pytest.raises(pmipt.PMIPTConfig.MalformedYaml):
        pmipt.PMIPTConfig.from_fp(fp)


def test_pmiptconfig_from_fp_not_dictionary():
    """Verify that PMIPTConfig.from_fp errors out on non-dictionary YAML."""
    fp = io.StringIO(str(yaml.dump(["not", "a", "dictionary"])))
    with pytest.raises(pmipt.PMIPTConfig.ExpectedDict):
        pmipt.PMIPTConfig.from_fp(fp)


def test_pmiptconfig_from_dict(raw_pmipt_config):
    """Verify that PMIPTConfig.from_dict properly reads a dictionary."""
    config = pmipt.PMIPTConfig.from_dict(raw_pmipt_config)
    assert isinstance(config, pmipt.PMIPTConfig)
    # all the tables must be represented, but only those that were configured
    # have any data
    for name in pmipt.TABLES:
        if name in raw_pmipt_config:
            assert config.tables[name]
        else:
            assert not config.tables[name]


def test_pmiptconfig_from_dict_calls_parse_table(raw_pmipt_config):
    """Verify that PMIPTConfig.from_dict calls _parse_table for each table."""
    mock_tables = {name: mock.Mock() for name in raw_pmipt_config}
    assert mock_tables
    assert len(mock_tables) < len(pmipt.TABLES)
    with mock.patch.object(pmipt.PMIPTConfig, "_parse_table") as mock_parse:
        mock_parse.side_effect = lambda t, d: mock_tables[t]
        config = pmipt.PMIPTConfig.from_dict(raw_pmipt_config)

    calls = [mock.call(name, raw_pmipt_config[name]) for name in raw_pmipt_config]
    mock_parse.assert_has_calls(calls)
    for name, mock_table in mock_tables.items():
        assert config.tables[name] == mock_table


def test_pmiptconfig_from_dict_not_dictionary():
    """Verify that PMIPTConfig.from_dict errors out on non-dictionary."""
    with pytest.raises(pmipt.PMIPTConfig.ExpectedDict):
        pmipt.PMIPTConfig.from_dict(list())


def test_pmiptconfig_parse_table(raw_pmipt_config):
    """Verify that PMIPTConfig._parse_table handles correct formats."""
    name = "filter"
    data = raw_pmipt_config[name]
    table = pmipt.PMIPTConfig._parse_table(name, data)
    assert set(table.keys()) == set(data.keys())
    for chain in table:
        assert isinstance(table[chain], collections.OrderedDict)


def test_pmiptconfig_parse_table_calls_parse_chain(raw_pmipt_config):
    """Verify that PMIPTConfig._parse_table calls _parse_chain for each chain."""
    tname = "filter"
    data = raw_pmipt_config[tname]
    mock_chains = {name: mock.Mock() for name in data}
    assert mock_chains

    with mock.patch.object(pmipt.PMIPTConfig, "_parse_chain") as mock_parse:
        mock_parse.side_effect = lambda t, c, d: mock_chains[c]
        table = pmipt.PMIPTConfig._parse_table(tname, data)

    # chains are enumerated from a dictionary and order doesn't matter here
    calls = [mock.call(tname, name, data[name]) for name in data]
    mock_parse.assert_has_calls(calls, any_order=True)
    for name, mock_chain in mock_chains.items():
        assert table[name] == mock_chain


def test_pmiptconfig_parse_table_unknown_table():
    """Verify that PMIPTConfig._parse_table errors on bad table names."""
    with pytest.raises(pmipt.PMIPTConfig.UnknownTable):
        pmipt.PMIPTConfig._parse_table("not a table", {})


def test_pmiptconfig_parse_table_not_dictionary():
    """Verify that PMIPTConfig._parse_table errors on non-dictionary data."""
    with pytest.raises(pmipt.PMIPTConfig.ExpectedDict):
        pmipt.PMIPTConfig._parse_table("filter", list())


def test_pmiptconfig_parse_chain(raw_pmipt_config):
    """Verify that PMIPTConfig._parse_chain handles correct formats."""
    tname = "filter"
    cname = list(raw_pmipt_config[tname].keys())[0]
    data = raw_pmipt_config[tname][cname]

    chain = pmipt.PMIPTConfig._parse_chain(tname, cname, data)
    assert isinstance(chain, collections.OrderedDict)
    assert len(chain) == len(data["rules"])


def test_pmiptconfig_parse_chain_calls_parse_chain(raw_pmipt_config):
    """Verify that PMIPTConfig._parse_chain calls _parse_rule for each rule."""
    tname = "filter"
    cname = list(raw_pmipt_config[tname].keys())[0]
    data = raw_pmipt_config[tname][cname]
    # use rule[::-1] in place of digest
    mock_rules = {rule[::-1]: rule for rule in data["rules"]}
    assert mock_rules

    with mock.patch.object(pmipt.PMIPTConfig, "_parse_rule") as mock_parse:
        mock_parse.side_effect = lambda t, c, r: (r[::-1], mock_rules[r[::-1]])
        chain = pmipt.PMIPTConfig._parse_chain(tname, cname, data)

    # note that data["rules"] is a list; this implies an ordering check
    calls = [mock.call(tname, cname, rule) for rule in data["rules"]]
    mock_parse.assert_has_calls(calls)
    for digest, rule in mock_rules.items():
        assert chain[digest] == rule


@pytest.mark.parametrize("data", [{}, {"rules": []}])
def test_pmiptconfig_parse_chain_no_rules(data):
    """Verify that PMIPTConfig._parse_chain accepts missing rules."""
    tname = "filter"
    cname = "OUTPUT"

    chain = pmipt.PMIPTConfig._parse_chain(tname, cname, data)
    assert isinstance(chain, collections.OrderedDict)
    assert len(chain) == 0


def test_pmiptconfig_parse_chain_bad_name():
    """Verify that PMIPTConfig._parse_chain errors on a bad chain name."""
    with pytest.raises(pmipt.PMIPTConfig.InvalidChainName):
        pmipt.PMIPTConfig._parse_chain("filter", "bad name", {})


def test_pmiptconfig_parse_chain_not_dictionary():
    """Verify that PMIPTConfig._parse_chain errors on non-dictionary data."""
    with pytest.raises(pmipt.PMIPTConfig.ExpectedDict):
        pmipt.PMIPTConfig._parse_chain("filter", "OUTPUT", list())


def test_pmiptconfig_parse_chain_stray_keys():
    """Verify that PMIPTConfig._parse_chain errors on non-dictionary data."""
    with pytest.raises(pmipt.PMIPTConfig.UnknownKeys):
        pmipt.PMIPTConfig._parse_chain("filter", "OUTPUT", {"stray": {}})


def test_pmiptconfig_parse_chain_rules_not_list():
    """Verify that PMIPTConfig._parse_chain errors if rules is not list."""
    with pytest.raises(pmipt.PMIPTConfig.ExpectedList):
        pmipt.PMIPTConfig._parse_chain("filter", "OUTPUT", {"rules": dict()})


def test_pmiptconfig_parse_rule(raw_pmipt_config):
    """Verify that PMIPTConfig._parse_rule handles correct formats."""
    tname = "filter"
    cname = list(raw_pmipt_config[tname].keys())[0]
    data = raw_pmipt_config[tname][cname]["rules"][0]

    digest, rule = pmipt.PMIPTConfig._parse_rule(tname, cname, data)
    assert digest_matches(digest, data)
    assert rule == ("-A %s %s -m comment --comment \"%s\""
                    % (cname, data, (pmipt.MANAGED_TEMPLATE % digest)))


@pytest.mark.parametrize("command", ["%s foo" % c for c in pmipt.IPT_COMMANDS])
def test_pmiptconfig_parse_rule_has_command(command, raw_pmipt_config):
    """Verify that PMIPTConfig._parse_rule errors on rules with commands."""
    tname = "filter"
    cname = list(raw_pmipt_config[tname].keys())[0]
    data = command + " " + raw_pmipt_config[tname][cname]["rules"][0]

    with pytest.raises(pmipt.PMIPTConfig.RuleHasCommand):
        pmipt.PMIPTConfig._parse_rule(tname, cname, data)


@pytest.mark.parametrize("comment", ["-m comment",
                                     "--match comment",
                                     "--comment foo",
                                     "-m comment --comment foo"])
def test_pmiptconfig_parse_rule_has_comment(comment, raw_pmipt_config):
    """Verify that PMIPTConfig._parse_rule errors on rules with comments."""
    tname = "filter"
    cname = list(raw_pmipt_config[tname].keys())[0]
    data = raw_pmipt_config[tname][cname]["rules"][0] + " " + comment

    with pytest.raises(pmipt.PMIPTConfig.RuleHasComment):
        pmipt.PMIPTConfig._parse_rule(tname, cname, data)


def test_iptablestate_initialization():
    """Veriy that IPTablesState initialization behaves as expected."""
    tables = object()
    state = pmipt.IPTablesState(tables)
    assert state.tables is tables


def test_iptablestate_from_fp(raw_iptables_save):
    """Verify that IPTablesState.from_fp properly reads from a file object."""
    fp = io.StringIO(str(raw_iptables_save))
    state = pmipt.IPTablesState.from_fp(fp)
    assert isinstance(state, pmipt.IPTablesState)


def test_iptablestate_from_lines(raw_iptables_save):
    """Verify that IPTablesState.from_lines properly reads from an iterable."""
    state = pmipt.IPTablesState.from_lines(raw_iptables_save.split("\n"))
    assert isinstance(state, pmipt.IPTablesState)
    assert any(state.tables.values())


def test_iptablestate_from_lines_simple():
    """Verify that IPTablesState.from_lines creates expected structure."""
    # this is a little (well, a lot) more manual than ideal. This is in
    # iptables-save format but is trimmed and tweaked for testing purposes.
    # The tests that use raw_iptables_save are actually exercising a closer
    # representation of actual iptables-save output.
    mangle_prerouting_rule_1 = ("-A PREROUTING -m addrtype --dst-type LOCAL"
                                " -j DOCKER")
    mangle_prerouting_rule_2 = ("-A PREROUTING -d 10.0.0.0/8 -j mychain"
                                " -m comment --comment \"PMIPT[digest1]\"")
    mangle_mychain_rule_1 = ("-A PMIPT[mychain] -d 10.0.0.255/32 -j MARK"
                             " --set-mark 0x13531 -m comment --comment"
                             " \"PMIPT[digest2]\"")

    filter_forward_rule_1 = "-A FORWARD -j DOCKER-ISOLATION"
    filter_docker_iso_rule_1 = "-A DOCKER-ISOLATION -j RETURN"

    lines = [
        "# this table has a managed chain and some managed rules",
        "*mangle",
        ":PREROUTING ACCEPT [123:456789]",
        ":PMIPT[mychain] - [12:345]",
        ":DOCKER - [0:0]",
        mangle_prerouting_rule_1,
        mangle_prerouting_rule_2,
        mangle_mychain_rule_1,
        "COMMIT",

        "# this table has no rules",
        "*nat",
        ":INPUT ACCEPT [391:24897]",
        ":OUTPUT ACCEPT [3128:22000]",
        "COMMIT",

        "# this table has an unmanaged chain and unmanaged rules",
        "*filter",
        ":FORWARD DROP [0:0]",
        ":DOCKER-ISOLATION - [0:0]",
        filter_forward_rule_1,
        filter_docker_iso_rule_1,
        "COMMIT",
    ]
    state = pmipt.IPTablesState.from_lines(lines)
    # all tables are represented even though not all have values
    for table in pmipt.TABLES:
        assert table in state.tables
        data = state.tables[table]
        if table == "mangle":
            assert set(data) == set(["PREROUTING", "PMIPT[mychain]", "DOCKER"])
            assert data["PREROUTING"] == [
                mangle_prerouting_rule_1,
                mangle_prerouting_rule_2,
            ]
            assert data["PMIPT[mychain]"] == [mangle_mychain_rule_1]
            assert data["DOCKER"] == []
        elif table == "nat":
            assert set(data) == set(["INPUT", "OUTPUT"])
            assert data["INPUT"] == []
            assert data["OUTPUT"] == []
        elif table == "filter":
            assert set(data) == set(["FORWARD", "DOCKER-ISOLATION"])
            assert data["FORWARD"] == [filter_forward_rule_1]
            assert data["DOCKER-ISOLATION"] == [filter_docker_iso_rule_1]
        else:
            assert not state.tables[table]


def test_iptablestate_from_lines_missing_early_commit():
    """Verify IPTablesState.from_lines errors if an early commit is missing."""
    lines = [
        "*nat", ":PREROUTING ACCEPT [0:0]",
        "*filter", ":INPUT ACCEPT [0:0]", ":OUTPUT ACCEPT [0:0]", "COMMIT",
    ]
    with pytest.raises(pmipt.IPTablesState.MissingCommit):
        pmipt.IPTablesState.from_lines(lines)


def test_iptablestate_from_lines_missing_final_commit():
    """Verify IPTablesState.from_lines errors if final commit is missing."""
    lines = [
        "*nat", ":PREROUTING ACCEPT [0:0]", "COMMIT",
        "*filter", ":INPUT ACCEPT [0:0]", ":OUTPUT ACCEPT [0:0]",
    ]
    with pytest.raises(pmipt.IPTablesState.MissingCommit):
        pmipt.IPTablesState.from_lines(lines)


def test_iptablestate_from_lines_unknown_table():
    """Verify IPTablesState.from_lines errors on an unknown table."""
    lines = [
        "*nat", ":PREROUTING ACCEPT [0:0]", "COMMIT",
        "*notatable", ":INPUT ACCEPT [0:0]", ":OUTPUT ACCEPT [0:0]", "COMMIT",
    ]
    with pytest.raises(pmipt.IPTablesState.UnknownTable):
        pmipt.IPTablesState.from_lines(lines)


@pytest.mark.parametrize("statement", ["COMMIT", ":mychain -", "-A mychain"])
def test_iptablestate_from_lines_outside_table_context(statement):
    """Verify IPTablesState.from_lines errors on statements outside a table."""
    lines = [
        "*nat", ":PREROUTING ACCEPT [0:0]", "COMMIT",
        statement,
        "*filter", ":INPUT ACCEPT [0:0]", ":OUTPUT ACCEPT [0:0]", "COMMIT",
    ]
    with pytest.raises(pmipt.IPTablesState.MissingTableContext):
        pmipt.IPTablesState.from_lines(lines)


@pytest.mark.parametrize("statement", [":", ":mychain"])
def test_iptablestate_from_lines_bad_chain(statement):
    """Verify IPTablesState.from_lines errors on bad chain statement."""
    lines = ["*nat", ":PREROUTING ACCEPT [0:0]", statement, "COMMIT"]
    with pytest.raises(pmipt.IPTablesState.MalformedLine):
        pmipt.IPTablesState.from_lines(lines)


@pytest.mark.parametrize("statement", [c for c in pmipt.IPT_COMMANDS if c != "-A"])
def test_iptablestate_from_lines_bad_commands(statement):
    """Verify IPTablesState.from_lines errors on non-A commands."""
    lines = ["*nat", ":PREROUTING ACCEPT [0:0]", statement, "COMMIT"]
    with pytest.raises(pmipt.IPTablesState.MalformedLine):
        pmipt.IPTablesState.from_lines(lines)


def test_generate_ouptut():
    """Verify generate_output() produces expected results given known inputs.

    This test checks:
        - Addition of new rules
        - Addition of new chains
        - Unmanaged chains and rules are ignored
        - Deletion of old managed rules
        - Deletion of old managed chains
        - Deletion and readdition of known managed rules
        - Internal ordering of operations
    """

    # it'd be nice to find a way to make this test less explicit, but
    # it's fine for now
    config = pmipt.PMIPTConfig.from_dict({
        "nat": {
            "PREROUTING": { "rules": [
                "-d 10.0.0.1 -p udp --dport 53 -j DNAT --to-destination 127.0.0.1",
                "-d 10.0.0.2 -j DNAT --to-destination 10.0.0.3",
            ]},
            "PMIPT[mynatchain]": { "rules": [
                "-d 2.2.2.2/30 -p tcp --dport 80 -j DNAT --to-destination 10.9.9.9",
                "-d 3.3.3.3/32 -p tcp --dport 443 -j SNAT --to 1.2.3.4",
            ]},
        },
        "filter": {
            "OUTPUT": { "rules": [
                "-d 2.2.2.2/30 -p tcp --dport 80 -j DROP",
                "-d 3.3.3.3/32 -p tcp --dport 443 -j ACCEPT",
            ]},
            "PMIPT[myfilterchain]": { "rules": [
                "-d 127.0.0.93 -m mark --mark 0x10901 -j ACCEPT",
                "-d 127.0.0.46 -m mark ! --mark 0x10901 -j DROP",
            ]},
        },
    })

    state = pmipt.IPTablesState.from_lines([
        "*mangle",
        ":PREROUTING ACCEPT [0:0]",
        ":POSTROUTING ACCEPT [0:0]",
        # chain to be deleted
        ":PMIPT[oldmanglechain] - [0:0]",
        # rule to be deleted
        "-A PMIPT[oldmanglechain] -d 127.0.0.1/8 -j MARK --set-mark 0x10001 -m comment --comment \"PMIPT[8b16855dc57c2cc40a9527e5dd37eceac420772211c5fd10faba808f6c8cabf8]\"",
        "COMMIT",

        "*nat",
        ":PREROUTING ACCEPT [0:0]",
        # custom chain already exists
        ":PMIPT[mynatchain] - [0:0]",
        # unmanaged rule
        "-A PREROUTING -d 192.168.0.0/16 -j SNAT --to 10.0.0.12",
        # rule to be deleted
        "-A PMIPT[mynatchain] -d 172.16.0.1/32 -j SNAT --to 10.0.0.11 -m comment --comment \"PMIPT[40cfd2e443c2ec0e78780c1c8680b355e3554f2783bfa0cc58acb7b7ddcc4c43]\"",
        # rule that matches and should be deleted/readded
        "-A PMIPT[mynatchain] -d 3.3.3.3/32 -p tcp --dport 443 -j SNAT --to 1.2.3.4 -m comment --comment \"PMIPT[d1fc1d5929547223237fb939483e2669aea113ba80185ef72f1329c0ece97b55]\"",
        "COMMIT",

        "*filter",
        ":OUTPUT ACCEPT [0:0]",
        # unmanaged chain
        ":mychain - [0:0]",
        # unmanaged rules
        "-A mychain -i eth0 -d 127.0.0.1/8 -j DROP",
        "-A OUTPUT -i eth0 -d 8.8.8.8/32 -p udp --dport 53 -j ACCEPT",
        "COMMIT",
    ])

    # order of tables is dictated by pmipt.TABLES...problem is
    expected = [
        "*filter",
        ":PMIPT[myfilterchain] -",
        "-A OUTPUT -d 2.2.2.2/30 -p tcp --dport 80 -j DROP -m comment --comment \"PMIPT[d4eaa261e93b1cd1b3988dcb838c5b7d0a6ddd79e6257c295ed86282bf2e95fd]\"",
        "-A OUTPUT -d 3.3.3.3/32 -p tcp --dport 443 -j ACCEPT -m comment --comment \"PMIPT[6d7ca8b65333781489a4864259e787d98f75c1da3667cb575e9627ad248f800a]\"",
        "-A PMIPT[myfilterchain] -d 127.0.0.93 -m mark --mark 0x10901 -j ACCEPT -m comment --comment \"PMIPT[90a3e25a4c53c8b2472ca13db9e9a960df194506b485b2cf78ac1094ca33a187]\"",
        "-A PMIPT[myfilterchain] -d 127.0.0.46 -m mark ! --mark 0x10901 -j DROP -m comment --comment \"PMIPT[5bc0bfec1cae643d8538844b32d43b3a9853d7935699f6e6b83908e8dc1a38e6]\"",
        "COMMIT",

        "*mangle",
        "-D PMIPT[oldmanglechain] -d 127.0.0.1/8 -j MARK --set-mark 0x10001 -m comment --comment \"PMIPT[8b16855dc57c2cc40a9527e5dd37eceac420772211c5fd10faba808f6c8cabf8]\"",
        "-X PMIPT[oldmanglechain]",
        "COMMIT",

        "*nat",
        "-D PMIPT[mynatchain] -d 172.16.0.1/32 -j SNAT --to 10.0.0.11 -m comment --comment \"PMIPT[40cfd2e443c2ec0e78780c1c8680b355e3554f2783bfa0cc58acb7b7ddcc4c43]\"",
        "-D PMIPT[mynatchain] -d 3.3.3.3/32 -p tcp --dport 443 -j SNAT --to 1.2.3.4 -m comment --comment \"PMIPT[d1fc1d5929547223237fb939483e2669aea113ba80185ef72f1329c0ece97b55]\"",
        "-A PMIPT[mynatchain] -d 2.2.2.2/30 -p tcp --dport 80 -j DNAT --to-destination 10.9.9.9 -m comment --comment \"PMIPT[ed6e000d22808e8b5983e72fd483a62d74a016f852ca8c400364c65634a176ea]\"",
        "-A PMIPT[mynatchain] -d 3.3.3.3/32 -p tcp --dport 443 -j SNAT --to 1.2.3.4 -m comment --comment \"PMIPT[d1fc1d5929547223237fb939483e2669aea113ba80185ef72f1329c0ece97b55]\"",
        "-A PREROUTING -d 10.0.0.1 -p udp --dport 53 -j DNAT --to-destination 127.0.0.1 -m comment --comment \"PMIPT[61f874b9358f3f42852d38e41c6da130d2eb9afb6dec4bb7f9e2a369e8977446]\"",
        "-A PREROUTING -d 10.0.0.2 -j DNAT --to-destination 10.0.0.3 -m comment --comment \"PMIPT[9908a2ddb1a8fb89a41e3d249e8a55485fc7f32f25b1e5f69d44b98b202d31a3]\"",
        "COMMIT",
    ]

    output = pmipt.generate_output(config, state, prog="test")
    lines = output.split("\n")
    assert lines[0] == "# WARNING: iptables-restore MUST BE CALLED WITH --noflush"
    assert lines[1].startswith("#")
    assert lines[2].startswith("#")
    assert lines[3:] == expected


def test_build_parser():
    """Verify build_parser() executes without issue."""
    parser = pmipt.build_parser()
    assert hasattr(parser, "parse_args")
    assert callable(parser.parse_args)
