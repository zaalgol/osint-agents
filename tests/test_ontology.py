from pathlib import Path

import pytest

from osint.core.ontology import Ontology, OntologyError

BASE = Path(__file__).resolve().parents[1] / "config/ontology.yaml"


@pytest.fixture
def onto() -> Ontology:
    return Ontology.load([BASE])


def test_base_loads(onto: Ontology):
    assert "person" in onto.entity_types
    assert "attack" in onto.event_types
    assert onto.source_reliability == list("ABCDEF")


def test_inheritance(onto: Ontology):
    assert onto.entity_is_a("armed_group", "organization")
    assert onto.entity_is_a("channel", "online_account")
    assert not onto.entity_is_a("person", "organization")


def test_strong_identifiers_inherit(onto: Ontology):
    strong = onto.strong_identifier_types()
    assert {"email", "phone", "crypto_wallet", "online_account"} <= strong
    assert "channel" in strong  # inherited from online_account
    assert "person" not in strong


def test_relation_constraints(onto: Ontology):
    onto.check_relation("member_of", "person", "armed_group")  # subtype allowed
    onto.check_relation("leader_of", "person", "organization")  # inherits from/to
    with pytest.raises(OntologyError):
        onto.check_relation("member_of", "organization", "person")
    with pytest.raises(OntologyError):
        onto.check_relation("no_such_relation", "person", "person")


def test_event_roles(onto: Ontology):
    assert "perpetrator" in onto.event_roles("attack")


def test_fragment_can_add_but_not_redefine(onto: Ontology):
    onto.merge({"entity_types": {"drone": {"parent": "weapon"}}}, origin="plugin")
    onto.validate()
    assert onto.entity_is_a("drone", "weapon")
    onto.merge({"entity_types": {"drone": {"parent": "weapon"}}})  # identical is fine
    with pytest.raises(OntologyError):
        onto.merge({"entity_types": {"person": {"parent": "organization"}}})


def test_unknown_parent_and_cycles_rejected():
    o = Ontology()
    o.merge({"entity_types": {"a": {"parent": "missing"}}})
    with pytest.raises(OntologyError):
        o.validate()
    o = Ontology()
    o.merge({"entity_types": {"a": {"parent": "b"}, "b": {"parent": "a"}}})
    with pytest.raises(OntologyError):
        o.validate()
