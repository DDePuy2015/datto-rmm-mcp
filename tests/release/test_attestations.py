"""Cosign payload claim verification; signature cryptography remains Cosign's job."""
import base64
import json
import unittest

from fixtures import attestations

DIGEST = "sha256:" + "a" * 64
PREDICATE = {"fixture": "sanitized"}
TYPE = "https://cyclonedx.org/bom"


def statement(**kwargs):
    value = {"_type": "https://in-toto.io/Statement/v0.1",
             "predicateType": TYPE, "predicate": PREDICATE,
             "subject": [{"name": "image", "digest": {"sha256": "a" * 64}}]}
    value.update(kwargs)
    return value


def envelope(value):
    return {"payload": base64.b64encode(json.dumps(value).encode()).decode()}


class AttestationTests(unittest.TestCase):
    def verify(self, content):
        attestations.verify(DIGEST, content, PREDICATE, TYPE)

    def test_exact_claims_in_single_envelope(self):
        self.verify(json.dumps(envelope(statement())))

    def test_array_and_multiple_json_documents(self):
        good = envelope(statement())
        other = envelope(statement(predicate={"old": True}))
        for text in (json.dumps([other, good]), json.dumps(other) + "\n" + json.dumps(good)):
            self.verify(text)

    def test_rejects_wrong_predicate_type_content_digest_or_missing_subject(self):
        for value in [statement(_type="unknown"), statement(predicateType="wrong"), statement(predicate={"other": True}),
                      statement(subject=[]), statement(subject=[{"digest": {"sha256": "b" * 64}}]),
                      statement(subject=[{"digest": {"sha256": "a" * 64}},
                                         {"digest": {"sha256": "b" * 64}}])]:
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.verify(json.dumps(envelope(value)))

    def test_empty_or_unmatched_payload_rejected(self):
        for text in ("", "[]", json.dumps([envelope(statement(predicate={"old": True}))])):
            with self.subTest(text=text), self.assertRaises(ValueError):
                self.verify(text)

    def test_malformed_json_or_base64_rejected(self):
        for text in ("broken", json.dumps({"payload": "%%%"}), json.dumps({})):
            with self.subTest(text=text), self.assertRaises((ValueError, KeyError)):
                self.verify(text)


if __name__ == "__main__":
    unittest.main()
