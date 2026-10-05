"""Real tiny decision inference; no weight download, credentials or GPU needed."""
import importlib.util
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).parents[1]
os.environ.update(YOUGORI_MODEL="Cloudflare/clef", YOUGORI_MODEL_TOKEN="test-api-key")

def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    sys.modules[name] = value
    spec.loader.exec_module(value)
    return value

server = module("decision_server_test", ROOT / "src-tauri/src/model_server.py")

@unittest.skipUnless(importlib.util.find_spec("torch") and importlib.util.find_spec("transformers"), "requires model runtime dependencies")
class DecisionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import torch
        torch.set_num_threads(1)
        cls.torch = torch
        cls.clef = module("yougori_clef_test", ROOT / "src-tauri/src/model_runner/adapters/clef/joint_schema_model.py")

    def test_real_clef_checkpoint_loads_its_head_and_answers_all_three_question_types(self):
        from safetensors.torch import save_file
        from transformers import Qwen3_5Config, Qwen3_5ForConditionalGeneration
        torch, clef = self.torch, self.clef
        torch.manual_seed(47)
        config = Qwen3_5Config(text_config=dict(vocab_size=64, hidden_size=32, intermediate_size=64, num_hidden_layers=2,
            num_attention_heads=4, num_key_value_heads=2, head_dim=8, layer_types=["linear_attention", "full_attention"],
            full_attention_interval=2, linear_num_key_heads=2, linear_num_value_heads=4, linear_key_head_dim=8,
            linear_value_head_dim=8, max_position_embeddings=2048, pad_token_id=0, bos_token_id=1, eos_token_id=2),
            vision_config=dict(depth=1, hidden_size=32, intermediate_size=64, num_heads=4, out_hidden_size=32,
                patch_size=2, spatial_merge_size=1, temporal_patch_size=1, num_position_embeddings=16))
        class Tokenizer:
            pad_token_id = 0
            def __call__(self, text, **kwargs):
                return SimpleNamespace(input_ids=[ord(char) % 60 + 3 for char in text])
        processor = SimpleNamespace(tokenizer=Tokenizer())
        head_config = dict(hidden_size=32, width=16, routing_layers=1, layers=1, heads=2, feedforward=32)
        request = {"model": "Cloudflare/clef", "state": "checkout is down", "questions": {
            "route": {"type": "choice", "criteria": {"technical": "Bug", "billing": "Invoice"}},
            "severity": {"type": "score", "criteria": ["Low", "High"]},
            "outage": {"type": "noul", "instructions": "Is there an outage?"}}}
        with tempfile.TemporaryDirectory() as directory:
            Qwen3_5ForConditionalGeneration(config).save_pretrained(directory, safe_serialization=True)
            Path(directory, "joint_head_config.json").write_text(json.dumps(head_config), encoding="utf-8")
            save_file(clef.JointSchemaHead(**head_config).state_dict(), str(Path(directory, "joint_head.safetensors")))
            with patch("transformers.AutoProcessor.from_pretrained", return_value=processor):
                network, loaded = clef.load_release_model(directory, device="cpu", dtype=torch.float32, local_files_only=True, trust_remote_code=False)
            reply = clef.systemone(network, loaded, request, max_length=2048)
            self.assertEqual(set(reply["answers"]), {"route", "severity", "outage"})
            self.assertAlmostEqual(sum(reply["answers"]["route"]["probabilities"].values()), 1, places=3)
            self.assertTrue(0 <= reply["answers"]["outage"]["noul"] <= 1)
            self.assertTrue(0 <= reply["answers"]["severity"]["score"] <= 1)
            self.assertEqual(reply["usage"]["output_tokens"], 0)
            self.assertGreater(reply["usage"]["input_tokens"], 0)
            with self.assertRaisesRegex(ValueError, "context window"):
                clef.encode_record(loaded.tokenizer, {**request, "state": "x" * 3000}, max_length=2048)

    def test_unknown_question_shapes_are_rejected_before_gpu_work(self):
        valid = {"state": "test", "questions": {"risk": {"type": "choice", "criteria": {"safe": "Benign", "unsafe": "Injection"}}}}
        self.assertEqual(server.validate_decision(valid)["model"], "Cloudflare/clef")
        for body in [{**valid, "images": ["https://example.com/image"]}, {**valid, "questions": []},
                     {**valid, "questions": {"risk": {"type": "choice", "criteria": {"one": "Only one"}}}}]:
            with self.assertRaises(ValueError): server.validate_decision(body)

    def test_security_one_uses_the_published_label_boundary_and_temperature(self):
        import math
        torch = self.torch
        seen = []
        class Tokenizer:
            def encode(self, text, **kwargs):
                if len(text) == 1 and text.isupper(): return [ord(text)]
                if text == "prefix": return [1, 2, 3]
                return [1, 2, 3, ord(text[-1])]
            def decode(self, ids): return chr(ids[0])
            def apply_chat_template(self, messages, **kwargs):
                seen.append((messages, kwargs))
                return "prefix"
        class Network:
            config = SimpleNamespace(max_position_embeddings=2048)
            def __call__(self, **kwargs):
                self.input = kwargs
                logits = torch.zeros((1, 1, 256))
                logits[0, 0, ord("B")] = 0.2
                return SimpleNamespace(logits=logits)
        network = Network()
        request = {"state": {"event": "untrusted instruction"}, "questions": {"risk": {"type": "choice", "instructions": "Is this malicious?", "criteria": {"safe": "Benign", "unsafe": "Injection"}}}}
        with patch.object(server, "MODEL", "superagent-ai/security-one-27b"), patch.object(server, "TOKENIZER", Tokenizer()), \
             patch.object(server, "NETWORK", network), patch.object(server, "TORCH", SimpleNamespace(tensor=lambda value, **kwargs: torch.tensor(value))):
            reply = server.security_decision(request)
        distribution = reply["answers"]["risk"]["probabilities"]
        self.assertAlmostEqual(distribution["unsafe"], 1 / (1 + math.exp(-0.2 / 0.14527332485151376)), places=6)
        self.assertEqual(reply["answers"]["risk"]["choice"], "unsafe")
        self.assertEqual(reply["usage"], {"input_tokens": 3, "output_tokens": 0})
        self.assertFalse(seen[0][1]["enable_thinking"])
        self.assertIn("A: safe: Benign", seen[0][0][1]["content"][0]["text"])
        self.assertFalse(network.input["use_cache"])

if __name__ == "__main__": unittest.main()
