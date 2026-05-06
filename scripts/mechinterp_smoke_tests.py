#!/usr/bin/env python3
"""Smoke tests for mechanistic-interpretability workflows on Qwen-style causal LMs.

The default model is deliberately tiny so GitHub-hosted CPU runners can execute the
checks. To test an actual Qwen/Qwen3.5 checkpoint, run the workflow manually with a
larger `model_id` and usually a GPU/self-hosted runner.
"""

from __future__ import annotations

import argparse
import json
import math
import sys
from dataclasses import dataclass
from typing import Callable, Dict, Iterable, List, Tuple

import numpy as np
import torch
from transformers import AutoModelForCausalLM, AutoTokenizer


@dataclass
class SmokeResult:
    name: str
    ok: bool
    detail: str


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def load_model(model_id: str, device: str):
    tokenizer = AutoTokenizer.from_pretrained(model_id, trust_remote_code=True)
    model = AutoModelForCausalLM.from_pretrained(
        model_id,
        trust_remote_code=True,
        torch_dtype=torch.float32,
        low_cpu_mem_usage=False,
    )
    model.eval().to(device)
    if tokenizer.pad_token_id is None:
        tokenizer.pad_token = tokenizer.eos_token
    return tokenizer, model


def model_layers(model) -> List[torch.nn.Module]:
    # Llama/Qwen style: model.model.layers. GPT-2 style fallback: transformer.h.
    if hasattr(model, "model") and hasattr(model.model, "layers"):
        return list(model.model.layers)
    if hasattr(model, "transformer") and hasattr(model.transformer, "h"):
        return list(model.transformer.h)
    raise RuntimeError("Unsupported causal LM architecture: cannot locate transformer blocks")


def get_attn_module(layer: torch.nn.Module) -> torch.nn.Module:
    for name in ("self_attn", "attn", "attention"):
        if hasattr(layer, name):
            return getattr(layer, name)
    raise RuntimeError("Cannot locate attention module on layer")


def get_mlp_module(layer: torch.nn.Module) -> torch.nn.Module:
    for name in ("mlp", "feed_forward", "ffn"):
        if hasattr(layer, name):
            return getattr(layer, name)
    raise RuntimeError("Cannot locate MLP module on layer")


def encode(tokenizer, prompt: str, device: str) -> Dict[str, torch.Tensor]:
    return tokenizer(prompt, return_tensors="pt").to(device)


def next_token_metric(logits: torch.Tensor, target_id: int) -> float:
    return float(logits[0, -1, target_id].detach().cpu())


def run_clean_forward(tokenizer, model, device: str, prompt: str) -> Tuple[Dict[str, torch.Tensor], torch.Tensor]:
    inputs = encode(tokenizer, prompt, device)
    with torch.no_grad():
        out = model(**inputs, output_hidden_states=True, output_attentions=True, use_cache=False)
    return inputs, out.logits


def smoke_logit_lens(tokenizer, model, device: str) -> str:
    prompt = "The capital of France is"
    inputs = encode(tokenizer, prompt, device)
    with torch.no_grad():
        out = model(**inputs, output_hidden_states=True, use_cache=False)
    hidden_states = out.hidden_states
    _require(hidden_states and len(hidden_states) >= 2, "missing hidden states")
    lm_head = model.get_output_embeddings()
    layer_logits = lm_head(hidden_states[-2])
    _require(layer_logits.shape[-1] == model.config.vocab_size, "logit lens vocab mismatch")
    top_id = int(torch.argmax(layer_logits[0, -1]).item())
    return f"projected penultimate layer to vocab; top token id={top_id}"


def smoke_direct_logit_attribution(tokenizer, model, device: str) -> str:
    prompt = "2 + 2 ="
    inputs = encode(tokenizer, prompt, device)
    layers = model_layers(model)
    contributions: Dict[str, torch.Tensor] = {}

    def make_hook(name: str):
        def hook(_module, _inp, output):
            value = output[0] if isinstance(output, tuple) else output
            contributions[name] = value.detach()
        return hook

    handles = []
    for i, layer in enumerate(layers[: min(2, len(layers))]):
        handles.append(layer.register_forward_hook(make_hook(f"block_{i}")))
    try:
        with torch.no_grad():
            out = model(**inputs, use_cache=False)
    finally:
        for h in handles:
            h.remove()

    _require(contributions, "no block contributions captured")
    target_id = int(torch.argmax(out.logits[0, -1]).item())
    lm_head = model.get_output_embeddings()
    scores = {}
    for name, tensor in contributions.items():
        logits = lm_head(tensor)
        scores[name] = float(logits[0, -1, target_id].detach().cpu())
    _require(all(math.isfinite(v) for v in scores.values()), "non-finite DLA score")
    return f"computed component contribution scores for target token {target_id}: {scores}"


def smoke_activation_patching(tokenizer, model, device: str) -> str:
    clean = "The capital of France is Paris. The capital of France is"
    corrupted = "The capital of France is Rome. The capital of France is"
    target_text = " Paris"
    target_ids = tokenizer(target_text, add_special_tokens=False).input_ids
    _require(target_ids, "target tokenization failed")
    target_id = int(target_ids[0])
    layers = model_layers(model)
    target_layer = layers[min(1, len(layers) - 1)]

    clean_cache: Dict[str, torch.Tensor] = {}

    def save_hook(_module, _inp, output):
        value = output[0] if isinstance(output, tuple) else output
        clean_cache["activation"] = value.detach()

    h = target_layer.register_forward_hook(save_hook)
    try:
        with torch.no_grad():
            model(**encode(tokenizer, clean, device), use_cache=False)
    finally:
        h.remove()
    _require("activation" in clean_cache, "clean activation not cached")

    def patch_hook(_module, _inp, output):
        patched = clean_cache["activation"]
        if isinstance(output, tuple):
            return (patched,) + output[1:]
        return patched

    with torch.no_grad():
        corrupt_logits = model(**encode(tokenizer, corrupted, device), use_cache=False).logits
    h = target_layer.register_forward_hook(patch_hook)
    try:
        with torch.no_grad():
            patched_logits = model(**encode(tokenizer, corrupted, device), use_cache=False).logits
    finally:
        h.remove()

    before = next_token_metric(corrupt_logits, target_id)
    after = next_token_metric(patched_logits, target_id)
    _require(math.isfinite(before) and math.isfinite(after), "non-finite patching metric")
    return f"patched layer {layers.index(target_layer)}; target-logit delta={after - before:.4f}"


def smoke_ablation(tokenizer, model, device: str) -> str:
    prompt = "A B C D E F"
    inputs = encode(tokenizer, prompt, device)
    layers = model_layers(model)
    mlp = get_mlp_module(layers[0])

    with torch.no_grad():
        base_logits = model(**inputs, use_cache=False).logits

    def zero_hook(_module, _inp, output):
        value = output[0] if isinstance(output, tuple) else output
        z = torch.zeros_like(value)
        if isinstance(output, tuple):
            return (z,) + output[1:]
        return z

    h = mlp.register_forward_hook(zero_hook)
    try:
        with torch.no_grad():
            ablated_logits = model(**inputs, use_cache=False).logits
    finally:
        h.remove()

    diff = float(torch.mean(torch.abs(base_logits - ablated_logits)).detach().cpu())
    _require(math.isfinite(diff), "non-finite ablation diff")
    return f"zero-ablated first MLP; mean absolute logit diff={diff:.6f}"


def smoke_attention_analysis(tokenizer, model, device: str) -> str:
    prompt = "alpha beta gamma alpha beta"
    inputs = encode(tokenizer, prompt, device)
    with torch.no_grad():
        out = model(**inputs, output_attentions=True, use_cache=False)
    attentions = out.attentions
    _require(attentions and len(attentions) > 0, "no attentions returned")
    first = attentions[0]
    _require(first.ndim == 4, "attention tensor should be [batch, heads, q, k]")
    row_sum = first[0, 0, -1].sum().item()
    _require(abs(row_sum - 1.0) < 1e-3 or row_sum > 0, "attention weights look invalid")
    return f"captured {len(attentions)} attention tensors; first shape={tuple(first.shape)}"


def smoke_probe(tokenizer, model, device: str) -> str:
    prompts = ["good", "great", "bad", "terrible"]
    labels = torch.tensor([1, 1, 0, 0], device=device, dtype=torch.float32)
    reps = []
    with torch.no_grad():
        for p in prompts:
            out = model(**encode(tokenizer, p, device), output_hidden_states=True, use_cache=False)
            reps.append(out.hidden_states[-1][0, -1].detach())
    x = torch.stack(reps)
    x = torch.cat([x, torch.ones(x.shape[0], 1, device=device)], dim=1)
    # Least squares linear probe. Use CPU fallback for compatibility.
    solution = torch.linalg.lstsq(x.cpu(), labels.cpu().unsqueeze(1)).solution
    pred = (x.cpu() @ solution).squeeze(1)
    _require(torch.isfinite(pred).all().item(), "probe predictions non-finite")
    return f"fit tiny linear probe; predictions={pred.tolist()}"


def smoke_steering(tokenizer, model, device: str) -> str:
    pos = encode(tokenizer, "I love this", device)
    neg = encode(tokenizer, "I hate this", device)
    test = encode(tokenizer, "This is", device)
    layers = model_layers(model)
    target_layer = layers[min(1, len(layers) - 1)]

    with torch.no_grad():
        pos_h = model(**pos, output_hidden_states=True, use_cache=False).hidden_states[min(2, len(layers))][0, -1]
        neg_h = model(**neg, output_hidden_states=True, use_cache=False).hidden_states[min(2, len(layers))][0, -1]
    direction = (pos_h - neg_h).detach()
    direction = direction / (torch.norm(direction) + 1e-6)

    with torch.no_grad():
        base = model(**test, use_cache=False).logits

    def steer_hook(_module, _inp, output):
        value = output[0] if isinstance(output, tuple) else output
        steered = value.clone()
        steered[:, -1, :] = steered[:, -1, :] + 0.5 * direction
        if isinstance(output, tuple):
            return (steered,) + output[1:]
        return steered

    h = target_layer.register_forward_hook(steer_hook)
    try:
        with torch.no_grad():
            steered = model(**test, use_cache=False).logits
    finally:
        h.remove()
    diff = float(torch.mean(torch.abs(base - steered)).detach().cpu())
    _require(diff > 0, "steering had no effect")
    return f"applied contrastive steering vector; mean absolute logit diff={diff:.6f}"


def smoke_sae_surrogate(tokenizer, model, device: str) -> str:
    prompt = "one two three four five"
    with torch.no_grad():
        out = model(**encode(tokenizer, prompt, device), output_hidden_states=True, use_cache=False)
    x = out.hidden_states[-1][0].detach().cpu()
    hidden = x.shape[-1]
    expansion = 2
    encoder = torch.nn.Linear(hidden, hidden * expansion, bias=True)
    decoder = torch.nn.Linear(hidden * expansion, hidden, bias=True)
    with torch.no_grad():
        features = torch.relu(encoder(x))
        recon = decoder(features)
    mse = float(torch.mean((recon - x) ** 2).item())
    sparsity = float((features <= 1e-8).float().mean().item())
    _require(math.isfinite(mse) and math.isfinite(sparsity), "SAE surrogate metrics non-finite")
    return f"ran SAE-style encode/decode surrogate; mse={mse:.6f}, zero_frac={sparsity:.3f}"


def smoke_circuit_pruning_surrogate(tokenizer, model, device: str) -> str:
    prompt = "repeat repeat repeat"
    inputs = encode(tokenizer, prompt, device)
    layers = model_layers(model)
    attn = get_attn_module(layers[0])
    mlp = get_mlp_module(layers[0])

    with torch.no_grad():
        base = model(**inputs, use_cache=False).logits

    def zero_hook(_module, _inp, output):
        value = output[0] if isinstance(output, tuple) else output
        z = torch.zeros_like(value)
        if isinstance(output, tuple):
            return (z,) + output[1:]
        return z

    diffs = {}
    for name, module in [("attn0", attn), ("mlp0", mlp)]:
        h = module.register_forward_hook(zero_hook)
        try:
            with torch.no_grad():
                logits = model(**inputs, use_cache=False).logits
        finally:
            h.remove()
        diffs[name] = float(torch.mean(torch.abs(base - logits)).detach().cpu())
    _require(all(math.isfinite(v) for v in diffs.values()), "pruning diffs non-finite")
    return f"estimated two candidate subnetwork effects: {diffs}"


SMOKE_TESTS: Dict[str, Callable] = {
    "logit_lens": smoke_logit_lens,
    "direct_logit_attribution": smoke_direct_logit_attribution,
    "activation_patching": smoke_activation_patching,
    "ablation": smoke_ablation,
    "attention_analysis": smoke_attention_analysis,
    "probing": smoke_probe,
    "steering": smoke_steering,
    "sae_surrogate": smoke_sae_surrogate,
    "circuit_pruning_surrogate": smoke_circuit_pruning_surrogate,
}


def parse_args(argv: Iterable[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--model-id", default="hf-internal-testing/tiny-random-LlamaForCausalLM")
    parser.add_argument("--device", default="cpu")
    parser.add_argument("--tests", default="all", help="Comma-separated test names or 'all'")
    parser.add_argument("--report", default="mechinterp_report.json")
    return parser.parse_args(list(argv))


def main(argv: Iterable[str]) -> int:
    args = parse_args(argv)
    selected = list(SMOKE_TESTS) if args.tests == "all" else [x.strip() for x in args.tests.split(",") if x.strip()]
    unknown = sorted(set(selected) - set(SMOKE_TESTS))
    if unknown:
        raise SystemExit(f"Unknown tests: {unknown}. Known tests: {sorted(SMOKE_TESTS)}")

    tokenizer, model = load_model(args.model_id, args.device)
    results: List[SmokeResult] = []
    for name in selected:
        try:
            detail = SMOKE_TESTS[name](tokenizer, model, args.device)
            results.append(SmokeResult(name=name, ok=True, detail=detail))
            print(f"PASS {name}: {detail}")
        except Exception as exc:  # noqa: BLE001 - CI report should collect all failures.
            results.append(SmokeResult(name=name, ok=False, detail=repr(exc)))
            print(f"FAIL {name}: {exc}", file=sys.stderr)

    payload = {
        "model_id": args.model_id,
        "device": args.device,
        "results": [r.__dict__ for r in results],
    }
    with open(args.report, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)

    return 0 if all(r.ok for r in results) else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
