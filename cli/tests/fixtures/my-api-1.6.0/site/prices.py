"""Default selling prices for every model the site serves, in US dollars per million
tokens (input, output).

How a default is chosen, so the site sells at the market rate and never below cost:

1. Your cost is the provider's own published price (LIST_PRICES), or the price a
   gateway reports with its catalogue. Introductory prices apply until their last day;
   the regular price then takes over by itself (PROMOTIONS).
2. The market is what OpenRouter charges for the same model today (MARKET, MARKET_OPEN).
3. The default is the higher of the two: it follows the market and never undercuts
   what the provider charges you.
4. Models on your own GPU (Ollama) default to the market price of the same open model
   (OPEN_MODELS), or to the market rate for open models of that size.
5. A model nobody publishes a price for gets a cautious estimate for its class
   (ESTIMATES), marked as an estimate so the admin can check it.
6. Free gateway models stay free. Image, audio, embedding and realtime models get no
   default: a per-token text price would undercharge them.

The admin's markup is added on top, and a price the admin sets by hand always wins.
"""
import re
from datetime import date

AS_OF = "2026-10-24"

SOURCES = {
    "openai": "https://developers.openai.com/api/docs/pricing",
    "anthropic": "https://platform.claude.com/docs/en/about-claude/pricing",
    "google": "https://ai.google.dev/gemini-api/docs/pricing",
    "market": "https://openrouter.ai/models",
}

# The providers' own standard prices (not batch, cached or priority), checked on AS_OF.
LIST_PRICES = {
    "openai": {
        "gpt-6-astra": (10.00, 50.00),
        "gpt-6.1-sol": (2.00, 10.00),
        "gpt-6-sol": (2.00, 10.00),
        "gpt-6-luna": (0.10, 0.50),
        "gpt-5.6-sol": (4.00, 20.00),
        "gpt-5.6-terra": (2.00, 12.00),
        "gpt-5.6-luna": (0.20, 1.20),
        "gpt-5.6-cyber": (12.50, 75.00),
        "gpt-5.5": (5.00, 30.00),
        "gpt-5.5-pro": (30.00, 180.00),
        "gpt-5.5-cyber": (12.50, 75.00),
        "gpt-5.4": (2.50, 15.00),
        "gpt-5.4-pro": (30.00, 180.00),
        "gpt-5.4-mini": (0.75, 4.50),
        "gpt-5.4-nano": (0.20, 1.25),
        "gpt-5.3-codex": (1.75, 14.00),
        "gpt-5.2": (1.75, 14.00),
        "gpt-5.2-pro": (21.00, 168.00),
        "gpt-5.1": (1.25, 10.00),
        "gpt-5": (1.25, 10.00),
        "gpt-5-mini": (0.25, 2.00),
        "gpt-5-nano": (0.05, 0.40),
        "gpt-5-pro": (15.00, 120.00),
        "gpt-5-search-api": (1.25, 10.00),
        "gpt-rosalind-research": (5.00, 25.00),
        "gpt-rosalind-discovery": (5.00, 25.00),
        "gpt-4.1": (2.00, 8.00),
        "gpt-4.1-mini": (0.40, 1.60),
        "gpt-4.1-nano": (0.10, 0.40),
        "gpt-4o": (2.50, 10.00),
        "gpt-4o-2024-05-13": (5.00, 15.00),
        "gpt-4o-mini": (0.15, 0.60),
        "gpt-4-turbo": (10.00, 30.00),
        "gpt-4-turbo-2024-04-09": (10.00, 30.00),
        "gpt-4": (30.00, 60.00),
        "gpt-4-0613": (30.00, 60.00),
        "gpt-3.5-turbo": (0.50, 1.50),
        "gpt-3.5-turbo-0125": (0.50, 1.50),
        "chat-latest": (5.00, 30.00),
        "o1": (15.00, 60.00),
        "o1-pro": (150.00, 600.00),
        "o3": (2.00, 8.00),
        "o3-pro": (20.00, 80.00),
        "o3-mini": (1.10, 4.40),
        "o4-mini": (1.10, 4.40),
    },
    "anthropic": {
        "claude-fable-5-1": (10.00, 50.00),
        "claude-mythos-5-1": (10.00, 50.00),
        "claude-fable-5": (10.00, 50.00),
        "claude-mythos-5": (10.00, 50.00),
        "claude-opus-5-5": (4.00, 20.00),
        "claude-opus-5": (5.00, 25.00),
        "claude-opus-4-8": (5.00, 25.00),
        "claude-opus-4-7": (5.00, 25.00),
        "claude-opus-4-6": (5.00, 25.00),
        "claude-opus-4-5": (5.00, 25.00),
        "claude-opus-4-1": (15.00, 75.00),
        "claude-opus-4": (15.00, 75.00),
        "claude-sonnet-5-5": (2.00, 10.00),
        "claude-sonnet-5": (2.00, 10.00),
        "claude-sonnet-4-6": (3.00, 15.00),
        "claude-sonnet-4-5": (3.00, 15.00),
        "claude-sonnet-4": (3.00, 15.00),
        # $0.10/$0.50 up to 100K prompt tokens; a 64 KiB request never reaches that.
        "claude-haiku-5-5": (0.10, 0.50),
        "claude-haiku-4-5": (1.00, 5.00),
        "claude-3-5-haiku": (0.80, 4.00),
    },
    "google": {
        "gemini-3.5-flash-lite": (0.30, 2.50),
        "gemini-3.1-flash-lite": (0.25, 1.50),
        "gemini-omni-1.1-flash": (1.50, 9.00),
        "gemini-3.1-pro-preview": (2.00, 12.00),
        "gemini-3.1-pro-preview-customtools": (2.00, 12.00),
        "gemini-3-flash-preview": (0.50, 3.00),
        "gemini-2.5-pro": (1.25, 10.00),
        "gemini-2.5-flash": (0.30, 2.50),
        "gemini-2.5-flash-lite": (0.10, 0.40),
    },
}

# Introductory prices: (price until the last day, last day, price from the next day).
PROMOTIONS = {
    ("google", "gemini-4-argon"): ((2.00, 10.00), "2026-11-30", (4.00, 20.00)),
    ("google", "gemini-3.8-flash"): ((0.75, 3.75), "2026-12-31", (1.50, 7.50)),
    ("google", "gemini-3.6-flash"): ((0.75, 3.75), "2026-12-31", (1.50, 7.50)),
    # Not on Google's page; the market sells it at the 3.6/3.8 introductory rate. It is
    # assumed to end with theirs, so its default rises with them rather than undercut cost.
    ("google", "gemini-3.7-flash"): ((0.75, 3.75), "2026-12-31", (1.50, 7.50)),
}
# Promotional prices with no announced end price: shown to the admin as a reminder.
OPEN_ENDED = {("openai", "gpt-5.6-sol"): "2026-11-21"}

# What the market (OpenRouter) charges today for models also sold by their makers.
MARKET = {
    "openai": {
        "gpt-3.5-turbo": (0.5, 1.5),
        "gpt-3.5-turbo-0613": (1, 2),
        "gpt-3.5-turbo-16k": (3, 4),
        "gpt-3.5-turbo-instruct": (1.5, 2),
        "gpt-4": (30, 60),
        "gpt-4-turbo": (10, 30),
        "gpt-4.1": (2, 8),
        "gpt-4.1-mini": (0.4, 1.6),
        "gpt-4.1-nano": (0.1, 0.4),
        "gpt-4o": (2.5, 10),
        "gpt-4o-2024-05-13": (5, 15),
        "gpt-4o-2024-08-06": (2.5, 10),
        "gpt-4o-2024-11-20": (2.5, 10),
        "gpt-4o-mini": (0.15, 0.6),
        "gpt-4o-mini-2024-07-18": (0.15, 0.6),
        "gpt-5": (1.25, 10),
        "gpt-5-mini": (0.25, 2),
        "gpt-5-nano": (0.05, 0.4),
        "gpt-5-pro": (15, 120),
        "gpt-5.1": (1.25, 10),
        "gpt-5.1-codex": (1.25, 10),
        "gpt-5.1-codex-max": (1.25, 10),
        "gpt-5.1-codex-mini": (0.25, 2),
        "gpt-5.2": (1.75, 14),
        "gpt-5.2-chat": (1.75, 14),
        "gpt-5.2-codex": (1.75, 14),
        "gpt-5.2-pro": (21, 168),
        "gpt-5.3-codex": (1.75, 14),
        "gpt-5.4": (2.5, 15),
        "gpt-5.4-mini": (0.75, 4.5),
        "gpt-5.4-nano": (0.2, 1.25),
        "gpt-5.4-pro": (30, 180),
        "gpt-5.5": (5, 30),
        "gpt-5.5-pro": (30, 180),
        "gpt-5.6-luna": (0.2, 1.2),
        "gpt-5.6-luna-pro": (0.2, 1.2),
        "gpt-5.6-sol": (4, 20),
        "gpt-5.6-sol-pro": (4, 20),
        "gpt-5.6-terra": (2, 12),
        "gpt-5.6-terra-pro": (2, 12),
        "gpt-6-astra": (10, 50),
        "gpt-6-astra-pro": (10, 50),
        "gpt-6-luna": (0.1, 0.5),
        "gpt-6-luna-pro": (0.1, 0.5),
        "gpt-6-sol": (2, 10),
        "gpt-6-sol-pro": (2, 10),
        "gpt-6.1-sol": (2, 10),
        "gpt-6.1-sol-pro": (2, 10),
        "gpt-chat-latest": (5, 30),
        "o1": (15, 60),
        "o1-pro": (150, 600),
        "o3": (2, 8),
        "o3-mini": (1.1, 4.4),
        "o3-mini-high": (1.1, 4.4),
        "o3-pro": (20, 80),
        "o4-mini": (1.1, 4.4),
        "o4-mini-high": (1.1, 4.4),
    },
    "anthropic": {
        "claude-fable-5": (10, 50),
        "claude-fable-5-1": (10, 50),
        "claude-haiku-4-5": (1, 5),
        "claude-haiku-5-5": (0.1, 0.5),
        "claude-opus-4-1": (15, 75),
        "claude-opus-4-5": (5, 25),
        "claude-opus-4-6": (5, 25),
        "claude-opus-4-7": (5, 25),
        "claude-opus-4-8": (5, 25),
        "claude-opus-5": (5, 25),
        "claude-opus-5-5": (4, 20),
        "claude-sonnet-4-5": (3, 15),
        "claude-sonnet-4-6": (3, 15),
        "claude-sonnet-5": (2, 10),
        "claude-sonnet-5-5": (2, 10),
    },
    "google": {
        "gemini-2.5-flash": (0.3, 2.5),
        "gemini-2.5-flash-lite": (0.1, 0.4),
        "gemini-2.5-pro": (1.25, 10),
        "gemini-2.5-pro-preview": (1.25, 10),
        "gemini-3-flash-preview": (0.5, 3),
        "gemini-3.1-flash-lite": (0.25, 1.5),
        "gemini-3.1-flash-lite-preview": (0.25, 1.5),
        "gemini-3.1-pro-preview": (2, 12),
        "gemini-3.1-pro-preview-customtools": (2, 12),
        "gemini-3.5-flash": (1.5, 9),
        "gemini-3.5-flash-lite": (0.3, 2.5),
        "gemini-3.6-flash": (0.75, 3.75),
        "gemini-3.7-flash": (0.75, 3.75),
        "gemini-3.8-flash": (0.825, 4.125),
        "gemini-4-argon": (2, 10),
        "gemma-2-27b-it": (0.65, 0.65),
        "gemma-3-12b-it": (0.05, 0.15),
        "gemma-3-27b-it": (0.08, 0.35),
        "gemma-3-4b-it": (0.04, 0.05),
        "gemma-4-26b-a4b-it": (0.0675, 0.225),
        "gemma-4-31b-it": (0.2, 0.4),
    },
}
# Open models sold by many hosts, by bare model name, for gateway IDs without a vendor.
MARKET_OPEN = {
    "codestral-2508": (0.3, 0.9),
    "command-a": (2.5, 10),
    "command-a-plus": (0.3, 1.5),
    "command-r-08-2024": (0.15, 0.6),
    "command-r-plus-08-2024": (2.5, 10),
    "command-r7b-12-2024": (0.0375, 0.15),
    "deepseek-chat": (0.2574, 1.0287),
    "deepseek-chat-v3-0324": (0.29, 1.14),
    "deepseek-chat-v3.1": (0.25, 0.95),
    "deepseek-r1-0528": (0.5, 2.15),
    "deepseek-v3.1-terminus": (0.27, 1),
    "deepseek-v3.2": (0.28, 0.42),
    "deepseek-v3.2-exp": (0.27, 0.41),
    "deepseek-v4-flash": (0.091, 0.182),
    "deepseek-v4-flash-0731": (0.0444, 0.1333),
    "deepseek-v4-pro": (0.2871, 0.5742),
    "deepseek-v4-pro-0813": (0.66, 1.98),
    "deepseek-v4.1-flash": (0.02, 1),
    "deepseek-v4.1-flash-1017": (0.15, 0.6),
    "devstral-2512": (0.4, 2),
    "glm-4.5": (0.6, 2.2),
    "glm-4.5-air": (0.13, 0.85),
    "glm-4.5v": (0.6, 1.8),
    "glm-4.6": (0.55, 2.2),
    "glm-4.6v": (0.3, 0.9),
    "glm-4.7": (0.54, 1.98),
    "glm-4.7-flash": (0.0605, 0.4),
    "glm-5": (1, 3.2),
    "glm-5-turbo": (1.2, 4),
    "glm-5.1": (1.4, 4.4),
    "glm-5.2": (0.0341, 7),
    "glm-5.3": (0.079, 1.4),
    "glm-5.3-flash": (0.0175, 0.0788),
    "glm-5.3-flashx": (0.37, 1.25),
    "glm-5.3-prime": (2.8, 8.8),
    "glm-5v-turbo": (1.2, 4),
    "granite-4.0-h-micro": (0.017, 0.112),
    "granite-4.2-8b": (0.06, 0.25),
    "hermes-3-llama-3.1-405b": (1, 1),
    "hermes-3-llama-3.1-70b": (0.7, 0.7),
    "hermes-4-405b": (1, 3),
    "hunyuan-a13b-instruct": (0.14, 0.57),
    "hy-mt2-1.8b": (0.044, 0.177),
    "hy-mt2-30b-a3b": (0.074, 0.295),
    "hy-mt2-7b": (0.074, 0.295),
    "hy3": (0.132, 0.528),
    "hy3-preview": (0.18, 0.6),
    "hy4-preview": (0.834, 2.501),
    "kimi-k2": (0.57, 2.3),
    "kimi-k2-0905": (0.6, 2.5),
    "kimi-k2-thinking": (0.6, 2.5),
    "kimi-k2.5": (0.5, 2.5),
    "kimi-k2.6": (0.65, 3.41),
    "kimi-k2.7-code": (0.6712, 3.35),
    "kimi-k3": (0.239, 10.8),
    "kimi-k3.1-pro": (2, 10),
    "llama-3.1-70b-instruct": (0.4, 0.4),
    "llama-3.1-8b-instruct": (0.05, 0.08),
    "llama-3.2-1b-instruct": (0.027, 0.201),
    "llama-3.2-3b-instruct": (0.0509, 0.335),
    "llama-3.3-70b-instruct": (0.1, 0.32),
    "llama-4-maverick": (0.1875, 0.6525),
    "llama-4-scout": (0.1, 0.3),
    "mimo-v2.5": (0.119, 0.238),
    "mimo-v2.5-pro": (0.3045, 0.609),
    "mimo-v2.6-flash": (0.14, 0.28),
    "mimo-v2.6-pro": (0.435, 0.87),
    "minimax-01": (0.2, 1.1),
    "minimax-m1": (0.55, 2.2),
    "minimax-m2": (0.255, 1.02),
    "minimax-m2-her": (0.3, 1.2),
    "minimax-m2.1": (0.3, 1.2),
    "minimax-m2.5": (0.3, 1.2),
    "minimax-m2.7": (0.3, 1.2),
    "minimax-m3": (0.3, 1.2),
    "minimax-m3.1-flash": (0.15, 0.6),
    "ministral-14b-2512": (0.2, 0.2),
    "ministral-3b-2512": (0.1, 0.1),
    "ministral-8b-2512": (0.15, 0.15),
    "mistral-large": (2, 6),
    "mistral-large-2407": (2, 6),
    "mistral-large-2512": (0.5, 1.5),
    "mistral-large-4-0": (1.36, 4.18),
    "mistral-medium-3": (0.4, 2),
    "mistral-medium-3-5": (1.5, 7.5),
    "mistral-medium-3.1": (0.4, 2),
    "mistral-nemo": (0.029, 0.03),
    "mistral-saba": (0.2, 0.6),
    "mistral-small-24b-instruct-2501": (0.05, 0.08),
    "mistral-small-2603": (0.15, 0.6),
    "mistral-small-3.1-24b-instruct": (0.351, 0.555),
    "mistral-small-3.2-24b-instruct": (0.075, 0.2),
    "mixtral-8x22b-instruct": (2, 6),
    "nemotron-3-nano-30b-a3b": (0.06, 0.24),
    "nemotron-3-super-120b-a12b": (0.3, 2.4),
    "nemotron-3-ultra-550b-a55b": (0.6, 2.4),
    "nemotron-3.5-lightning": (0.07, 0.2),
    "nemotron-3.5-super-vl": (0.15, 0.5),
    "phi-4": (0.07, 0.14),
    "qwen-2.5-72b-instruct": (0.36, 0.4),
    "qwen-2.5-7b-instruct": (0.1, 0.2),
    "qwen-2.5-coder-32b-instruct": (0.66, 1),
    "qwen-plus": (0.26, 0.78),
    "qwen3-14b": (0.12, 0.24),
    "qwen3-235b-a22b-2507": (0.09, 0.55),
    "qwen3-235b-a22b-thinking-2507": (0.45, 3.5),
    "qwen3-30b-a3b": (0.12, 0.5),
    "qwen3-30b-a3b-instruct-2507": (0.09, 0.3),
    "qwen3-32b": (0.08, 0.28),
    "qwen3-coder": (0.3, 1),
    "qwen3-coder-30b-a3b-instruct": (0.07, 0.28),
    "qwen3-coder-flash": (0.195, 0.975),
    "qwen3-coder-next": (0.12, 0.8),
    "qwen3-next-80b-a3b-instruct": (0.09, 1.1),
    "qwen3-next-80b-a3b-thinking": (0.15, 1.2),
    "qwen3.5-122b-a10b": (0.4, 3.2),
    "qwen3.5-27b": (0.27, 2.16),
    "qwen3.5-35b-a3b": (0.14, 1),
    "qwen3.5-397b-a17b": (0.5, 3.6),
    "qwen3.5-9b": (0.17, 0.25),
    "qwen3.5-flash-02-23": (0.065, 0.26),
    "qwen3.5-plus-02-15": (0.26, 1.56),
    "qwen3.5-plus-20260420": (0.3, 1.8),
    "qwen3.6-27b": (0.25, 2),
    "qwen3.6-35b-a3b": (0.1, 0.95),
    "qwen3.6-flash": (0.1875, 1.125),
    "qwen3.6-plus": (0.325, 1.95),
    "qwen3.7-flash": (0.03, 0.13),
    "qwen3.7-max": (1.475, 4.425),
    "qwen3.7-plus": (0.32, 1.28),
    "qwen3.8-2.4t-a95b": (2, 6),
    "qwen3.8-27b": (0.2, 2.5),
    "qwen3.8-flash": (0.15, 0.47),
    "qwen3.8-max-0902": (2, 6),
    "qwen3.8-max-prime": (4, 12),
    "voxtral-small-24b-2507": (0.1, 0.3),
}

# Ollama models: (family, size tag) -> the market price of the same open model.
OPEN_MODELS = {
    ("llama3.3", "70b"): (0.10, 0.32),
    ("llama3.1", "8b"): (0.05, 0.08),
    ("llama3.1", "70b"): (0.40, 0.40),
    ("llama3.2", "1b"): (0.027, 0.201),
    ("llama3.2", "3b"): (0.0509, 0.335),
    ("llama4", "scout"): (0.10, 0.30),
    ("llama4", "16x17b"): (0.10, 0.30),
    ("llama4", "maverick"): (0.1875, 0.6525),
    ("llama4", "128x17b"): (0.1875, 0.6525),
    ("qwen3", "14b"): (0.12, 0.24),
    ("qwen3", "30b"): (0.12, 0.50),
    ("qwen3", "32b"): (0.08, 0.28),
    ("qwen3", "235b"): (0.09, 0.55),
    ("qwen3-coder", "30b"): (0.07, 0.28),
    ("qwen3-coder", "480b"): (0.30, 1.00),
    ("qwen3-next", "80b"): (0.09, 1.10),
    ("qwen3.5", "9b"): (0.17, 0.25),
    ("qwen3.5", "27b"): (0.27, 2.16),
    ("qwen3.5", "35b"): (0.14, 1.00),
    ("qwen3.5", "122b"): (0.40, 3.20),
    ("qwen3.5", "397b"): (0.50, 3.60),
    ("qwen3.6", "27b"): (0.25, 2.00),
    ("qwen3.6", "35b"): (0.10, 0.95),
    ("qwen3.8", "27b"): (0.20, 2.50),
    ("qwen2.5", "7b"): (0.10, 0.20),
    ("qwen2.5", "72b"): (0.36, 0.40),
    ("qwen2.5-coder", "32b"): (0.66, 1.00),
    ("gemma3", "4b"): (0.04, 0.05),
    ("gemma3", "12b"): (0.05, 0.15),
    ("gemma3", "27b"): (0.08, 0.35),
    ("gemma2", "27b"): (0.65, 0.65),
    ("gemma4", "26b"): (0.0675, 0.225),
    ("gemma4", "31b"): (0.20, 0.40),
    ("deepseek-r1", "671b"): (0.50, 2.15),
    ("deepseek-v3", "671b"): (0.29, 1.14),
    ("deepseek-v3.1", "671b"): (0.25, 0.95),
    ("mistral-nemo", "12b"): (0.029, 0.03),
    ("mistral-small", "24b"): (0.05, 0.08),
    ("mistral-small3.1", "24b"): (0.351, 0.555),
    ("mistral-small3.2", "24b"): (0.075, 0.20),
    ("mixtral", "8x22b"): (2.00, 6.00),
    ("ministral-3", "3b"): (0.10, 0.10),
    ("ministral-3", "8b"): (0.15, 0.15),
    ("ministral-3", "14b"): (0.20, 0.20),
    ("phi4", "14b"): (0.07, 0.14),
    ("gpt-oss", "20b"): (0.018, 0.09),
    ("gpt-oss", "120b"): (0.15, 0.60),
    ("nemotron-3-nano", "30b"): (0.06, 0.24),
    ("nemotron-3-super", "120b"): (0.30, 2.40),
    ("command-r7b", "7b"): (0.0375, 0.15),
    ("hermes3", "70b"): (0.70, 0.70),
    ("hermes3", "405b"): (1.00, 1.00),
}
# The size Ollama pulls for a bare or ":latest" name.
OLLAMA_DEFAULT_SIZE = {
    "llama3.3": "70b", "llama3.2": "3b", "llama3.1": "8b", "llama3": "8b", "llama4": "scout",
    "qwen3": "8b", "qwen2.5": "7b", "qwen2.5-coder": "7b", "qwen3-coder": "30b", "qwq": "32b",
    "gemma3": "4b", "gemma2": "9b", "deepseek-r1": "8b", "deepseek-v3": "671b", "mistral": "7b",
    "mistral-nemo": "12b", "mistral-small": "24b", "mistral-small3.2": "24b", "phi4": "14b",
    "phi3": "3.8b", "gpt-oss": "20b", "command-r7b": "7b", "codellama": "7b", "llava": "7b",
}
# The market rate for open models by size in billions of parameters, when no exact match exists.
SIZE_TIERS = ((4, (0.05, 0.20)), (9, (0.10, 0.20)), (16, (0.10, 0.25)), (40, (0.12, 0.40)),
              (80, (0.30, 0.50)), (150, (0.30, 1.00)), (float("inf"), (0.50, 2.00)))
UNKNOWN_SIZE = (0.15, 0.50)

# Cautious estimates for paid models nobody publishes a price for: the dearest current
# model of the same kind, so an estimate errs towards charging more, never less.
ESTIMATES = {
    "openai": (("nano", (0.20, 1.25)), ("mini", (0.75, 4.50)), ("luna", (0.20, 1.20)), ("pro", (30.00, 180.00)), ("", (10.00, 50.00))),
    "anthropic": (("haiku", (1.00, 5.00)), ("sonnet", (3.00, 15.00)), ("opus", (15.00, 75.00)), ("", (10.00, 50.00))),
    "google": (("gemma", (0.65, 0.65)), ("lite", (0.30, 2.50)), ("flash", (1.50, 9.00)), ("pro", (4.00, 18.00)), ("", (4.00, 20.00))),
    "gateway": (("", (3.00, 12.00)),),
}

# Models that do not answer text chat get no per-token default.
NOT_CHAT = re.compile(r"embed|image|imagen|veo|lyria|tts|audio|realtime|transcri|live|robotics|aqa|moderation|banana|computer-use|guard|safety")

# A dated or numbered snapshot of a listed model costs what the model costs:
# gpt-4o-mini-2024-07-18, gemini-2.5-flash-001, claude-...-20250929, ...-latest.
# Anything else (a preview build, an image variant) is not assumed to match.
_SNAPSHOT = re.compile(r"-(?:\d{4}-\d{2}-\d{2}|\d{8}|\d{3}|latest)$")


def _plain(upstream):
    return upstream[len("models/"):] if upstream.startswith("models/") else upstream


def _lookup(table, name):
    if name in table:
        return table[name]
    base = _SNAPSHOT.sub("", name)
    return table.get(base) if base != name else None


def _today(today):
    return (today or date.today()).isoformat()


def list_price(provider, upstream, today=None):
    """What the provider charges for the model today, or None when this table does not know.
    An exact ID wins over a snapshot match, so gpt-4o-2024-05-13 keeps its own price."""
    if not isinstance(upstream, str):
        return None
    name = _plain(upstream)
    for key in (name, _SNAPSHOT.sub("", name)):
        if (provider, key) in PROMOTIONS:
            intro, last_day, after = PROMOTIONS[(provider, key)]
            return intro if _today(today) <= last_day else after
    return _lookup(LIST_PRICES.get(provider, {}), name)


def promotion_ends(provider, upstream, today=None):
    """The last day of an introductory price that applies today, or None."""
    if not isinstance(upstream, str):
        return None
    name = _plain(upstream)
    for key in (name, _SNAPSHOT.sub("", name)):
        if (provider, key) in PROMOTIONS and _today(today) <= PROMOTIONS[(provider, key)][1]:
            return PROMOTIONS[(provider, key)][1]
        if (provider, key) in OPEN_ENDED and _today(today) <= OPEN_ENDED[(provider, key)]:
            return OPEN_ENDED[(provider, key)]
    return None


def market_price(provider, upstream):
    """What the market charges today for the same model, or None."""
    if not isinstance(upstream, str):
        return None
    name = _plain(upstream)
    # A gateway's free tier is the same model as its paid listing.
    if name.endswith(":free"):
        name = name[:-len(":free")]
    if provider in MARKET:
        return _lookup(MARKET[provider], name.replace(".", "-") if provider == "anthropic" else name)
    # Gateway IDs are "vendor/model" or a bare model name.
    vendor, _, bare = name.rpartition("/")
    if vendor in MARKET:
        return market_price(vendor, bare)
    return _lookup(MARKET_OPEN, bare)


def _billions(size):
    match = re.fullmatch(r"(?:(\d+(?:\.\d+)?)x)?e?(\d+(?:\.\d+)?)([bm])", size or "")
    if not match:
        return None
    count = float(match.group(1) or 1) * float(match.group(2))
    return count / 1000 if match.group(3) == "m" else count


def local_price(upstream):
    """((input, output), source) for an Ollama model: the market price of the same open
    model, or the market rate for its size."""
    name = upstream.lower().rsplit("/", 1)[-1]
    family, _, tag = name.partition(":")
    tag = tag or "latest"
    match = re.match(r"(?:\d+(?:\.\d+)?x)?e?\d+(?:\.\d+)?[bm](?![a-z0-9])", tag)
    size = match.group(0) if match else (OLLAMA_DEFAULT_SIZE.get(family) if tag == "latest" else tag.split("-")[0])
    if (family, size) in OPEN_MODELS:
        return OPEN_MODELS[(family, size)], "market"
    billions = _billions(size)
    if billions is None:
        return UNKNOWN_SIZE, "estimate"
    return next(price for limit, price in SIZE_TIERS if billions <= limit), "estimate"


def repo_price(repo):
    """((input, output), source) for a Hugging Face model started with `yougori run`: the
    market price of the same model, or the market rate for its size."""
    name = repo.lower()
    market = market_price("yougori", name)
    if market:
        return market, "market"
    for token in re.split(r"[-_]", name.rsplit("/", 1)[-1]):
        billions = _billions(token)
        if billions is not None:
            return next(price for limit, price in SIZE_TIERS if billions <= limit), "estimate"
    return UNKNOWN_SIZE, "estimate"


def estimate(provider, upstream):
    name = _plain(upstream).lower()
    vendor, _, bare = name.rpartition("/")
    table = ESTIMATES.get(provider) or ESTIMATES.get(vendor) or ESTIMATES["gateway"]
    price = next(price for word, price in table if word in bare)
    return price[0], price[1], "estimate"


def default_price(provider, upstream, sandbox="paid", cost=None, today=None):
    """(input, output, source) for a model, before the admin's markup. The source is
    'list' (the provider's price), 'market' (the market charges more) or 'estimate'.
    None for models that do not answer text chat."""
    if not isinstance(upstream, str) or NOT_CHAT.search(upstream.lower()):
        return None
    if sandbox in ("local", "attached"):
        price, source = (local_price if sandbox == "local" else repo_price)(upstream)
        return price[0], price[1], source
    # A gateway's free tier reports a zero cost: that is no price, so the market decides.
    official = list_price(provider, upstream, today) or (tuple(cost) if cost and any(cost) else None)
    market = market_price(provider, upstream)
    if official and market:
        price = (max(official[0], market[0]), max(official[1], market[1]))
        return price[0], price[1], "list" if price == tuple(official) else "market"
    if official:
        return official[0], official[1], "list"
    if market:
        return market[0], market[1], "market"
    return estimate(provider, upstream)
