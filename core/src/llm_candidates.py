"""Owner-approved Linux CPU candidates; these are not certified models."""

# Public GGUF variants are the closest available CPU builds to the tested CLI
# aliases. Their weights can differ; exact digests prevent silent tag drift.
CANDIDATES = {
    "gemma4-12b": {
        "label": "Gemma 4 12B — summaries and documentation",
        "model": "gemma4:12b",
        "digest": "6114515d63c17436a7c0417d82820ac65ad643e2806c5a3c89cb62846436ed0b",
        "options": {"num_ctx": 65536, "temperature": 0.7, "top_p": 0.8, "top_k": 64},
    },
    "qwen36-coding": {
        "label": "Qwen 3.6 35B — coding drafts",
        "model": "qwen3.6:35b-a3b-coding",
        "digest": "017eda0b7c34529c494d9e0fba88519bed43aa7ed3b18a4f70c648d53e50db3c",
        "options": {"num_ctx": 65536, "temperature": 0.6, "top_p": 0.95,
                    "top_k": 20, "repeat_penalty": 1.0},
    },
    "qwen38-scout": {
        "label": "Qwen 3.8 27B — read-only scouting",
        "model": "qwen3.8:27b",
        "digest": "aaee06c39dcf2437cde036998d960e1fc1494b8191be7cc9657d01e509097813",
        "options": {"num_ctx": 65536, "temperature": 1.0, "top_p": 0.95,
                    "top_k": 20, "repeat_penalty": 1.0},
    },
    "deepseek-r1-70b": {
        "label": "DeepSeek R1 70B — reasoning",
        "model": "deepseek-r1:70b",
        "digest": "d37b54d01a76512a5adbaa9da4ee1c00833bf2dfefb0d4cc54351ba529e0f4da",
        "options": {"num_ctx": 65536, "temperature": 0.6, "top_p": 0.95},
    },
}


# Task -> ordered CANDIDATES keys, used when the operator sets no llm_task_models
# entry for a task, so routing works with no configuration.
DEFAULT_TASK_MODELS = {
    "summary": ["gemma4-12b"],
    "docs": ["gemma4-12b"],
    "pr_summary": ["gemma4-12b", "qwen38-scout"],  # submitted by LlmPool.ab_pr_summary
    "coding": ["qwen36-coding", "qwen38-scout"],
    "scout": ["qwen38-scout"],
    "reasoning": ["deepseek-r1-70b", "qwen38-scout"],
}


def default_task_models(task):
    """Return the default ordered rows for a task, shaped like operator profile rows.

    The candidate's sampling options use the same key names model_sampling()
    reads, so the pool validates them with its one rule set. No hardware minima.
    """
    return [{"model": CANDIDATES[key]["model"], "digest": CANDIDATES[key]["digest"],
             **CANDIDATES[key]["options"]}
            for key in DEFAULT_TASK_MODELS.get(task, ())]
