"""
Deception Engine
Adaptive persona management for DeepDecoy.

Purpose:
- Observe attacker interactions (SSH commands, web routes, payloads)
- Decide whether to shift deception persona dynamically
- Provide updated prompt fragments for AI responders (SSH + Web)

Design:
- Stateless GPT evaluation wrapper + lightweight local state
- Evaluate after configurable interval (e.g., every 3 interactions)
- Return a structured decision object

Safety:
- Never expose real data / credentials
- Strict JSON parsing of GPT output with fallback defaults
"""
from __future__ import annotations

from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field
from datetime import datetime
import json
import uuid
import os
import sqlite3

try:
    from openai import OpenAI  # Using same client as other modules
    from config import Config
except Exception:
    OpenAI = None  # Allows basic operation if OpenAI import fails during scaffolding

from personas import PERSONAS, DEFAULT_PERSONA


@dataclass
class PersonaState:
    name: str
    prompt_overrides: Dict[str, str] = field(default_factory=dict)  # keys: ssh, web
    active_modules: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class PersonaTransition:
    timestamp: str
    previous: str
    new: str
    reason: str
    modules: List[str]


class DeceptionEngine:
    """Adaptive persona decision engine."""

    def __init__(self, model: Optional[str] = None, evaluation_interval: Optional[int] = None):
        # Pull defaults from Config if not provided
        interval_cfg = getattr(Config, "DECEPTION_EVAL_INTERVAL", 3)
        self.model = model or (getattr(Config, "OPENAI_MODEL", "gpt-4"))
        self.evaluation_interval = evaluation_interval if evaluation_interval is not None else interval_cfg
        self.interaction_count = 0
        # Initialize current persona mapping keys from DEFAULT_PERSONA structure
        self.current_persona = PersonaState(
            name=DEFAULT_PERSONA.get("name", "Unknown"),
            prompt_overrides=DEFAULT_PERSONA.get("prompts", {}),
            active_modules=DEFAULT_PERSONA.get("modules", []),
            metadata=DEFAULT_PERSONA.get("metadata", {}),
        )
        self.transitions: List[PersonaTransition] = []
        self.session_id = str(uuid.uuid4())

        # Pre-build OpenAI client only if available
        self.client = None
        disable_openai = getattr(Config, "DISABLE_OPENAI", False)
        if OpenAI and getattr(Config, "OPENAI_API_KEY", None) and not disable_openai:
            try:
                self.client = OpenAI(api_key=Config.OPENAI_API_KEY)
            except Exception:
                self.client = None

    def record_interaction(self, source: str, content: str):
        """Record a command or request and trigger evaluation if threshold reached."""
        self.interaction_count += 1
        # Store in a limited ring buffer (not persisted here)
        if not hasattr(self, "_recent"):
            self._recent: List[Dict[str, str]] = []
        self._recent.append({"source": source, "content": content})
        if len(self._recent) > 25:
            self._recent.pop(0)

    def should_evaluate(self) -> bool:
        return self.interaction_count % self.evaluation_interval == 0

    def evaluate(self) -> Optional[PersonaTransition]:
        """Ask GPT (or fallback) whether to shift persona, returning transition if any."""
        # Fallback simple heuristic if GPT client unavailable or disabled
        if not self.client:
            return self._heuristic_fallback_with_learning()

        prompt = self._build_prompt()
        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {
                        "role": "system",
                        "content": (
                            "You are an adaptive deception engine for a cybersecurity honeypot. "
                            "You decide whether to shift the simulated system persona based on attacker behavior. "
                            "Always output STRICT JSON only."
                        ),
                    },
                    {"role": "user", "content": prompt},
                ],
                temperature=0.4,
                max_tokens=500,
            )
            raw = response.choices[0].message.content.strip()
            decision = self._parse_decision(raw)
        except Exception:
            return self._heuristic_fallback()

        if not decision or decision.get("action") != "switch":
            return None

        # Bias the suggested persona using learned weights
        decision = self._bias_decision_with_learning(decision)
        return self._apply_transition(decision)

    def _apply_transition(self, decision: Dict[str, Any]) -> PersonaTransition:
        previous_name = self.current_persona.name
        target_name = decision.get("new_persona", previous_name)
        persona_def = PERSONAS.get(target_name, PERSONAS.get(previous_name, DEFAULT_PERSONA))

        self.current_persona = PersonaState(
            name=persona_def["name"],
            prompt_overrides=persona_def.get("prompts", {}),
            active_modules=persona_def.get("modules", []),
            metadata=persona_def.get("metadata", {}),
        )

        transition = PersonaTransition(
            timestamp=datetime.utcnow().isoformat(),
            previous=previous_name,
            new=self.current_persona.name,
            reason=decision.get("reason", "unspecified"),
            modules=self.current_persona.active_modules,
        )
        self.transitions.append(transition)
        return transition

    def _build_prompt(self) -> str:
        interactions = self._recent if hasattr(self, "_recent") else []
        snippet = [f"[{i['source']}] {i['content']}" for i in interactions[-10:]]
        joined = "\n".join(snippet) if snippet else "(no interactions yet)"
        return (
            "Attacker interactions so far:\n" + joined + "\n\n" +
            f"Current persona: {self.current_persona.name}\n" +
            "Decide if we should switch persona. Respond with JSON:\n" +
            "{\n  'action': 'stay' | 'switch',\n  'new_persona': 'name if switching',\n  'reason': 'short justification'\n}"
        )

    def _parse_decision(self, raw: str) -> Optional[Dict[str, Any]]:
        # Allow raw JSON or with code fencing
        cleaned = raw.strip()
        if cleaned.startswith("```"):
            cleaned = cleaned.strip("`")
            # remove language hint if present
            cleaned = cleaned.replace("json", "", 1).strip()
        cleaned = cleaned.replace("'", '"')  # normalize quotes if single quotes
        try:
            data = json.loads(cleaned)
            if isinstance(data, dict):
                return data
        except Exception:
            return None
        return None

    def _heuristic_fallback(self) -> Optional[PersonaTransition]:
        # Simple rule: if any interaction mentions 'sql' switch to MySQL Backend persona
        if not hasattr(self, "_recent"):
            return None
        recent_text = " ".join(r["content"].lower() for r in self._recent[-5:])
        if "sql" in recent_text or "database" in recent_text:
            decision = {"action": "switch", "new_persona": "MySQL Backend", "reason": "Detected DB probing"}
            return self._apply_transition(decision)
        # Additional simple heuristics (lightweight):
        if any(k in recent_text for k in ["firmware", "device", "sensor"]):
            decision = {"action": "switch", "new_persona": "IoT Hub", "reason": "Detected IoT-oriented probing"}
            return self._apply_transition(decision)
        if any(k in recent_text for k in ["admin", "cms", "wp-"]):
            decision = {"action": "switch", "new_persona": "Vulnerable Web CMS", "reason": "Detected CMS/admin reconnaissance"}
            return self._apply_transition(decision)
        return None

    # Integrate learned strategy weights
    def _heuristic_fallback_with_learning(self) -> Optional[PersonaTransition]:
        """Heuristic fallback that prefers personas with higher learned weights."""
        if not hasattr(self, "_recent"):
            return None
        recent_text = " ".join(r["content"].lower() for r in self._recent[-5:])
        candidates: List[str] = []
        reason = None
        if "sql" in recent_text or "database" in recent_text:
            candidates.append("MySQL Backend")
            reason = "Detected database probing (learned preference)"
        if any(k in recent_text for k in ["firmware", "device", "sensor"]):
            candidates.append("IoT Hub")
            # set reason if not already set by a stronger signal
            reason = reason or "Detected IoT-oriented probing (learned preference)"
        if any(k in recent_text for k in ["admin", "cms", "wp-"]):
            candidates.append("Vulnerable Web CMS")
            reason = reason or "Detected CMS/admin reconnaissance (learned preference)"
        if not candidates:
            return None
        target = self._choose_by_weights(candidates)
        decision = {"action": "switch", "new_persona": target, "reason": reason or "Detected change in intent (learned preference)"}
        return self._apply_transition(decision)

    def _bias_decision_with_learning(self, decision: Dict[str, Any]) -> Dict[str, Any]:
        """Given a decision from GPT, bias the new_persona using learned weights if multiple candidates are suggested.
        Accepts decisions with optional 'candidates' list.
        """
        candidates = decision.get("candidates") or [decision.get("new_persona")]
        candidates = [c for c in candidates if c]
        if not candidates:
            return decision
        best = self._choose_by_weights(candidates)
        decision["new_persona"] = best
        return decision

    def _choose_by_weights(self, candidates: List[str]) -> str:
        weights = self._load_persona_weights()
        best_score = -1e9
        chosen = candidates[0]
        for p in candidates:
            w = weights.get(p, {"engagement_weight": 0.0, "threat_weight": 0.0})
            score = float(w.get("engagement_weight", 0.0)) + float(w.get("threat_weight", 0.0))
            if score > best_score:
                best_score = score
                chosen = p
        return chosen

    def _load_persona_weights(self) -> Dict[str, Dict[str, float]]:
        db_path = os.environ.get('LEARNING_DB_PATH', os.path.join('data', 'deepdecoy.db'))
        use_sqlite = os.environ.get('USE_SQLITE', 'true').lower() == 'true'
        if not use_sqlite:
            return {}
        try:
            conn = sqlite3.connect(db_path)
            cur = conn.cursor()
            cur.execute('SELECT persona_name, engagement_weight, threat_weight FROM persona_strategy')
            rows = cur.fetchall()
            result: Dict[str, Dict[str, float]] = {}
            for name, e_w, t_w in rows:
                result[name] = {"engagement_weight": float(e_w or 0.0), "threat_weight": float(t_w or 0.0)}
            conn.close()
            return result
        except Exception:
            return {}

    def get_persona_prompt(self, context: str) -> Optional[str]:
        """Return prompt override for context ('ssh' or 'web')."""
        return self.current_persona.prompt_overrides.get(context)

    def serialize_transitions(self) -> List[Dict[str, Any]]:
        return [
            {
                "timestamp": t.timestamp,
                "previous": t.previous,
                "new": t.new,
                "reason": t.reason,
                "modules": t.modules,
            }
            for t in self.transitions
        ]

    def persona_metadata(self) -> Dict[str, Any]:
        return {
            "name": self.current_persona.name,
            "modules": self.current_persona.active_modules,
            "metadata": self.current_persona.metadata,
        }


__all__ = ["DeceptionEngine", "PersonaState", "PersonaTransition"]
