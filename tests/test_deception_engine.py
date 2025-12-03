import os
import pytest

from deception_engine import DeceptionEngine


def test_heuristic_mysql_switch():
    # Disable OpenAI to force heuristic path
    os.environ["DEEPDECOY_DISABLE_OPENAI"] = "true"
    engine = DeceptionEngine(evaluation_interval=1)
    engine.record_interaction("ssh", "show sql databases")
    assert engine.should_evaluate() is True
    transition = engine.evaluate()
    assert transition is not None
    assert transition.new == "MySQL Backend"
    assert transition.reason.lower().startswith("detected")


def test_heuristic_iot_switch():
    os.environ["DEEPDECOY_DISABLE_OPENAI"] = "true"
    engine = DeceptionEngine(evaluation_interval=1)
    engine.record_interaction("web", "/firmware/update.bin")
    transition = engine.evaluate()
    assert transition is not None
    assert transition.new == "IoT Hub"


def test_no_switch_without_indicators():
    os.environ["DEEPDECOY_DISABLE_OPENAI"] = "true"
    engine = DeceptionEngine(evaluation_interval=1)
    engine.record_interaction("ssh", "echo hello world")
    transition = engine.evaluate()
    assert transition is None

