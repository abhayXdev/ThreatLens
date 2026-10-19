from pathlib import Path

import pandas as pd
import pytest

from nids_logic import (
    CLASS_INFO, explain, load_model, predict_many, predict_one,
    validate_input, validate_table)

EXAMPLES_PATH = Path(__file__).parent.parent / "data" / "examples.csv"


@pytest.fixture(scope="module")
def stuff():
    model, columns, options = load_model()
    examples = pd.read_csv(EXAMPLES_PATH)
    return model, columns, options, examples


def example_row(examples, i):
    row = examples.iloc[i].to_dict()
    row.pop("true_class")
    return row


def test_model_files_load(stuff):
    model, columns, options, examples = stuff
    assert len(columns) == 40
    assert set(options) == {"protocol_type", "service", "flag"}


def test_valid_example_has_no_problems(stuff):
    model, columns, options, examples = stuff
    assert validate_input(example_row(examples, 0), columns, options) == []


def test_missing_value_is_reported(stuff):
    model, columns, options, examples = stuff
    row = example_row(examples, 0)
    del row["duration"]
    assert "Missing value for 'duration'." in validate_input(row, columns, options)


def test_negative_number_is_rejected(stuff):
    model, columns, options, examples = stuff
    row = example_row(examples, 0)
    row["src_bytes"] = -5
    assert "'src_bytes' cannot be negative." in validate_input(row, columns, options)


def test_rate_above_one_is_rejected(stuff):
    model, columns, options, examples = stuff
    row = example_row(examples, 0)
    row["serror_rate"] = 1.5
    assert "'serror_rate' must be between 0 and 1." in validate_input(row, columns, options)


def test_unknown_service_is_rejected(stuff):
    model, columns, options, examples = stuff
    row = example_row(examples, 0)
    row["service"] = "not_a_service"
    problems = validate_input(row, columns, options)
    assert "'not_a_service' is not a known value for 'service'." in problems


def test_predict_one_returns_valid_probabilities(stuff):
    model, columns, options, examples = stuff
    predicted, shares = predict_one(model, columns, example_row(examples, 0))
    assert predicted in CLASS_INFO
    assert set(shares) == set(CLASS_INFO)
    assert abs(sum(shares.values()) - 1.0) < 1e-6


def test_known_examples_predict_as_expected(stuff):
    model, columns, options, examples = stuff
    assert predict_one(model, columns, example_row(examples, 0))[0] == "Normal"
    assert predict_one(model, columns, example_row(examples, 2))[0] == "DOS"


def test_every_class_has_an_explanation():
    assert set(CLASS_INFO) == {"Normal", "DOS", "PROBE", "R2L", "U2R"}
    for name in CLASS_INFO:
        info = explain(name)
        assert set(info) == {"meaning", "severity", "action"}


def test_predict_many_matches_predict_one(stuff):
    model, columns, options, examples = stuff
    many = predict_many(model, columns, examples)["prediction"].tolist()
    one_by_one = [predict_one(model, columns, example_row(examples, i))[0]
                  for i in range(len(examples))]
    assert many == one_by_one


def test_validate_table_reports_row_number(stuff):
    model, columns, options, examples = stuff
    table = examples.copy()
    table.loc[0, "src_bytes"] = -5
    problems = validate_table(table, columns, options)
    assert any(p.startswith("Row 1:") for p in problems)


def test_validate_table_reports_missing_columns(stuff):
    model, columns, options, examples = stuff
    table = examples.drop(columns=["duration"])
    problems = validate_table(table, columns, options)
    assert problems == ["Missing columns: duration"]