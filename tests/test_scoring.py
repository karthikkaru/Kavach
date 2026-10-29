from kavach.scanner import Finding, grade, score


def F(sev, passed):
    return Finding("x", "c", "t", sev, passed, "d")


def test_score_math():
    assert score([]) == 100
    assert score([F("high", False), F("medium", False), F("low", False)]) == 100 - 15 - 8 - 3
    assert score([F("high", True), F("info", False)]) == 100
    assert score([F("high", False)] * 10) == 0


def test_grade():
    assert [grade(s) for s in (95, 80, 65, 45, 10)] == ["A", "B", "C", "D", "F"]
