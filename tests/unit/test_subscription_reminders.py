from datetime import timedelta

from vpn_service.worker.subscription_reminders import _paid_reminder_stage, _reminder_text


def test_paid_reminder_stages_include_one_hour() -> None:
    assert _paid_reminder_stage(timedelta(days=2)) == "3d"
    assert _paid_reminder_stage(timedelta(hours=12)) == "1d"
    assert _paid_reminder_stage(timedelta(minutes=59)) == "1h"
    assert _paid_reminder_stage(timedelta(days=4)) is None


def test_one_hour_reminder_asks_user_to_pay() -> None:
    text = _reminder_text("1h")

    assert "менее чем через час" in text
    assert "Оплатите подписку" in text
