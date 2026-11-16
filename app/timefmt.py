from datetime import timedelta


def minutes(delta: timedelta) -> int:
    return int(delta.total_seconds() // 60)
