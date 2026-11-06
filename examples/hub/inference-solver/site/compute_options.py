"""Public cloud configuration; all purchase inputs are bound to a fresh quote."""
import math


def rental_options(data):
    def integer(name, default, low, high):
        value = data.get(name, default)
        if type(value) is not int or not low <= value <= high:
            raise ValueError(f"{name} must be a whole number from {low} to {high}.")
        return value
    count = integer("gpu_count", 1, 1, 8)
    disk = integer("disk_gb", 80, 5, 4000)
    storage = data.get("storage", "temporary")
    if storage not in ("temporary", "persistent"):
        raise ValueError("Choose temporary disk or a persistent pod volume.")
    volume = integer("volume_gb", 0 if storage == "temporary" else 80, 0, 4000)
    if storage == "persistent" and volume < 1:
        raise ValueError("Choose a positive persistent volume size.")
    if disk + (volume if storage == "persistent" else 0) > 4000:
        raise ValueError("The combined runtime disk and volume must be at most 4000 GB.")
    return {"gpu_count": count, "disk_gb": disk, "storage": storage,
            "volume_gb": volume if storage == "persistent" else 0}


def public_account(result):
    account = result.get("account") or {}
    clean = {"connected": result.get("connected") is True}
    for key in ("balance", "spendPerHour", "spendLimit"):
        value = account.get(key)
        if type(value) in (float, int) and math.isfinite(value):
            clean[key] = value
    return clean
