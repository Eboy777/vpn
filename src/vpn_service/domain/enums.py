from enum import StrEnum


class UserStatus(StrEnum):
    ACTIVE = "active"
    BLOCKED = "blocked"


class DeviceStatus(StrEnum):
    PENDING = "pending"
    ACTIVE = "active"
    REVOKED = "revoked"


class NodeStatus(StrEnum):
    WARMING = "warming"
    ACTIVE = "active"
    QUIESCING = "quiescing"
    DRAINING = "draining"
    DEAD = "dead"
    BLOCKED = "blocked"


class NodeSelectionMode(StrEnum):
    AUTO = "auto"
    MANUAL = "manual"


class PaymentStatus(StrEnum):
    CREATED = "created"
    PAID = "paid"
    FAILED = "failed"


class AuthTokenStatus(StrEnum):
    CURRENT = "current"
    NEXT = "next"
    REVOKED = "revoked"


class CanaryStatus(StrEnum):
    ACTIVE = "active"
    REVOKED = "revoked"


class OutboxStatus(StrEnum):
    PENDING = "pending"
    PROCESSING = "processing"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
