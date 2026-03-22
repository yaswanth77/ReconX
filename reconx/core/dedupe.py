"""
Deduplication store — the heart of "no redundancy".

Every expansion stage passes candidates through a DedupeStore.
Only genuinely new items proceed downstream.
"""


class DedupeStore:
    """
    In-memory set of canonical keys.

    Usage:
        dedup = DedupeStore()
        if dedup.add("api.example.com"):
            # This is a new host — process it
        if dedup.add("api.example.com"):
            # Returns False — already seen
    """

    def __init__(self):
        self._seen: set[str] = set()

    def add(self, key: str) -> bool:
        """
        Add a key. Returns True if the key is new (not seen before).
        Returns False if already seen (duplicate).
        """
        normalized = key.strip().lower()
        if normalized in self._seen:
            return False
        self._seen.add(normalized)
        return True

    def add_many(self, keys: list[str]) -> list[str]:
        """Add multiple keys, return only the new ones."""
        new_keys = []
        for key in keys:
            if self.add(key):
                new_keys.append(key)
        return new_keys

    def has(self, key: str) -> bool:
        """Check if a key has been seen."""
        return key.strip().lower() in self._seen

    @property
    def count(self) -> int:
        """Number of unique items stored."""
        return len(self._seen)

    def clear(self):
        """Reset the store."""
        self._seen.clear()
