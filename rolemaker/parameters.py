#!/usr/bin/env python3
"""
Site-wide configuration for Rolemaker.
"""
from time import time
from flask import session

class Parameters(object):
    """
    Site-parameters, used on every page render. This is heavily cached to
    avoid overloading the persistent store (usually DynamoDB).
    """
    cache_time = 300

    def __init__(self, persistence):
        super(Parameters, self).__init__()
        self._next_refresh_time = 0
        self.persistence = persistence
        self._items = {}
        self.refresh()
        return

    def refresh(self):
        """
        Refresh all items from the persistent store.
        """
        self._items = {}
        for item in self.persistence.get_all(consistent=True):
            if "Value" in item:
                self._items[item["Name"]] = item
        self._next_refresh_time = time() + self.cache_time
        return

    def refresh_if_needed(self):
        """
        Refresh all items from the persistent store if the cache time has
        been exceeded.
        """
        if self.refresh_needed:
            self.refresh()

    @property
    def refresh_needed(self):
        """
        Indicates whether a cache refresh is needed.
        """
        return time() > self._next_refresh_time

    def get(self, name, default=None):
        """
        Returns the specified parameter.
        """
        return self._items.get(name, default)

    def safe_set(self, name, value):
        """
        Sets the specified parameter, ensuring it does not already exist.
        """
        self.persistence.put(
            key={"Name": name}, values={"Value": value},
            expected={{"Name": {"Exists": False}}})
        self._items[name] = value
        return

    def __getitem__(self, name):
        return self._items.get(name, "")

    def __setitem__(self, name, value):
        if not session.get("is_admin"):
            return

        if not value:
            del self[name]
        else:
            self.persistence.put({"Name": name}, {"Value": value})
            self._items[name] = value
        return

    def __delitem__(self, name):
        self.persistence.delete({"Name": name})
        try:
            del self._items[name]
        except KeyError:
            pass
        return
