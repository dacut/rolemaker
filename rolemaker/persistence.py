#!/usr/bin/env python3
"""
Persistence handler for Rolemaker.
"""
from botocore.exceptions import ClientError
from frozendict import frozendict

_not_specified = object() # pylint: disable=invalid-name

class KeyExistsError(RuntimeError):
    """
    Exception raised to indicate a key already exists.
    """
    pass


class DynamoDBPersistence(object):
    """
    Persist data to DynamoDB.
    """
    def __init__(self, table):
        super(DynamoDBPersistence, self).__init__()
        self.table = table
        return

    def get(self, key, consistent=True, default=_not_specified):
        """
        Returns all values for the given key.
        """
        result = self.table.get_item(Key=key, ConsistentRead=consistent)
        item = result.get("Item")
        if item is None:
            if default is _not_specified:
                raise KeyError(key)
            return default

        return item

    def get_all(self, consistent=False):
        """
        Returns all entries in this table.
        """
        result = self.table.scan(ConsistentRead=consistent)
        return result.get("Items", [])

    def put(self, key, values, overwrite=False):
        """
        Writes values for the given key.
        """
        item = dict(key)

        attribute_names = {}
        next_attribute_id = 0

        def map_attribute(name):
            """
            Map an attribute name to a placeholder to avoid conflicts with
            DynamoDB reserved names.
            """
            nonlocal attribute_names, next_attribute_id
            mapped_name = attribute_names.get(name)
            if mapped_name is None:
                mapped_name = "#a%d" % next_attribute_id
                next_attribute_id += 1
            return mapped_name

        for name, value in values.items():
            item[map_attribute(name)] = value

        if not overwrite:
            expected = {name: {"Exists": False} for name in key}
            ddb_kw = {"Expected": expected}
        else:
            ddb_kw = {}

        try:
            self.table.put_item(
                Item=item, ExpressionAttributeNames=attribute_names, **ddb_kw)
        except ClientError as e: # pylint: disable=invalid-name
            error_code = e.response.get("Error", {}).get("Code")
            if error_code == "ConditionalCheckFailedException":
                raise KeyExistsError(key)
            raise

        return

    def delete(self, key):
        """
        Removes the given key.
        """
        self.table.delete_item(Key=key)
        return

class InMemoryPersistence(object):
    """
    Persist data in memory.
    """
    def __init__(self):
        super(InMemoryPersistence, self).__init__()
        self._data = {}
        return

    def get(self, key, consistent=True, default=_not_specified):
        # pylint: disable=unused-argument
        """
        Returns all values for the given key.
        """
        try:
            return self._data[frozendict(key)]
        except KeyError:
            if default is _not_specified:
                raise
            return default

    def put(self, key, values, overwrite=False):
        """
        Writes values for the given key.
        """
        f_key = frozendict(key)

        if not overwrite and f_key in self._data:
            raise KeyExistsError(key)

        self._data[f_key] = values
        return

    def delete(self, key):
        """
        Removes the given key.
        """
        try:
            del self._data[frozendict(key)]
        except KeyError:
            pass

        return
