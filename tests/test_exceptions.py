# Copyright (C) 2016-present the asyncpg authors and contributors
# <see AUTHORS file>
#
# This module is part of asyncpg and is released under
# the Apache 2.0 License: http://www.apache.org/licenses/LICENSE-2.0


import async_gaussdb
from async_gaussdb import _testbase as tb


class TestExceptions(tb.ConnectedTestCase):

    def test_exceptions_exported(self):
        for err in ('GaussDBError', 'SubstringError', 'InterfaceError'):
            self.assertTrue(hasattr(async_gaussdb, err))
            self.assertIn(err, async_gaussdb.__all__)

        for err in ('GaussDBMessage',):
            self.assertFalse(hasattr(async_gaussdb, err))
            self.assertNotIn(err, async_gaussdb.__all__)

        self.assertIsNone(async_gaussdb.GaussDBError.schema_name)

    async def test_exceptions_unpacking(self):
        try:
            await self.con.execute('SELECT * FROM _nonexistent_')
        except async_gaussdb.UndefinedTableError as e:
            self.assertEqual(e.sqlstate, '42P01')
            self.assertEqual(e.position, '15')
            self.assertEqual(e.query, 'SELECT * FROM _nonexistent_')
            self.assertIsNotNone(e.severity)
        else:
            self.fail('UndefinedTableError not raised')

    async def test_exceptions_str(self):
        try:
            await self.con.execute('''
                 CREATE FUNCTION foo() RETURNS bool AS $$ $$ LANGUAGE SQL;
            ''')
        except async_gaussdb.InvalidFunctionDefinitionError as e:
            if self.server_version < (17, 0):
                detail = (
                    "Function's final statement must be SELECT or "
                    "INSERT/UPDATE/DELETE RETURNING."
                )
            else:
                detail = (
                    "Function's final statement must be SELECT or "
                    "INSERT/UPDATE/DELETE/MERGE RETURNING."
                )

            self.assertEqual(e.detail, detail)
            self.assertIn('DETAIL:  Function', str(e))
        else:
            self.fail('InvalidFunctionDefinitionError not raised')
