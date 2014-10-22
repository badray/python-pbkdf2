# -*- coding: utf-8 -*-

import unittest

from pbkdf2 import pbkdf2_hex


class TestPBKKDF2(unittest.TestCase):

    def _check(self, data, salt, iterations, keylen, expected):
        rv = pbkdf2_hex(data, salt, iterations, keylen)
        self.assertEqual(rv, expected)

    def test_testRFC6070Samples_returnsExceptedResults(self):
        self._check(
            'password', 'salt', 1, 20, '0c60c80f961f0e71f3a9b524af6012062fe037a6'
        )
        self._check(
            'password', 'salt', 2, 20, 'ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957'
        )
        self._check(
            'password', 'salt', 4096, 20, '4b007901b765489abead49d926f721d065a429c1'
        )
        self._check(
            'passwordPASSWORDpassword',
            'saltSALTsaltSALTsaltSALTsaltSALTsalt',
            4096,
            25,
            '3d2eec4fe41c849b80c8d83662c0e44a8b291a964cf2f07038'
        )
        self._check(
            'pass\x00word',
            'sa\x00lt',
            4096,
            16,
            '56fa6aa75548099dcc37d7f03425e0c3'
        )

        # This one is from the RFC but it just takes for ages and
        # big amount of RAM
        # self._check(
        #     'password',
        #     'salt',
        #     16777216,
        #     20,
        #     'eefe3d61cd4da4e4e9945b3d6ba2158c2634e984'
        # )

    def test_CtyptPBKDF2Samples_returnsExceptedResults(self):
        self._check(
            'password',
            'ATHENA.MIT.EDUraeburn',
            1,
            16,
            'cdedb5281bb2f801565a1122b2563515'
        )
        self._check(
            'password',
            'ATHENA.MIT.EDUraeburn',
            1,
            32,
            'cdedb5281bb2f801565a1122b25635150ad1f7a04bb9f3a333ecc0e2e1f70837'
        )
        self._check(
            'password',
            'ATHENA.MIT.EDUraeburn',
            2,
            16,
            '01dbee7f4a9e243e988b62c73cda935d'
        )
        self._check(
            'password',
            'ATHENA.MIT.EDUraeburn',
            2,
            32,
            '01dbee7f4a9e243e988b62c73cda935da05378b93244ec8f48a99e61ad799d86'
        )
        self._check(
            'password',
            'ATHENA.MIT.EDUraeburn',
            1200,
            32,
            '5c08eb61fdf71e4e4ec3cf6ba1f5512ba7e52ddbc5e5142f708a31e2e62b1e13'
        )
        self._check(
            'X' * 64,
            'pass phrase equals block size',
            1200,
            32,
            '139c30c0966bc32ba55fdbf212530ac9c5ec59f1a452f5cc9ad940fea0598ed1'
        )
        self._check(
            'X' * 65,
            'pass phrase exceeds block size',
            1200,
            32,
            '9ccad6d468770cd51b10e6a68721be611a8b4d282601db3b36be9246915ec82a'
        )
