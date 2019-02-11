from django.test import TestCase


class FirstTestCase(TestCase):

    def test_successful(self):
        """Test, that must finish successfully"""
        self.assertEqual(True, True)

    def test_unsuccessful(self):
        """Test, that must fail"""
        self.assertEqual(False, True)