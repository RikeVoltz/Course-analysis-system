from django.test import TestCase


class FirstTestCase(TestCase):

    def test_successful(self):
        """Test, that must finish successfully"""
        self.assertEqual(True, True)