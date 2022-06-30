from django.test import TestCase, RequestFactory, Client
from django.db import IntegrityError
from .forms import SearchForm, InsertForm

class  SearchFormTests(TestCase):
    def test_valid_sha256(self):
        toolong = 'a' *70
        form = SearchForm(data={'sha256': toolong})
        self.assertFalse(form.is_valid())

class InsertFormTests(TestCase):
    def test_valid_sha256(self):
        tooshort = 'aaa'
        form = InsertForm(data={'sha256': tooshort})
        self.assertFalse(form.is_valid())

        toolong = 'a' *70
        form = InsertForm(data={'sha256': toolong})
        self.assertFalse(form.is_valid())
