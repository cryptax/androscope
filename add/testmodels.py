from django.test import TestCase, RequestFactory, Client
from django.db import IntegrityError
from django.contrib.auth.models import User, AnonymousUser
from .models import Malware, Property

def internal_file_upload(f):
    # this is not meant to be called as a test
    factory = RequestFactory()
    request = factory.post('/add/upload/', { 'name' : 'filename', 'file' : f })
    request.session = {}
    request.session['nextstep'] = 'upload'
    request.session['captcha'] = True
    request.user = AnonymousUser()
    response = upload(request)
    return response

class MalwareModelTests(TestCase):
    def automatic_date(self):
        malware = Malware()
        self.assertIs(malware.insert_date == '', False)

class PropertyTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        # Set up non-modified objects used by all test methods
        Property.objects.create(sha256='deadbeef', native_exploit=True, lang1_kotlin = False, lang_other='python,perl')

    def test_lang_other_max_length(self):
        p = Property.objects.get(id=1)
        max_length = p._meta.get_field('lang_other').max_length
        self.assertEqual(max_length, 250)

    def test_native_exploit_label(self):
        p = Property.objects.get(id=1)
        field_label = p._meta.get_field('native_exploit').verbose_name
        self.assertEqual(field_label, 'native exploit')

    def test_default_values(self):
        p = Property.objects.get(id=1)
        self.assertFalse(p.common1_keylogger)
        self.assertEqual(p.common2_other_malicious, '')

    def test_set_values(self):
        p = Property.objects.get(id=1)
        self.assertTrue(p.native_exploit)
        self.assertEqual(p.lang_other, 'python,perl')

    def test_unique_sha256(self):
        self.assertRaises(IntegrityError, lambda: Property.objects.create(sha256='deadbeef'))

    def test_packer_name(self):
        p = Property.objects.create(packer_name = 'apkprotect')
        self.assertEqual(p.packer_name, 'apkprotect')
        self.assertRaises(IntegrityError, lambda: Property.objects.create(packer_name = 'does not exist'))

    def test_obfuscation_name(self):
        p = Property.objects.create(obfuscation_name = 'javaguard')
        self.assertEqual(p.obfuscation_name, 'javaguard')
        self.assertRaises(IntegrityError, lambda: Property.objects.create(obfuscation_name = 'does not exist'))

    def test_ids(self):
        Property.objects.create(general_name='should be id 2')
        p2 = Property.objects.get(id=2)
        self.assertEqual(p2.general_name, 'should be id 2')
        self.assertEqual(p2.id, 2)
        
