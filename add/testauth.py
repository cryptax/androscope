from django.test import TestCase, RequestFactory, Client
from django.db import IntegrityError
from django.contrib.auth.models import User, AnonymousUser, Group
from django.core.exceptions import PermissionDenied
from .models import Malware, Property
from .views import paginate, insert, upload, belongs_to_group, mark_checked, edit, select
from tempfile import TemporaryFile, NamedTemporaryFile
import zipfile, os

class AuthTests(TestCase):
    def test_valid_login(self):
        credentials = { 'username' : 'alice', 'password' : 'secret' }
        alice = User.objects.create_user(**credentials)
        self.assertTrue(self.client.login(**credentials))

    def test_wrong_password(self):
        credentials = { 'username' : 'alice', 'password' : 'secret' }
        alice = User.objects.create_user(**credentials)
        credentials['password'] = 'wrongpass'
        self.assertFalse(self.client.login(**credentials))

    '''
    def test_signup(self):
        # Good
        good_pass = 'aksdjaifhqyiqyeihfshf8'
        credentials = { 'username' : 'alice', 'password1' : good_pass, 'password2' : good_pass }
        response = self.client.post('/accounts/signup/', credentials)
        self.assertRedirects(response, '/accounts/login/')

        # Too short
        bad_pass = 'short'
        credentials = { 'username' : 'alice', 'password1' : bad_pass, 'password2' : bad_pass }
        response = self.client.post('/accounts/signup/', credentials, follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTrue(b'This password is too short' in response.content)

        # passwords do not match
        credentials = { 'username' : 'alice', 'password1' : good_pass, 'password2' : 'different' }
        response = self.client.post('/accounts/signup/', credentials)
        self.assertEqual(response.status_code, 200)
        self.assertTrue(b'The two password fields' in response.content)
    '''    
        
        

    def test_default_user(self):
        alice = User.objects.create_user(username='alice', password='so_secret')
        self.assertFalse(belongs_to_group(alice))
        self.assertFalse(belongs_to_group(alice, 'reviewer'))

    def test_anonymous(self):
        user = AnonymousUser()
        self.assertFalse(belongs_to_group(user))
        self.assertFalse(belongs_to_group(user, 'reviewer'))

    def test_power_user(self):
        powergroup = Group.objects.create(name='poweruser')
        irene = User.objects.create_user(username='irene', password='so_secret')
        powergroup.user_set.add(irene)
        self.assertTrue(belongs_to_group(irene))
        self.assertFalse(belongs_to_group(irene, group_name='adifferentgroup'))
        self.assertFalse(belongs_to_group(irene, 'reviewer'))

    def test_reviewer(self):
        reviewer = Group.objects.create(name='reviewer')
        cryptax = User.objects.create_user(username='cryptax', password='no_way')
        reviewer.user_set.add(cryptax)
        self.assertTrue(belongs_to_group(cryptax, 'reviewer'))
        self.assertFalse(belongs_to_group(cryptax))

    def test_edit(self):
        user = AnonymousUser()
        alice = User.objects.create_user(username='alice', password='so_secret')
        
        powergroup = Group.objects.create(name='poweruser')
        irene = User.objects.create_user(username='irene', password='so_secret')
        powergroup.user_set.add(irene)
        
        reviewer = Group.objects.create(name='reviewer')
        cryptax = User.objects.create_user(username='cryptax', password='no_way')
        reviewer.user_set.add(cryptax)
        
        this_hash = 'a' * 64
        Malware.objects.create(sha256=this_hash)
        Property.objects.create(sha256=this_hash)

        factory = RequestFactory()
        request = factory.get('/add/edit/{}'.format(this_hash))
        request.user = user
        self.assertRaises(PermissionDenied, lambda: edit(request, this_hash))

        request.user = alice
        self.assertRaises(PermissionDenied, lambda: edit(request, this_hash))

        request.user = irene
        self.assertEquals(edit(request, this_hash).status_code, 200)

        request.user = cryptax
        self.assertEquals(edit(request, this_hash).status_code, 200)

class ReviewingTests(TestCase):        
    def test_mark_checked(self):
        this_hash = 'b' * 64
        Malware.objects.create(sha256=this_hash)
        m = Malware.objects.get(id=1)
        self.assertTrue(m.to_check)

        mark_checked(this_hash)
        m = Malware.objects.get(id=1)
        self.assertFalse(m.to_check)

        mark_checked(this_hash, to_check=True)
        m = Malware.objects.get(id=1)
        self.assertTrue(m.to_check)

                         
