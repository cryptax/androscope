from django.test import TestCase, RequestFactory, Client
from django.db import IntegrityError
from django.contrib.auth.models import User, AnonymousUser, Group
from django.core.exceptions import PermissionDenied
from .models import Malware, Property
from .forms import SearchForm, InsertForm, SelectForm
from .android import search_pithus, search_koodous, get_virustotal_names, Filetype, suggest_from_dex, unzip_apk
from .views import insert, upload, belongs_to_group, mark_checked, edit, select, view
from tempfile import TemporaryFile, NamedTemporaryFile
import zipfile, os




class GlobalTests(TestCase):
    
    def setUp(self):
        self.factory = RequestFactory()
        self.apkfile = ''
        self.thehash = 'a' * 64
        self.reviewer = Group.objects.create(name='reviewer')
        self.reviewer_username='cryptax'
        self.reviewer_password='no_way'
        self.cryptax = User.objects.create_user(username=self.reviewer_username)
        self.cryptax.set_password(self.reviewer_password)
        self.cryptax.save()
        self.reviewer.user_set.add(self.cryptax)


    def prepare_request(self, request, captcha=True, nextstep='upload'):
        request.session = {}
        request.session['captcha'] = captcha
        request.session['nextstep'] = nextstep
        request.user = AnonymousUser()
        return request

    def create_apk(self):
        dexfile = 'classes.dex'
        dex = open(dexfile,'wb')
        dex.write(b'dex\n035\x00\xd8\xa5\xeb\xae\x1fH\xd895z\x07\xbfkP\xa3{\xfb\xf0#\x82\x9f%\xe6\x03P.\x01\x00p\x00\x00\x00xV4\x12\x00\x00\x00\x00\x00\x00')
        dex.write(b'startRecording')
        dex.close()

        # create the zip file
        self.apkfile = 'my.apk'
        with zipfile.ZipFile(self.apkfile, 'w') as myzip:
            myzip.write(dexfile)
        return self.apkfile

    def main_page(self):
        print("-------------> Go to main page")
        response = self.client.get('/')
        self.assertEqual(response.status_code, 200)

    def upload_menu(self):
        print("-------------> Upload menu")
        # hit the upload menu
        response = self.client.get('/add/upload.html')
        self.assertRedirects(response, '/add/captcha.html?nextstep=upload')

    def fake_captcha(self):
        print("-------------> Solve captcha")
        request = self.factory.get('/add/upload/')
        self.prepare_request(request)
        response = upload(request)
        # we can't use assertTemplateUsed == 'upload.html' so we do our best to ascertain
        # this template was used
        self.assertEqual(response.status_code, 200)
        self.assertTrue(b'upload' in response.content)

    def upload_apk(self):
        print("-------------> Upload APK")
        self.create_apk()
        f = open(self.apkfile, 'rb')
        request = self.factory.post('/add/upload/', { 'name' : 'filename', 'file' : f })
        self.prepare_request(request)
        response = upload(request)
        # we should get the confirm template
        self.assertTrue(b'confirm it is malicious' in response.content)
        return self.apkfile

    def confirm(self):
        print("-------------> Confirm")
        request = self.factory.post('/add/upload/', { 'choice' : 'yes' })
        self.prepare_request(request)

        request.session['upload_sha256'] = self.thehash
        request.session['upload_filename'] = self.apkfile
        request.session['upload_tmpfile'] = self.apkfile
        response = upload(request)
        response.client = Client()
        self.assertRedirects(response, '/select/{}/'.format(self.thehash))

    def prefill(self):
        print("-------------> Make prefill features")
        request = self.factory.get('/add/select/{}/'.format(self.thehash))
        request.session = {}
        request.session['upload_tmpname'] = self.apkfile
        request.session['upload_filetype'] = Filetype.ZIP
        request.user = AnonymousUser()
        response = select(request, self.thehash)
        self.assertTrue(b'id="id_privacy2_audio" checked>' in response.content)

    def create_default_selectform(self):
        myform = {}
        f = SelectForm()
        for field in f.fields.keys():
            myform[ field ] = f.get_initial_for_field(f.fields[field], field)
        return myform


    def select_features(self):
        print("-------------> Select features")
        myform = self.create_default_selectform()
        myform['lang1_kotlin'] = True

        response = self.client.post('/add/select/{}/'.format(self.thehash), myform)
        self.assertRedirects(response, '/view/')

    def get_search(self):
        print("-------------> Get the search form")
        response = self.client.get('/add/search/')
        self.assertEqual(response.status_code, 200)

    def create_default_searchform(self):
        myform = {}
        f = SearchForm()
        for field in f.fields.keys():
            myform[ field ] = f.get_initial_for_field(f.fields[field], field)
        myform['sha256']=''
        return myform

    def post_search(self):
        print("-------------> Post the search form")
        myform = self.create_default_searchform()
        response = self.client.post('/add/search/', myform)
        self.assertEqual(response.status_code, 200)
        self.assertFalse(bytes(self.thehash, 'utf-8') in response.content)

    def login_reviewer(self):
        print("-------------> Login as reviewer")
        # login as reviewer
        self.client = Client()
        logged_in = self.client.login(username=self.reviewer_username, password=self.reviewer_password)
        self.assertTrue(logged_in)

    def view_as_reviewer(self):
        print("-------------> View page as reviewer")
        factory = RequestFactory()
        request = self.factory.get('/add/view/')
        request.user = self.cryptax
        response = view(request)
        self.assertTrue(bytes(' <input class="form-check-input" type="checkbox" name="{}'.format(self.thehash), 'utf-8') in response.content)

    def validate(self):
        print("-------------> Review a sample")
        request = self.factory.post('/add/view/', { self.thehash : "False" })
        request.user = self.cryptax
        response = view(request)
        self.assertFalse(bytes(' <input class="form-check-input" type="checkbox" name="{}'.format(self.thehash), 'utf-8') in response.content)

    def post_search_find(self):
        print("-------------> Search for the sample now")
        myform = self.create_default_searchform()
        response = self.client.post('/add/search/', myform)
        self.assertTrue(bytes(self.thehash, 'utf-8') in response.content)


    def test_usage(self):
        self.main_page()
        self.upload_menu()
        self.fake_captcha()
        self.upload_apk()
        self.confirm()
        self.prefill()
        self.select_features()
        self.get_search()
        self.post_search()
        self.login_reviewer()
        self.view_as_reviewer()
        self.validate()
        self.client.logout()
        self.post_search_find()

        

        
        

