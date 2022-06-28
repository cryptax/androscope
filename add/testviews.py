from django.test import TestCase, RequestFactory, Client
from django.db import IntegrityError
from django.contrib.auth.models import User, AnonymousUser, Group
from django.core.exceptions import PermissionDenied
from .models import Malware, Property
from .android import search_pithus, search_koodous, get_virustotal_names, Filetype, suggest_from_dex, unzip_apk
from .views import paginate, insert, perform_search, upload, belongs_to_group, mark_checked, edit, select
from .forms import SelectForm
from tempfile import TemporaryFile, NamedTemporaryFile
import zipfile, os

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
        


class ViewsTests(TestCase):
    def setUp(self):
        self.the_hash = 'a' * 64
        
    def test_index(self):
        response = self.client.get('/')
        self.assertEqual(response.status_code, 200)        
        self.assertTemplateUsed(response, 'index.html')

        response = self.client.get('/index.html')
        self.assertEqual(response.status_code, 200)        
        self.assertTemplateUsed(response, 'index.html')

    def test_menu(self):
        response = self.client.get('/add/view/')
        self.assertEqual(response.status_code, 200)

        response = self.client.get('/add/search/')
        self.assertEqual(response.status_code, 200)        

        response = self.client.get('/add/about/')
        self.assertEqual(response.status_code, 200)        
        self.assertTemplateUsed(response, 'about.html')

    def test_no_hash(self):
        for cmd in ['select', 'show', 'edit']:
            response = self.client.get('/add/{}/'.format(cmd))
            self.assertEqual(response.status_code, 404)

    def test_unknown_hash(self):
        for method in ['select', 'show']:
            response = self.client.get('/add/{}/0aaaaaa9de74efa5e6351c2d2a7c0b44714eb150db0b492667a80fcc54aad53e/'.format(method))
            self.assertRedirects(response, '/index.html')

        # edit will answer 403, not redirect because we need to be power user

    def test_select_template(self):
        # show the select form for a dummy malware
        Malware.objects.create(sha256=self.the_hash)
        response = self.client.get('/add/select/{}/'.format(self.the_hash))
        self.assertTemplateUsed(response, 'select.html')

    def test_select_overwrite(self):
        # special case where the property for the malware already exist and need to be overwritten
        Malware.objects.create(sha256=self.the_hash)
        Property.objects.create(sha256=self.the_hash, native_exploit=True)
        response = self.client.get('/add/select/{}/'.format(self.the_hash))
        self.assertTemplateUsed(response, 'select.html')

    def test_select_prefill_dex(self):
        Malware.objects.create(sha256=self.the_hash)
        # try to prefill features for a DEX - set to delete False because select() deletes it
        with NamedTemporaryFile(delete=False) as tmp:
            tmp.write(b'dex\n035\x00\xd8\xa5\xeb\xae\x1fH\xd895z\x07\xbfkP\xa3{\xfb\xf0#\x82\x9f%\xe6\x03P.\x01\x00p\x00\x00\x00xV4\x12\x00\x00\x00\x00\x00\x00')
            tmp.seek(0)

            factory = RequestFactory()
            request = factory.get('/add/select/{}/'.format(self.the_hash))
            request.session = {}
            request.session['upload_tmpname'] = tmp.name
            request.session['upload_filetype'] = Filetype.DEX
            request.user = AnonymousUser()
            response = select(request, self.the_hash)
            response.client = Client()
            self.assertTrue(b'common1_ransom' in response.content)
            self.assertEqual(response.status_code, 200)

    def test_select_prefill_zip(self):
        Malware.objects.create(sha256=self.the_hash)
        # try prefill features for a Zip file
        dexfile = 'classes.dex'
        dex = open(dexfile,'wb')
        dex.write(b'dex\n035\x00\xd8\xa5\xeb\xae\x1fH\xd895z\x07\xbfkP\xa3{\xfb\xf0#\x82\x9f%\xe6\x03P.\x01\x00p\x00\x00\x00xV4\x12\x00\x00\x00\x00\x00\x00')
        dex.close()

        # create the zip file
        apkfile = 'my.apk'
        with zipfile.ZipFile(apkfile, 'w') as myzip:
            myzip.write(dexfile)

        factory = RequestFactory()
        request = factory.get('/add/select/{}/'.format(self.the_hash))
        request.session = {}
        request.session['upload_tmpname'] = apkfile
        request.session['upload_filetype'] = Filetype.ZIP
        request.user = AnonymousUser()
        response = select(request, self.the_hash)
        response.client = Client()
        self.assertTrue(b'common1_ransom' in response.content)
        self.assertEqual(response.status_code, 200)

        # cleanup
        if os.path.exists(apkfile):
            os.remove(apkfile)

        if os.path.exists(dexfile):
            os.remove(dexfile)


    def test_post_select(self):
        thehash = 'a' * 64
        Malware.objects.create(sha256=thehash)

        myform = {}
        f = SelectForm()
        for field in f.fields.keys():
            myform[ field ] = f.get_initial_for_field(f.fields[field], field)

        myform['lang1_kotlin'] = True

        response = self.client.post('/add/select/{}/'.format(thehash), myform )
        self.assertRedirects(response, '/view/')

    def test_show(self):
        # show a standard entry
        this_hash = 'b5728080de8a6a1bdb8c3a2ff52ab88f81438415e0ea83b6c56c5b49bdec419e'
        Malware.objects.create(sha256=this_hash)
        Property.objects.create(sha256=this_hash, native_exploit=True, lang1_kotlin = False, lang_other='python,perl')
        response = self.client.get('/add/show/{}/'.format(this_hash))
        self.assertTemplateUsed(response, 'show.html')

        # show an entry with no properties
        this_hash = 'a' * 64
        Malware.objects.create(sha256=this_hash)
        response = self.client.get('/add/show/{}/'.format(this_hash))
        self.assertTemplateUsed(response, 'show.html')

    def test_paginate(self):
        for i in range(0x41, 0x50):
            this_hash = chr(i) * 64
            Malware.objects.create(sha256=this_hash)

        malware_list = Malware.objects.all()
        factory = RequestFactory()
        request = factory.get('/add/view/')
        nb_pages = 2
        page_list = paginate(request, malware_list, nb_per_page=nb_pages)
        self.assertEqual(len(page_list), nb_pages)

        # get another page
        request = factory.get('/add/view/?page=3')
        page_list = paginate(request, malware_list, nb_per_page=nb_pages)
        self.assertEqual(len(page_list), nb_pages)

    def test_captcha(self):
        response = self.client.get('/add/captcha.html')
        self.assertTemplateUsed(response, 'captcha.html')

        response = self.client.get('/add/captcha.html?nextstep=insert')
        self.assertEqual(self.client.session['nextstep'], 'insert')
        
        response = self.client.get('/add/captcha.html?nextstep=upload')
        self.assertEqual(self.client.session['nextstep'], 'upload')

        # test a bad captcha 
        response = self.client.post('/add/captcha.html?nextstep=upload', { 'captcha_1' : '9999999' })
        print(response.content)
        self.assertTrue(b'Invalid' in response.content)
        

    def test_insert(self):
        factory = RequestFactory()
        request = factory.get('/add/insert/')

        # test OK
        request.session = {}
        request.session['nextstep'] = 'insert'
        request.session['captcha'] = True
        request.user = AnonymousUser()
        response = insert(request)
        self.assertEqual(response.status_code, 200)

        # missing nextstep
        del request.session['nextstep']
        response = insert(request)
        self.assertEqual(response.status_code, 302)

        # we should redirect to upload
        request.session['nextstep'] = 'upload'
        request.session['captcha'] = True
        response = insert(request)
        self.assertEqual(response.status_code, 302)

        # captcha is invalid
        request.session['nextstep'] = 'insert'
        request.session['captcha'] =  '123'
        response = insert(request)
        self.assertEqual(response.status_code, 302)

        # captcha does not exist
        response = self.client.get('/add/insert.html', redirect = False)
        self.assertEqual(response.status_code, 302)

    def test_double_insert(self):
        this_hash = 'a' * 64
        Malware.objects.create(sha256=this_hash)
        Property.objects.create(sha256=this_hash)
        
        factory = RequestFactory()
        request = factory.post('/add/insert/', { 'sha256' : this_hash })
        request.session = {}
        request.session['nextstep'] = 'insert'
        request.session['captcha'] = True
        request.user = AnonymousUser()
        response = insert(request)
        self.assertEqual(response.status_code, 200)
        # "A sample with this precise SHA256 already exists"
        self.assertTrue('already exists', response.content)

    def test_insert_badhex(self):
        this_hash = 'z' * 64
        factory = RequestFactory()
        request = factory.post('/add/insert/', { 'sha256' : this_hash })
        request.session = {}
        request.session['nextstep'] = 'insert'
        request.session['captcha'] = True
        request.user = AnonymousUser()
        response = insert(request)
        self.assertTrue('Invalid SHA256: not a hexadecimal string', response.content)


    def test_upload(self):
        factory = RequestFactory()
        request = factory.get('/add/upload/')

        # test OK
        request.session = {}
        request.session['nextstep'] = 'upload'
        request.session['captcha'] = True
        request.user = AnonymousUser()
        response = upload(request)
        self.assertEqual(response.status_code, 200)
        
        # captcha does not exist
        response = self.client.get('/add/upload.html', redirect = False)
        self.assertEqual(response.status_code, 302)


    def test_file_upload(self):
        with TemporaryFile() as f:
            f.write(b'this is not a dex')
            f.seek(0)
            response = internal_file_upload(f)
            self.assertEqual(response.status_code, 200)
            self.assertTrue(b'is not an Android' in response.content)

        with TemporaryFile() as f:
            f.write(b'dex\n035\x00\xd8\xa5\xeb\xae\x1fH\xd895z\x07\xbfkP\xa3{\xfb\xf0#\x82\x9f%\xe6\x03P.\x01\x00p\x00\x00\x00xV4\x12\x00\x00\x00\x00\x00\x00')
            f.seek(0)
            response = internal_file_upload(f)
            self.assertEqual(response.status_code, 200)
            self.assertTrue(b'confirm it is malicious' in response.content)

    def test_confirm(self):
        for choice in ['yes', 'cancel']:
            factory = RequestFactory()
            request = factory.post('/add/upload/', { 'choice' : choice })
            request.session = {}
            thehash = 'a' * 64
            request.session['upload_sha256'] = thehash
            request.session['upload_filename'] = 'test'
            request.session['upload_tmpfile'] = '/tmp/fakename'
            request.session['captcha'] = True
            request.session['nextstep']='upload'
            request.user = AnonymousUser()
            response = upload(request)
            response.client = Client()
            if choice == 'yes':
                self.assertRedirects(response, '/select/{}/'.format(thehash))
            else:
                # cancel -> upload.html
                self.assertEqual(response.status_code, 200)

    def test_search(self):
        this_hash = 'a' * 64
        this_packer = 'jiagu'
        cleaned_form = {'sha256': this_hash, 'packer_yes': True, 'packer_name' : this_packer }
        Malware.objects.create(sha256=this_hash, to_check=False)
        Property.objects.create(sha256=this_hash, packer_yes=True, packer_name=this_packer)
        
        factory = RequestFactory()
        request = factory.post('/search/', cleaned_form)
        queryset = perform_search(cleaned_form)
        self.assertTrue(len(queryset) == 1)

        found = queryset[0]
        self.assertTrue(found.packer_name == this_packer and found.sha256 == this_hash)

        # Test when there are more samples which do not match
        this_hash2 = 'b' * 64
        this_packer2 = 'alibaba'
        Malware.objects.create(sha256=this_hash2, to_check=False)
        Property.objects.create(sha256=this_hash2, packer_yes=True, packer_name=this_packer2)

        this_hash3 = 'c' * 64
        Malware.objects.create(sha256=this_hash3, to_check=False)
        Property.objects.create(sha256=this_hash3, packer_yes=False, packer_name=this_packer2)

        factory = RequestFactory()
        request = factory.post('/search/', cleaned_form)
        queryset = perform_search(cleaned_form)
        self.assertTrue(len(queryset) == 1)



            
            
