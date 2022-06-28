from django.test import TestCase, RequestFactory, Client
from django.db import IntegrityError
from django.contrib.auth.models import User, AnonymousUser, Group
from django.core.files.uploadedfile import UploadedFile
from .models import Malware, Property
from .android import search_pithus, search_koodous, search_malwarebazaar, get_virustotal_names, Filetype, suggest_from_dex, unzip_apk, is_dex_inside, get_type
from tempfile import NamedTemporaryFile
import zipfile, os

def internal_create_dex(dexfile='classes.dex'):
    dex = open(dexfile,'wb')
    dex.write(b'dex\n035\x00\xd8\xa5\xeb\xae\x1fH\xd895z\x07\xbfkP\xa3{\xfb\xf0#\x82\x9f%\xe6\x03P.\x01\x00p\x00\x00\x00xV4\x12\x00\x00\x00\x00\x00\x00')
    dex.close()
    return dexfile

def internal_create_apk(apkfile='my.apk', dexfile='classes.dex'):
    '''
    Creates an APK containing a dummy but acceptable DEX
    '''
    dexfile = internal_create_dex()

    # create the zip file
    with zipfile.ZipFile(apkfile, 'w') as myzip:
        myzip.write(dexfile)

    return apkfile

def internal_create_jar_no_dex(mailjar_filename = 'mail.jar'):
    '''
    Creates a dummy JAR with no DEX inside
    '''
    thejar = open(mailjar_filename,'wb')
    thejar.write(b'PK\x03\x04\n\x00\x00\x00\x00\x00`}.>\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\t\x00\x00\x00META-INF/PK\x03\x04\n\x00\x00\x00\x08\x00]}.>\x82\xadX\xa2\xaa\x03\x00\x00\x9f\x0c\x00\x00\x14\x00\x00\x00META-INF/MANIFEST.MF\x8dVMs\xda0\x10\xbd{\xc6\xff')
    thejar.close()
    return mailjar_filename


def cleanup_created_apk(apkfile='my.apk', dexfile='classes.dex'):
    # call this to erase files created by internal_create_apk
    if os.path.exists(apkfile):
        os.remove(apkfile)
    if os.path.exists(dexfile):
        os.remove(dexfile)


class AndroidTests(TestCase):
    def test_pithus(self):
        # tests.py
        self.assertIs(search_pithus('00f0bc19de74efa5e6351c2d2a7c0b44714eb150db0b492667a80fcc54aad53e'), False)
        # covid-malware.apk
        self.assertIs(search_pithus('b5728080de8a6a1bdb8c3a2ff52ab88f81438415e0ea83b6c56c5b49bdec419e'), True)

    def test_koodous(self):
        # tests.py
        self.assertIs(search_koodous('00f0bc19de74efa5e6351c2d2a7c0b44714eb150db0b492667a80fcc54aad53e'), False)
        # covid-malware.apk
        self.assertIs(search_koodous('b5728080de8a6a1bdb8c3a2ff52ab88f81438415e0ea83b6c56c5b49bdec419e'), True)

    def test_malwarebazaar(self):
        # tests.py
        self.assertIs(search_malwarebazaar('00f0bc19de74efa5e6351c2d2a7c0b44714eb150db0b492667a80fcc54aad53e'), False)
        # joker sample
        self.assertIs(search_malwarebazaar('4e69ae43fc7fb627474318422617249d372dfae88a8fa034e6ed473e7f6f94d1'), True)
        

    def test_virustotal_names(self):
        self.assertEqual(get_virustotal_names(''), '')

    def test_suggest_from_dex(self):
        # this dex should have no feature
        with NamedTemporaryFile() as tmp:
            data = b'dex\n035\x00\xd8\xa5\xeb\xae\x1fH\xd895z\x07\xbfkP\xa3{\xfb\xf0#\x82\x9f%\xe6\x03P.\x01\x00p\x00\x00\x00xV4\x12\x00\x00\x00\x00\x00\x00'
            tmp.write(data)
            tmp.seek(0)
            initial, prefilled = suggest_from_dex(tmp.name)
            self.assertEqual(initial, {})
            self.assertEqual(len(prefilled), 0)

            # this dex should have abortBroadcast
            tmp.write(data)
            tmp.write(b'abortBroadcast')
            tmp.write(b'blah')
            tmp.seek(0)
            initial, prefilled = suggest_from_dex(tmp.name)
            self.assertTrue(initial['sms_intercept'])
            self.assertEqual(len(prefilled), 1)


    def test_get_type(self):
        # create an APK with a DEX inside
        apkfile = internal_create_apk()
        uf = UploadedFile(file=open(apkfile,'rb'), content_type='application/vnd.android.package-archive')
        thetype = get_type(uf)
        self.assertEqual(thetype, Filetype.ZIP)
        cleanup_created_apk()

        # create a JAR with no DEX inside
        mailjar_filename = internal_create_jar_no_dex()
        uf = UploadedFile(file=open(mailjar_filename,'rb'))
        thetype = get_type(uf)
        self.assertEqual(thetype, Filetype.ZIP)
        if os.path.exists(mailjar_filename):
            os.remove(mailjar_filename)

        # create a DEX
        dexfile = internal_create_dex()
        uf = UploadedFile(file=open(dexfile, 'rb'))
        thetype = get_type(uf)
        self.assertEqual(thetype, Filetype.DEX)
        if os.path.exists(dexfile):
            os.remove(dexfile)

        # create unknown file
        unknown_file = 'unknown'
        f = open(unknown_file, 'wb')
        f.write(b'sjkqwiqkksajdskajdakdjsakdj238ksdjfksjd')
        f.close()
        uf = UploadedFile(file=open(unknown_file, 'rb'))
        thetype = get_type(uf)
        self.assertEqual(thetype, Filetype.UNKNOWN)
        if os.path.exists(unknown_file):
            os.remove(unknown_file)
        
        
        
    def test_is_dex_inside(self):
        # create an APK with a DEX inside
        apkfile = internal_create_apk()
        uf = UploadedFile(file=open(apkfile,'rb'), content_type='application/vnd.android.package-archive')
        self.assertTrue(is_dex_inside(uf))
        cleanup_created_apk()

        # create a JAR with no DEX inside
        mailjar_filename = internal_create_jar_no_dex()
        uf = UploadedFile(file=open(mailjar_filename,'rb'))
        self.assertFalse(is_dex_inside(uf))
        if os.path.exists(mailjar_filename):
            os.remove(mailjar_filename)
        

    def test_unzip_apk(self):
        dexfile = 'classes.dex'
        apkfile = internal_create_apk()
        filename = unzip_apk(apkfile)
        self.assertEqual(os.path.basename(filename), dexfile)

        cleanup_created_apk()
            
            
