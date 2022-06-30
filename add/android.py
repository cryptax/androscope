import hashlib
import logging
import magic
import requests
import zipfile
import os
from enum import IntEnum

from django.conf import settings
from virustotal_python import Virustotal
from tempfile import NamedTemporaryFile

logging.basicConfig(format='[%(asctime)s] %(levelname)s: %(message)s', level=logging.DEBUG)
logger = logging.getLogger(__name__)

def compute_sha256(f):
    logger.debug("compute_sha256(): filename={}".format(f.name))

    # compute sha256 of the file
    sha256_hash = hashlib.sha256()
    for chunk in f.chunks():
        sha256_hash.update(chunk)

    return sha256_hash.hexdigest()

class Filetype(IntEnum):
    # it's important to use an IntEnum for Filetype to be serialized ok by Django
    UNKNOWN = -1
    JAR = 0
    ZIP = 1
    DEX = 2


def get_type(f):
    logger.debug("get_type(): filename={}".format(f.name))
    for chunk in f.chunks(chunk_size=2048):
        logger.debug("get_type(): len_chunk={}".format(len(chunk)))
        filetype = magic.from_buffer(chunk)
        break
    value = Filetype.UNKNOWN
    
    # 'Java archive data (JAR)'
    if 'Java' in filetype:
        value =  Filetype.JAR

    # 'Zip archive data, at least v1.0 to extract'
    if 'Zip' in filetype:
        value = Filetype.ZIP

    # 'Dalvik dex file version 035'
    if 'Dalvik' in filetype:
        value = Filetype.DEX

    logger.debug("get_type(): type={} ({}) filename={}".format(filetype, value, f.name))
    return value

def is_dex_inside(f):
    logger.debug("is_dex_inside(): filename={}".format(f.name))
    for chunk in f.chunks(chunk_size=2048):
        if b'.dex' in chunk:
            return True

    return False

def write_tmp_file(f):
    # f is a Django request.FILES
    name = ''

    with NamedTemporaryFile(delete=False) as tmp:
        for chunk in f.chunks():
            tmp.write(chunk)
        tmp.seek(0)
        name = tmp.name
        tmp.close()

    logger.debug("write_tmp_file(): tmpfilename={}".format(name))
    return name

def unzip_apk(apk_filename):
    dex_to_extract = 'classes.dex'
    filename = ''
    try:
        with zipfile.ZipFile(apk_filename) as z:
            with open(dex_to_extract, 'wb') as f:
                f.write(z.read(dex_to_extract))
                
        filename = os.path.abspath(f.name)
        logger.debug("unzip_apk(): extracted {} ok".format(filename))
    except Exception as e:
        logger.warning("unzip_apk(): failed to extract {} from {} - exception={}".format(dex_to_extract, apk_filename, e))


    return filename

def suggest_from_dex(filename):
    prefilled_features = []
    initial = {}

    data = open(filename, 'rb').read()

    # We try to include only things for which we are certain or close to certain

    if b'isAdminActive' in data or b'DeviceAdminReceiver' in data:
        initial['common1_deviceadmin'] = True
        prefilled_features.append("Adds itself as device admin (category: Main)")
        
    if b'setComponentEnabledSetting' in data:
        initial['common1_hideicon'] = True
        prefilled_features.append("Hides the application icon (category: Main)")

    if b'lockNow' in data:
        initial['common1_screenlock'] = True
        prefilled_features.append('Locks the screen (category: Main)' )

    if b'VerifyAppsSettingsActivity' in data:
        initial['common1_playprotect' ] = True
        prefilled_features.append('Disables Play Protect (category: Main)')
        
    if b'abortBroadcast' in data:
        initial['sms_intercept'] = True
        prefilled_features.append("Intercept incoming SMS (category: SMS)")

    if b'createFromPdu' in data or b'getOriginatingAddress' in data:
        initial['sms_spy'] = True
        prefilled_features.append("Spies incoming and/or outgoing SMS (category: SMS)")

    if b'ACTION_CALL' in data or b'ACTION_DIAL' in data or b'android.intent.action.CALL' in data:
        initial['call_send'] = True
        prefilled_features.append("Calls phone numbers (category: Phone calls)")
        
    if b'answerRingingCall' in data:
        initial['call_answer'] = True
        prefilled_features.append("Answers an incoming call (category: Phone calls)")

    if b'setRingerMode' in data:
        initial['call_ringer'] = True
        prefilled_features.append("Modifies ringer mode (category: Phone calls)")

    if b'Camera' in data:
        initial['privacy2_camera'] = True
        prefilled_features.append("Takes pictures, videos, screenshots (category: Privacy)")

    if b'getLatitude' in data or b'getLongitude' in data or b'getCid' in data or b'getLac' in data or b'getLastKnownLocation' in data or b'getCellLocation' in data or b'requestLocationUpdates' in data or b'getNeighbouringCellInfo' in data:
        # we are not totally sure it tracks GPS but it is a good guess
        initial['privacy2_gps'] = True
        prefilled_features.append("Tracks GPS location (category: Privacy)")

    if b'getAllVisitedUrls' in data or b'getAllBookmarks' in data:
        initial['privacy2_browser'] = True
        prefilled_features.append("Leaks browser history, bookmarks or cookies (category: Privacy)")

    if b'startRecording' in data:
        initial['privacy2_audio'] = True
        prefilled_features.append("Records audio (category: Privacy)")

    if b'HttpPost' in data:
        initial['network1_post'] = True
        prefilled_features.append("Posts HTTP data (category: Network)")

    if b'InMemoryDexClassLoader' in data:
        initial['packer_yes'] = True
        initial['packer_inmemory'] = True
        prefilled_features.append("Packed - in memory (category: Packing)")


    if b'15555215554' in data or b'310260000000000' in data or b'e21833235b6eef10' in data:
        initial['anti1_emulator'] = True
        prefilled_features.append("Detects default values of emulators (category: Anti-reversing)")

    if b'fstab.andy' in data or b'ueventd.andy.rc' in data or b'com.bluestacks' in data or b'/dev/socket/baseband_genyd' in data or b'/dev/scoket/genyd' in data or b'genymotion' in data:
        initial['anti1_geny'] = True
        prefilled_features.append("Detects specific emulators (Andy, Genymotion, Bluestacks...)  (category: Anti-reversing)")

    if b'isDebuggerConnected' in data:
        initial['anti1_debugger'] = True
        prefilled_features.append("Uses isDebuggerConnected (category: Anti-reversing)")

    logger.debug("suggest_from_dex(): prefilled={} initial={}".format(prefilled_features, initial))
    return initial, prefilled_features
    
                 
def search_pithus(sha256):
    url = "https://beta.pithus.org/report/{}".format(sha256)
    r = requests.get(url, allow_redirects=False)
    found = False
    
    if r.status_code == 200:
        found = True

    logger.debug("search_pithus(): found={} url={}".format(found, url))
    return found

def search_koodous(sha256):
    if settings.KOODOUS_APIKEY == '':
        logger.warning("search_koodous(): no KOODOUS_APIKEY - check is disabled")
        return None

    logger.debug("Using KOODOUS_APIKEY={}".format(settings.KOODOUS_APIKEY))
    url = "https://developer.koodous.com/apks/{}/".format(sha256)
    r = requests.get(url, headers={ 'Authorization' : 'Token {}'.format(settings.KOODOUS_APIKEY) })
    found = False
    
    if r.status_code == 200 and r.json()['sha256'] == sha256 and r.json()['is_detected']:
        found = True

    logger.debug("search_koodous(): found={} url={}".format(found, url))
    return found

def search_malwarebazaar(sha256):
    url = 'https://mb-api.abuse.ch/api/v1/'
    post_data = { 'query' : 'get_info' , 'hash' : '{}'.format(sha256) }
    r = requests.post(url, data=post_data)
    found = False
    
    if r.status_code == 200 and r.json()['query_status'] == 'ok' and r.json()['data'][0]['sha256_hash'] == sha256:
        found = True

    logger.debug("search_malwarebazaar(): found={} url={}".format(found, url))
    return found
    
    
def search_virustotal(sha256):
    if settings.VIRUSTOTAL_APIKEY == '':
        logger.warning("search_virustotal(): no VIRUSTOTAL_APIKEY - check is disabled")
        return None

    FILE_ID = sha256
    vtotal = Virustotal(API_KEY=settings.VIRUSTOTAL_APIKEY)
    try:
        resp = vtotal.request("file/report", {"resource": FILE_ID})
    except Exception as e:
        logger.error("search_virustotal(): Exception={} sha256={}".format(e, sha256))
        return None
    
    if resp.response_code > 0:
        logger.debug("search_virustotal(): OK - we found sha256={}".format(sha256))
        return resp.json()

    logger.warning("search_virustotal(): did not find sha256={}".format(sha256))
    return None

def get_virustotal_names(vtotal_json):
    '''
    Provide a VirusTotal response (see search_virustotal()) as input argument
    Output: potential names for this sample
    '''
    #logger.debug("get_virustotal_names(): json={}".format(vtotal_json))
    name = ''
    if 'scans' in vtotal_json:
        AVs = ['Fortinet', 'ESET-NOD32', 'DrWeb', 'Kaspersky']
        for av in AVs:
            if av in vtotal_json['scans']:
                if vtotal_json['scans'][av]['detected'] and vtotal_json['scans'][av]['result'].lower() != 'undetected':
                    if name != '':
                        name = name + ','
                    name = name + vtotal_json['scans'][av]['result']
                
    logger.debug("get_virustotal_names(): {}".format(name))
    return name

