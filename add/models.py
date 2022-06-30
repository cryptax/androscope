from django.db  import models


class Malware(models.Model):
    sha256 = models.CharField(max_length=64, unique=True, default='')
    filename = models.CharField(max_length=200)
    insertion_date = models.DateField(auto_now_add=True)
    # True if the malware has been uploaded by a non-power user
    to_check = models.BooleanField(default=True)

    labels = { 'sha256' : 'SHA256',
               'filename' : 'Filename',
               'insertion_date' : 'Sample insertion date',
               'to_check' : 'Entry needs to be reviewed?',
    }


    class Meta:
        ordering = ['-id'] # to fix UnorderedObjectListWarning
        verbose_name_plural = "malware"

    def __str__(self):
        return "sha256: {}, filename: {}, date: {}, to_check: {}".format(self.sha256, self.filename, self.insertion_date, self.to_check)

class MalwareName():

    def __init__(self, malware = None, general_name=''):
        self.malware = malware
        self.general_name = general_name

    def __str__(self):
        return "{} general_name: {}".format(str(self.malware), self.general_name)

class Property(models.Model):
    PACKERS = ( ('unknown', 'Unknown / Any / Not specified'),
                ( 'alibaba', 'Alibaba - libmobisec.so'),
                ( 'apkencryptor', 'ApkEncryptor - https://github.com/FlyingYu-Z/ApkEncryptor'),
                ( 'apkguard', 'APKGuard - http://apkguard.io'),
                ( 'apkprotect' , 'ApkProtect' ),
                ( 'appfortify', 'App Fortify - libNSaferOnly.so'),
                ( 'appguard', 'AppGuard - http://appguard.nprotect.com'),
                ( 'approov', 'Approov - https://www.approov.io'),
                ( 'appsealing', 'AppSealing Loader - https://www.appsealing.com'),
                ( 'appsuit', 'AppSuit - http://www.stealien.com/appsuit.html'),
                ( 'bangle' , 'Bangcle' ),
                ( 'baidu', 'Baidu' ),
                ( 'crazydog', 'Crazy Dog Wrapper'),
                ( 'cryptoshell', 'CryptoShell - http://cryptoshell.io'),
                ( 'dexhelper', 'libDexHelper.so'),
                ( 'dexprotector', 'DexProtector - https://dexprotector.com/'),
                ( 'divilar', 'Divilar' ),
                ( 'dxshield', 'DxShield - http://www.nshc.net/wp/portfolio-item/dxshield_eng'),
                ( 'gaoxor', 'GaoXor' ),
                ( 'ijiami', 'Ijiami' ),
                ( 'jarpack', 'Jar Packer'),
                ( 'jiagu', 'Jiagu - http://jiagu.360.cn'),
                ( 'jsonpacker', 'JsonPacker'),
                ( 'kiro', 'libkiroro.so'),
                ( 'kony', 'Kony - http://www.kony.com'),
                ( 'liapp', 'Liapp'),
                ( 'medusah', 'Medusah - https://appsolid.co'),
                ( 'multidex', 'Multidex - aka ApkProtector Premium'),
                ( 'kiwisec', 'Kiwisec' ),
                ( 'pangxie', 'PangXie'),
                ( 'qdbh', 'QDBH'),
                ( 'qihoo' , 'Qihoo'),
                ( 'legu', 'Tencent  Legu'),
                ( 'secenh', 'Secenh - libsecenh.so'),
                ( 'secneo', 'SecNeo - http://www.secneo.com'),
                ( 'talsec', 'Talsec - https://www.talsec.app/flutter-security'),
                ( 'tencent', 'Mobile Tencent Protect - https://intl.cloud.tencent.com/product/mtp'),
                ( 'yidun', 'https://dun.163.com/product/app-protect'),
    )
    
    OBFUSCATORS = ( ('unknown', 'Unknown / Any / Not specified'),
                    ( 'andstr' , 'AndStrObfuscator - https://github.com/cyoyochoo/AndStrObfuscator'),
                   ( 'andresguard', 'AndResGuard - https://github.com/shwenzhang/AndResGuard'),
                   ( 'dasho' , 'DashO - https://www.preemptive.com/products/dasho'),
                    ( 'dexprotector' , 'Dexprotector - https://dexprotector.com' ),
                   ( 'enigma' , 'Enigma - https://github.com/christopherney/Enigma'),
                   ( 'javaguard' , 'JavaGuard - https://sourceforge.net/projects/javaguard/ '),
                   ( 'paranoid' , 'Paranoid - https://github.com/MichaelRocks/paranoid'),
                   ( 'proguard' , 'Proguard' ),
                   ( 'zelix', 'Zelix KlassMaster - http://www.zelix.com/klassmaster/'))
    
    sha256 = models.CharField(max_length=64, unique=True, default='', error_messages={ 'unique' : 'A sample with this precise SHA256 already exists' })
    general_name = models.CharField(max_length=150, default='', blank=True)
    username = models.CharField(max_length=150, default='', blank=True)

    common1_keylogger = models.BooleanField(default=False)
    common1_screenlock = models.BooleanField(default=False)
    common1_ransom = models.BooleanField(default=False)
    common1_overlay = models.BooleanField(default=False)
    common1_playprotect = models.BooleanField(default=False)
    common1_gesture = models.BooleanField(default=False)
    common1_av_kill = models.BooleanField(default=False)
    common1_turn_off = models.BooleanField(default=False)
    common1_wallpaper = models.BooleanField(default=False)
    common1_hideicon = models.BooleanField(default=False)
    common1_deviceadmin = models.BooleanField(default=False)
    
    common2_accessibility = models.CharField(max_length=250, default='' , blank=True)
    common2_steal_password = models.CharField(max_length=250, default='', blank=True)
    common2_cryptocurrency = models.CharField(max_length=250, default='', blank=True)
    common2_analysis = models.CharField(max_length=250, default='' , blank=True)
    common2_other_malicious = models.CharField(max_length=250, default='', blank=True)

    sms_send = models.BooleanField(default=False)
    sms_intercept = models.BooleanField(default=False)
    sms_spy = models.BooleanField(default=False)
    sms_mtan = models.BooleanField(default=False)

    call_send = models.BooleanField(default=False)
    call_answer = models.BooleanField(default=False)
    call_record = models.BooleanField(default=False)
    call_ringer = models.BooleanField(default=False)
    call_ussd = models.BooleanField(default=False)

    privacy1_imei = models.BooleanField(default=False)
    privacy1_imsi = models.BooleanField(default=False)
    privacy1_contacts = models.BooleanField(default=False)
    privacy1_installed_apps = models.BooleanField(default=False)
    privacy1_mac = models.BooleanField(default=False)
    privacy1_ip = models.BooleanField(default=False)
    privacy1_operator = models.BooleanField(default=False)
    privacy1_phonenumber = models.BooleanField(default=False)
    privacy2_browser = models.BooleanField(default=False)
    privacy2_camera = models.BooleanField(default=False)
    privacy2_audio = models.BooleanField(default=False)
    privacy2_gps = models.BooleanField(default=False)
    privacy2_model = models.BooleanField(default=False)
    privacy2_calendar = models.BooleanField(default=False)
    privacy2_remotecontrol = models.BooleanField(default=False)
    privacy_other = models.CharField(max_length=250, default='', blank=True)
                   
    network1_botnet = models.BooleanField(default=False)
    network1_post = models.BooleanField(default=False)
    network1_socket = models.BooleanField(default=False)
    network1_reverse_shell = models.BooleanField(default=False)
    network2_encrypted_com = models.BooleanField(default=False)
    network2_ssh = models.BooleanField(default=False)
    network2_download_apk = models.BooleanField(default=False)
    network2_download_data = models.BooleanField(default=False)
    network_other = models.CharField(max_length=250, default='', blank=True)

    packer_yes = models.BooleanField(default=False)
    packer_inmemory = models.BooleanField(default=False)
    packer_native = models.BooleanField(default=False)
    packer_name = models.CharField(null=True, max_length=200, choices=PACKERS, default=PACKERS[0][0])

    obfuscation_yes = models.BooleanField(default=False)
    obfuscation_junkcode = models.BooleanField(default=False)
    obfuscation_encryption = models.BooleanField(default=False)
    obfuscation_name = models.CharField(null=True, max_length=200, choices=OBFUSCATORS, default=OBFUSCATORS[0][0])

    native_exploit = models.BooleanField(default=False)
    native_busybox = models.BooleanField(default=False)
    native_library = models.BooleanField(default=False)

    anti1_debugger = models.BooleanField(default=False)
    anti1_emulator = models.BooleanField(default=False)
    anti1_geny = models.BooleanField(default=False)
    anti1_root_su = models.BooleanField(default=False)
    anti2_root_app = models.BooleanField(default=False)
    anti2_emulator_os = models.BooleanField(default=False)
    anti2_stack_trace = models.BooleanField(default=False)
    anti2_libc = models.BooleanField(default=False)
    anti_other = models.CharField(max_length=250, default='', blank=True)

    lang1_kotlin = models.BooleanField(default=False)
    lang1_c = models.BooleanField(default=False)
    lang1_javascript = models.BooleanField(default=False)
    lang1_basic = models.BooleanField(default=False)
    lang_other = models.CharField(max_length=250, default='', blank=True)

    class Meta:
        verbose_name_plural = "properties"
        ordering = ['-id']
        
    def __str__(self):
        return "sha256: {}, keylogger: {}, screenlock: {}, accessibility: {} lang_other: {} ... ".format(self.sha256, self.common1_keylogger, self.common1_screenlock, self.common2_accessibility, self.lang_other)


