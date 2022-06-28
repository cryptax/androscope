from django import forms
from django.forms import ModelForm, ValidationError
from .models import Property
from captcha.fields import CaptchaField

import logging
logging.basicConfig(format='[%(asctime)s] %(levelname)s: %(message)s', level=logging.DEBUG)
logger = logging.getLogger(__name__)

class CaptchaForm(forms.Form):
    captcha = CaptchaField()

class SelectForm(ModelForm):
    class Meta:
        model = Property
        exclude = ('sha256', 'username')
        fields = '__all__'
        labels = {
                   'sha256' : 'SHA256',
                   'general_name' : 'Malware name',
                   'common1_keylogger' : 'Keylogger',
                   'common1_screenlock' : 'Locks the screen',
                   'common1_ransom' : 'Asks for a ransom',
                   'common1_overlay' : 'Uses screen overlay',
                   'common1_playprotect' : 'Disables Play Protect',
                   'common1_gesture' : 'Performs gestures or swipes',
                   'common1_av_kill' : 'Kills or uninstalls anti-virus or security apps',
                   'common1_turn_off' : 'Turns off or dims the screen',
                   'common1_wallpaper' : 'Modifies the wallpaper',
                   'common1_hideicon' : 'Hides the application icon',
                   'common1_deviceadmin' : 'Adds itself as device admin',
                   'common2_accessibility' : 'Other abuses of Accessibility Services',
                   'common2_steal_password' : 'Stealing passwords?',
                   'common2_cryptocurrency' : 'Steals or abuses cryptocurrencies?',
                   'common2_other_malicious' : 'Anything else?',
                   'common2_analysis' : 'Reference to malware analysis',
                   'sms_send' : 'Send malicious/unsollicited SMS',
                   'sms_intercept' : 'Intercept incoming SMS',
                   'sms_spy' : 'Spies incoming and/or outgoing SMS',
                   'sms_mtan' : 'Steals mTANs from SMS',
                   'call_send' : 'Calls phone numbers',
                   'call_answer' : 'Answers an incoming call',
                   'call_record' : 'Spies or records ongoing phone calls',
                   'call_ringer' : 'Modifies ringer mode',
                   'call_ussd' : 'Calls a USSD code',
                   'privacy1_imei' : 'Leaks IMEI',
                   'privacy1_imsi' : 'Leaks IMSI',
                   'privacy1_contacts' : 'Leaks contacts phone numbers, emails or call logs',
                   'privacy1_installed_apps' : 'Leaks installed apps',
                   'privacy1_mac' : 'Leaks MAC address',
                   'privacy1_ip' : 'Leaks IP address',
                   'privacy1_operator' : 'Leaks operator name',
                   'privacy1_phonenumber' : 'Leaks phone number (getLine1Number)',
                   'privacy2_browser' : 'Leaks browser history, bookmarks or cookies',
                   'privacy2_camera' : 'Takes pictures, videos, screenshots',
                   'privacy2_audio' : 'Records audio',
                   'privacy2_gps' : 'Tracks GPS location',
                   'privacy2_model' : 'Leaks phone model, manufacturer, screen size, Android ID...',
                   'privacy2_calendar' : 'Leaks calendar events',
                   'privacy2_remotecontrol' : 'Remote control the phone via a tool such as Team Viewer',
                   'privacy_other' : 'Other',
                   'network1_botnet' : 'Is part of a botnet',
                   'network1_post' : 'Posts HTTP data',
                   'network1_socket' : 'Opens a socket with a remote host',
                   'network1_reverse_shell' : 'Implements a reverse shell (metasploit...)',
                   'network2_encrypted_com' : 'Communication with remote server is encrypted',
                   'network2_ssh' : 'SSH into remote server',
                   'network2_download_apk' : 'Downloads code from a reverse server',
                   'network2_download_data' : 'Downloads configuration data from remote server',
                   'network_other' : 'Other',
                   'packer_yes' : 'Yes, it is packed',
                   'packer_inmemory' : 'In memory',
                   'packer_native' : 'Native loading',
                   'packer_name' : 'Packer name',
                   'obfuscation_yes' : 'Yes, it is obfuscated',
                   'obfuscation_junkcode' : 'Junk code',
                   'obfuscation_encryption' : 'Uses encryption (standard or custom)',
                   'obfuscation_name' : 'Obfuscator name',
                   'native_exploit' : 'Uses exploits',
                   'native_busybox' : 'Uses busybox',
                   'native_library' : 'Some (or all) malicious parts are implemented in a native library',
                   'anti1_debugger' : 'Uses isDebuggerConnected',
                   'anti1_emulator' : 'Detects default values of emulators',
                   'anti1_geny' : 'Detects specific emulators (Andy, Genymotion, Bluestacks...)',
                   'anti1_root_su' : 'Detects su or similar rooting binaries',
                   'anti2_root_app' : 'Detects rooting apps',
                   'anti2_emulator_os' : 'Detects emulator at system level',
                   'anti2_stack_trace' : 'Anti-reversing based on stack trace',
                   'anti2_libc' : 'Anti-reversing at libc-level',
                   'anti_other' : 'Other anti-reversing techniques',
                   'lang1_kotlin' : 'Kotlin',
                   'lang1_c' : 'C',
                   'lang1_javascript' : 'JavaScript',
                   'lang1_basic' : 'Basic 4 Android',
                   'lang_other' : 'Other languages'
        }
        help_texts = { 'sha256' : 'SHA256 hash of the sample',
                       'general_name' : 'Detection name by Anti-Virus, aliases or personal label',
                       'network1_botnet' : 'The malware is a bot. This bot is controlled by an external bot master',
                       'network2_download_apk' : 'APK, DEX, JAR, ZIP, update, native library, javascript...',
                       'network2_download_data' : 'Resources, cryptographic key, images...',
                       'packer_inmemory' : 'Packer users InMemoryDexClassLoader',
                       'packer_native' : 'DEX loading or execution is performed by a native library',
                       'anti1_emulator' : 'e.g. 15555215554 as phone number',
                       'anti2_root_app' : 'e.g. com.noshufou.android.su',
                       'anti2_emulator_os' : 'processes, files...'
        }

            


class SearchForm(SelectForm):
    sha256 = forms.CharField(max_length=64, required=False)
    '''
    This is a *search* form. We have the same fields, but many of the constraints are released.
    For example, obviously we want to allow to search for malware with an "already existing" sha256,
    i.e. we need to release uniqueness of sha256 field
    '''
    def validate_unique(self):
        try:
            self.instance.validate_unique(exclude='sha256')
        except forms.ValidationError as e:
            try:
                del e.error_dict['sha256']
            except:
                pass
            self._update_errors(e)

    def clean_sha256(self):
        logger.debug("clean_sha256(): custom sha256 validation")
        if self.data['sha256'] == 'None' or self.data['sha256'] == '':
            logger.debug("clean_sha256(): returning empty sha256")
            return ''
        
        sha256 = self.cleaned_data['sha256']
        l = len(sha256)
        if l > 64:
            logger.warning("clean_sha256(): sha256 has {} characters!".format(l))
            raise ValidationError('SHA256 is invalid: too long (len={})'.format(l))

        # check this is hexadecimal
        try:
            int(self.data['sha256'], 16)
        except ValueError as e:
            logger.warning("clean_sha256(): this is not a hex string")
            raise ValidationError('Invalid SHA256: not a hexadecimal string')

        logger.debug("clean_sha256(): returning sha256={}".format(sha256))
        return sha256

class InsertForm(ModelForm):
    class Meta:
        model = Property
        fields = ('sha256',)
        labels = {  'sha256' : 'SHA256' }
        help_texts = { 'sha256' : 'SHA256 hash of the sample to add to Androscope' }

    def clean_sha256(self):
        logger.debug("InsertForm::clean_sha256(): happily checking your SHA256")
        if self.data['sha256'] == 'None':
            raise ValidationError('SHA256 is empty')
        l = len(self.cleaned_data['sha256'])
        expected = 64
        if l != expected:
            raise ValidationError('Invalid SHA256 length: we got {} characters (expecting {})'.format(l, expected))

        # check this is hexadecimal
        try:
            int(self.data['sha256'], 16)
        except ValueError as e:
            logger.warning("clean_sha256(): this is not a hex string")
            raise ValidationError('Invalid SHA256: not a hexadecimal string')

        logger.debug("InsertForm::clean_sha256(): OK - returning sha256={}".format(self.cleaned_data['sha256']))
        return self.cleaned_data['sha256']
        

    

    
