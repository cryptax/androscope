from django.contrib import admin
from .models import Malware, Property
from django.contrib.auth.models import User
from django.contrib.auth.admin import UserAdmin

@admin.action(description="Mark selected items as checked i.e reviewed")
def mark_all_as_reviewed(modeladmin, request, queryset):
    queryset.update(to_check=False)

class MalwareAdmin(admin.ModelAdmin):
    list_display = ('sha256', 'filename', 'insertion_date', 'to_check')
    search_fields = ('sha256', 'filename', 'insertion_date', 'to_check')
    list_filter = ('to_check', )
    date_hierarchy = 'insertion_date'
    actions = [mark_all_as_reviewed]


class PropertyAdmin(admin.ModelAdmin):
    list_display = ('sha256', 'username', 'general_name', 'sms_send', 'packer_yes', 'packer_name', 'obfuscation_yes', 'obfuscation_name', 'common1_screenlock', 'common1_ransom', 'common1_deviceadmin', 'common2_accessibility', 'privacy1_contacts', 'native_library', 'anti1_emulator')
    list_filter = ('username', 'common1_screenlock', 'common1_ransom', 'sms_send', 'packer_yes', 'obfuscation_yes', 'general_name')
    search_fields = list_display

admin.site.site_header = "Androscope Administration Panel"
admin.site.register(Malware, MalwareAdmin)
admin.site.register(Property, PropertyAdmin)

