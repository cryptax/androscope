# Generated by Django 3.2.5 on 2022-06-23 07:50

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('add', '0003_alter_property_obfuscation_name'),
    ]

    operations = [
        migrations.AlterField(
            model_name='property',
            name='packer_name',
            field=models.CharField(choices=[('unknown', 'Unknown / Any / Not specified'), ('alibaba', 'Alibaba - libmobisec.so'), ('apkencryptor', 'ApkEncryptor - https://github.com/FlyingYu-Z/ApkEncryptor'), ('apkguard', 'APKGuard - http://apkguard.io'), ('apkprotect', 'ApkProtect'), ('appfortify', 'App Fortify - libNSaferOnly.so'), ('appguard', 'AppGuard - http://appguard.nprotect.com'), ('approov', 'Approov - https://www.approov.io'), ('appsealing', 'AppSealing Loader - https://www.appsealing.com'), ('appsuit', 'AppSuit - http://www.stealien.com/appsuit.html'), ('bangle', 'Bangcle'), ('baidu', 'Baidu'), ('crazydog', 'Crazy Dog Wrapper'), ('cryptoshell', 'CryptoShell - http://cryptoshell.io'), ('dexhelper', 'libDexHelper.so'), ('dexprotector', 'DexProtector - https://dexprotector.com/'), ('divilar', 'Divilar'), ('dxshield', 'DxShield - http://www.nshc.net/wp/portfolio-item/dxshield_eng'), ('gaoxor', 'GaoXor'), ('ijiami', 'Ijiami'), ('jarpack', 'Jar Packer'), ('jiagu', 'Jiagu - http://jiagu.360.cn'), ('jsonpacker', 'JsonPacker'), ('kiro', 'libkiroro.so'), ('kony', 'Kony - http://www.kony.com'), ('liapp', 'Liapp'), ('medusah', 'Medusah - https://appsolid.co'), ('multidex', 'Multidex - aka ApkProtector Premium'), ('kiwisec', 'Kiwisec'), ('pangxie', 'PangXie'), ('qdbh', 'QDBH'), ('qihoo', 'Qihoo'), ('legu', 'Tencent  Legu'), ('secenh', 'Secenh - libsecenh.so'), ('secneo', 'SecNeo - http://www.secneo.com'), ('talsec', 'Talsec - https://www.talsec.app/flutter-security'), ('tencent', 'Mobile Tencent Protect - https://intl.cloud.tencent.com/product/mtp'), ('yidun', 'https://dun.163.com/product/app-protect')], default='unknown', max_length=200, null=True),
        ),
    ]
