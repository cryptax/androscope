from django import template

register = template.Library()

@register.filter('startswith')
def startswith(text, starts):
    
    if isinstance(text, str):
        ret = text.startswith(starts)
        #print("[debug] startswith.py: text={} starts={} ret={}".format(text, starts,ret))    
        return ret
    #print("[debug] startswith.py: not a string")
    return False

'''
@register.filter(name='is_in_group')
def is_in_group(user, group_name):
    return user.groups.filter(name=group_name).exists()
'''
