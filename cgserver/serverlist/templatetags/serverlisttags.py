from django import template

register = template.Library()

@register.filter
def islist(value):
    return isinstance(value, list)

@register.simple_tag
def eqorno(x, y, yes, no):
    return yes if x == y else no

@register.filter
def datetimeexpires(date):
    return date < date.now(date.tzinfo)

@register.filter
def ftppermtrans(key):
    return {
        'none': 'No access',
        'read': 'Read only',
        'write': 'Read & write',
        'admin': 'Admin'
    }.get(key, 'Unknown')
