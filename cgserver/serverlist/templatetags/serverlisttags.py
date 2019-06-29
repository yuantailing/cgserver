from django import template

register = template.Library()

@register.filter
def islist(value):
    return isinstance(value, list)

@register.simple_tag
def oneq(x, y, yes, no):
    return yes if x == y else no
