from django import template

register = template.Library()

@register.filter(name='islist')
def islist(value):
    return isinstance(value, list)
