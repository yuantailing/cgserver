from django.contrib import admin

from .models import Client, ClientReport, Employee, UnknownReport
from django.contrib.auth.models import User

# Register your models here.

class ClientAdmin(admin.ModelAdmin):
    list_display = ('__str__', 'client_id', 'display_name', 'created_at', )


class ClientReportAdmin(admin.ModelAdmin):
    list_display = ('__str__', 'client', 'ip', 'version', 'created_at', )
    list_filter = ('client__client_id', 'ip', 'version', )


class UnknownReportAdmin(admin.ModelAdmin):
    list_display = ('id', 'client_id', 'ip', 'version', 'created_at', )
    list_filter = ('client_id', 'ip', 'version', )


class EmployeeAdmin(admin.ModelAdmin):
    def user_username(inst):
        return inst.user.username

    def user_email(inst):
        return inst.user.email

    readonly_fields = ('user', user_email, 'comment', 'vpn_username')
    list_display = ('id', user_username, user_email, 'comment', 'can_access', )
    list_filter = ('can_access', )


admin.site.register(Client, ClientAdmin)
admin.site.register(ClientReport, ClientReportAdmin)
admin.site.register(UnknownReport, UnknownReportAdmin)
admin.site.register(Employee, EmployeeAdmin)
