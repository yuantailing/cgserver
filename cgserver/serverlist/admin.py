from django.contrib import admin

from .models import AccessLog, Client, ClientReport, Employee, GithubUser, UnknownReport
from django.contrib.auth.models import User

# Register your models here.

class AccessLogAdmin(admin.ModelAdmin):
    list_display = ('id', 'user', 'ip', 'target', 'param', 'created_at', )
    list_filter = ('user', 'ip', 'target', )
    readonly_fields = ('user', 'ip', 'target', 'param', 'info', )

class ClientAdmin(admin.ModelAdmin):
    list_display = ('id', 'client_id', 'display_name', 'created_at', )


class ClientReportAdmin(admin.ModelAdmin):
    list_display = ('id', 'client', 'ip', 'version', 'created_at', )
    list_filter = ('client__client_id', 'ip', 'version', )


class EmployeeAdmin(admin.ModelAdmin):
    def user_username(inst):
        return inst.user.username

    def user_email(inst):
        return inst.user.email

    list_display = ('user_id', user_username, user_email, 'can_access', 'staff_number', )
    list_filter = ('can_access', )
    readonly_fields = (user_username, user_email, )


class GithubUserAdmin(admin.ModelAdmin):
    list_display = ('id', 'github_id', 'github_login', 'github_email', )
    readonly_fields = ('github_id', )


class UnknownReportAdmin(admin.ModelAdmin):
    list_display = ('id', 'client_id', 'ip', 'version', 'created_at', )
    list_filter = ('client_id', 'ip', 'version', )


admin.site.register(AccessLog, AccessLogAdmin)
admin.site.register(Client, ClientAdmin)
admin.site.register(ClientReport, ClientReportAdmin)
admin.site.register(Employee, EmployeeAdmin)
admin.site.register(GithubUser, GithubUserAdmin)
admin.site.register(UnknownReport, UnknownReportAdmin)
